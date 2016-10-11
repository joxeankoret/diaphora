#!/usr/bin/python

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015-2016, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import re
import sys
import time
import json
import decimal
import sqlite3

from cStringIO import StringIO
from difflib import SequenceMatcher

from jkutils.kfuzzy import CKoretFuzzyHashing
from jkutils.factor import (FACTORS_CACHE, difference, difference_ratio,
                            primesbelow as primes)

try:
  import idaapi
  is_ida = True
except ImportError:
  is_ida = False

#-----------------------------------------------------------------------
VERSION_VALUE = "1.0.8"
COPYRIGHT_VALUE="Copyright(c) 2015-2016 Joxean Koret"
COMMENT_VALUE="Diaphora diffing plugin for IDA version %s" % VERSION_VALUE

# Used to clean-up the pseudo-code and assembly dumps in order to get
# better comparison ratios
CMP_REPS = ["loc_", "sub_", "qword_", "dword_", "byte_", "word_", "off_",
            "unk_", "stru_", "dbl_", "locret_", "short"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]


#-----------------------------------------------------------------------
def result_iter(cursor, arraysize=1000):
  'An iterator that uses fetchmany to keep memory usage down'
  while True:
    results = cursor.fetchmany(arraysize)
    if not results:
      break
    for result in results:
      yield result

#-----------------------------------------------------------------------
def quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.quick_ratio()
  except:
    print "quick_ratio:", str(sys.exc_info()[1])
    return 0

#-----------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.real_quick_ratio()
  except:
    print "real_quick_ratio:", str(sys.exc_info()[1])
    return 0

#-----------------------------------------------------------------------
def ast_ratio(ast1, ast2):
  if ast1 == ast2:
    return 1.0
  elif ast1 is None or ast2 is None:
    return 0
  return difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))

#-----------------------------------------------------------------------

def log(msg):
  print "[%s] %s\n" % (time.asctime(), msg);


def log_refresh(msg, show=False):
  log(msg)


class CChooser():
  class Item:
    def __init__(self, ea, name, ea2 = None, name2 = None, desc="100% equal", ratio = 0, bb1 = 0, bb2 = 0):
      self.ea = ea
      self.vfname = name
      self.ea2 = ea2
      self.vfname2 = name2
      self.description = desc
      self.ratio = ratio
      self.bb1 = bb1
      self.bb2 = bb2
      self.cmd_import_selected = None
      self.cmd_import_all = None
      self.cmd_import_all_funcs = None

    def __str__(self):
      return '%08x' % self.ea

  def __init__(self, title, bindiff, show_commands=True):
    if title == "Unmatched in primary":
      self.primary = False
    else:
      self.primary = True

    self.title = title

    self.n = 0
    self.items = []
    self.icon = 41
    self.bindiff = bindiff
    self.show_commands = show_commands

    self.cmd_diff_asm = None
    self.cmd_diff_graph = None
    self.cmd_diff_c = None
    self.cmd_import_selected = None
    self.cmd_import_all = None
    self.cmd_import_all_funcs = None
    self.cmd_show_asm = None
    self.cmd_show_pseudo = None
    self.cmd_highlight_functions = None
    self.cmd_unhighlight_functions = None
    
    self.selected_items = []

  def add_item(self, item):
    if self.title.startswith("Unmatched in"):
      self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname])
    else:
      self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname,
                         "%08x" % int(item.ea2), item.vfname2, "%.3f" % item.ratio,
                         "%d" % item.bb1, "%d" % item.bb2, item.description])
    self.n += 1

  def get_color(self):
    if self.title.startswith("Best"):
      return 0xffff99
    elif self.title.startswith("Partial"):
      return 0x99ff99
    elif self.title.startswith("Unreliable"):
      return 0x9999ff


#-----------------------------------------------------------------------
MAX_PROCESSED_ROWS = 1000000
TIMEOUT_LIMIT = 60 * 3

#-----------------------------------------------------------------------
class CBinDiff:
  def __init__(self, db_name, chooser=CChooser):
    self.names = dict()
    self.primes = primes(2048*2048)
    self.db_name = db_name
    self.db = None
    self.open_db()
    self.matched1 = set()
    self.matched2 = set()
    self.total_functions1 = None
    self.total_functions2 = None
    self.equal_callgraph = False

    self.kfh = CKoretFuzzyHashing()
    # With this block size we're sure it will only apply to functions
    # somehow big
    self.kfh.bsize = 32

    self.pseudo = {}
    self.pseudo_hash = {}
    self.unreliable = False
    self.relaxed_ratio = False
    self.experimental = False
    self.slow_heuristics = False
    self.use_decompiler_always = True
    self.exclude_library_thunk = True

    # Create the choosers
    self.chooser = chooser
    # Create the choosers
    self.create_choosers()

    self.last_diff_db = None
    self.re_cache = {}
    
    ####################################################################
    # LIMITS
    #
    # Do not run heuristics for more than 3 minutes per each 20.000
    # functions.
    self.timeout = TIMEOUT_LIMIT
    # It's typical in SQL queries to get a cartesian product of the 
    # results in the functions tables. Do not process more than this
    # value per each 20k functions.
    self.max_processed_rows = MAX_PROCESSED_ROWS
    # Limits to filter the functions to export
    self.min_ea = 0
    self.max_ea = 0
    # Export only non IDA automatically generated function names? I.e.,
    # excluding these starting with sub_*
    self.ida_subs = True
    # Export only function summaries instead of also exporting both the
    # basic blocks and all instructions used by functions?
    self.function_summaries_only = False
    # Ignore IDA's automatically generated sub_* names for heuristics
    # like the 'Same name'?
    self.ignore_sub_names = True
    # Ignore any and all function names for the 'Same name' heuristic?
    self.ignore_all_names = True
    # Ignore small functions?
    self.ignore_small_functions = False
    ####################################################################

  def __del__(self):
    if self.db is not None:
      try:
        if self.last_diff_db is not None:
          with self.db.cursor():
            cur.execute('detach "%s"' % self.last_diff_db)
      except:
        pass
      self.db_close()

  def open_db(self):
    self.db = sqlite3.connect(self.db_name)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row
    self.create_schema()

  def db_cursor(self):
    if self.db is None:
      self.open_db()
    return self.db.cursor()

  def db_close(self):
    self.db.close()
    self.db = None

  def create_schema(self):
    cur = self.db_cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    sql = """ create table if not exists functions (
                        id integer primary key,
                        name varchar(255),
                        address text unique,
                        nodes integer,
                        edges integer,
                        indegree integer,
                        outdegree integer,
                        size integer,
                        instructions integer,
                        mnemonics text,
                        names text,
                        prototype text,
                        cyclomatic_complexity integer,
                        primes_value text,
                        comment text,
                        mangled_function text,
                        bytes_hash text,
                        pseudocode text,
                        pseudocode_lines integer,
                        pseudocode_hash1 text,
                        pseudocode_primes text,
                        function_flags integer,
                        assembly text,
                        prototype2 text,
                        pseudocode_hash2 text,
                        pseudocode_hash3 text,
                        strongly_connected integer,
                        loops integer,
                        rva text unique,
                        tarjan_topological_sort text,
                        strongly_connected_spp text,
                        clean_assembly text,
                        clean_pseudo text,
                        mnemonics_spp text,
                        switches text,
                        function_hash text,
                        bytes_sum integer) """
    cur.execute(sql)

    sql = """ create table if not exists program (
                id integer primary key,
                callgraph_primes text,
                callgraph_all_primes text,
                processor text,
                md5sum text
              ) """
    cur.execute(sql)

    sql = """ create table if not exists program_data (
                id integer primary key,
                name varchar(255),
                type varchar(255),
                value text
              )"""
    cur.execute(sql)

    sql = """ create table if not exists version (value text) """
    cur.execute(sql)
    
    sql = """ create table if not exists instructions (
                id integer primary key,
                address text unique,
                disasm text,
                mnemonic text,
                comment1 text,
                comment2 text,
                name text,
                type text) """
    cur.execute(sql)

    sql = "create index if not exists idx_instructions_address on instructions (address)"
    cur.execute(sql)

    sql = """ create table if not exists basic_blocks (
                id integer primary key,
                num integer,
                address text unique)"""
    cur.execute(sql)

    sql = """ create table if not exists bb_relations (
                id integer primary key,
                parent_id integer not null references basic_blocks(id) ON DELETE CASCADE,
                child_id integer not null references basic_blocks(id) ON DELETE CASCADE)"""
    cur.execute(sql)

    sql = "create index if not exists idx_bb_relations on bb_relations(parent_id, child_id)"
    cur.execute(sql)

    sql = """ create table if not exists bb_instructions (
                id integer primary key,
                basic_block_id integer references basic_blocks(id) on delete cascade,
                instruction_id integer references instructions(id) on delete cascade)"""
    cur.execute(sql)

    sql = "create index if not exists idx_bb_instructions on bb_instructions (basic_block_id, instruction_id)"
    cur.execute(sql)

    sql = """ create table if not exists function_bblocks (
                id integer primary key,
                function_id integer not null references functions(id) on delete cascade,
                basic_block_id integer not null references basic_blocks(id) on delete cascade)"""
    cur.execute(sql)

    sql = "create index if not exists id_function_blocks on function_bblocks (function_id, basic_block_id)"
    cur.execute(sql)

    cur.execute("select 1 from version")
    row = cur.fetchone()
    if not row:
      cur.execute("insert into main.version values ('%s')" % VERSION_VALUE)

    sql = "create index if not exists idx_assembly on functions(assembly)"
    cur.execute(sql)

    sql = "create index if not exists idx_bytes_hash on functions(bytes_hash)"
    cur.execute(sql)

    sql = "create index if not exists idx_pseudocode on functions(pseudocode)"
    cur.execute(sql)

    sql = "create index if not exists idx_name on functions(name)"
    cur.execute(sql)

    sql = "create index if not exists idx_mangled_name on functions(mangled_function)"
    cur.execute(sql)

    sql = "create index if not exists idx_names on functions(names)"
    cur.execute(sql)
    
    sql = "create index if not exists idx_asm_pseudo on functions(assembly, pseudocode)"
    cur.execute(sql)

    sql = "create index if not exists idx_nodes_edges_instructions on functions(nodes, edges, instructions)"
    cur.execute(sql)

    sql = "create index if not exists idx_composite1 on functions(nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree)"
    cur.execute(sql)

    sql = "create index if not exists idx_composite2 on functions(instructions, mnemonics, names)"
    cur.execute(sql)

    sql = "create index if not exists idx_composite3 on functions(nodes, edges, cyclomatic_complexity)"
    cur.execute(sql)

    sql = "create index if not exists idx_composite4 on functions(pseudocode_lines, pseudocode)"
    cur.execute(sql)

    sql = "create index if not exists idx_composite5 on functions(pseudocode_lines, pseudocode_primes)"
    cur.execute(sql)
    
    sql = "create index if not exists idx_composite6 on functions(names, mnemonics)"
    cur.execute(sql)

    sql = "create index if not exists idx_pseudocode_hash1 on functions(pseudocode_hash1)"
    cur.execute(sql)

    sql = "create index if not exists idx_pseudocode_hash2 on functions(pseudocode_hash2)"
    cur.execute(sql)

    sql = "create index if not exists idx_pseudocode_hash3 on functions(pseudocode_hash3)"
    cur.execute(sql)

    sql = "create index if not exists idx_pseudocode_hash on functions(pseudocode_hash1, pseudocode_hash2, pseudocode_hash3)"
    cur.execute(sql)

    sql = "create index if not exists idx_strongly_connected on functions(strongly_connected)"
    cur.execute(sql)

    sql = "create index if not exists idx_strongly_connected_spp on functions(strongly_connected_spp)"
    cur.execute(sql)

    sql = "create index if not exists idx_loops on functions(loops)"
    cur.execute(sql)

    sql = "create index if not exists idx_rva on functions(rva)"
    cur.execute(sql)

    sql = "create index if not exists idx_tarjan_topological_sort on functions(tarjan_topological_sort)"
    cur.execute(sql)

    sql = "create index if not exists idx_mnemonics_spp on functions(mnemonics_spp)"
    cur.execute(sql)

    sql = "create index if not exists idx_clean_asm on functions(clean_assembly)"
    cur.execute(sql)

    sql = "create index if not exists idx_clean_pseudo on functions(clean_pseudo)"
    cur.execute(sql)

    sql = "create index if not exists idx_switches on functions(switches)"
    cur.execute(sql)

    sql = "create index if not exists idx_function_hash on functions(function_hash)"
    cur.execute(sql)

    sql = "create index if not exists idx_bytes_sum on functions(bytes_sum)"
    cur.execute(sql)

    cur.close()

  def attach_database(self, diff_db):
    cur = self.db_cursor()
    cur.execute('attach "%s" as diff' % diff_db)
    cur.close()

  def equal_db(self):
    cur = self.db_cursor()
    sql = "select count(*) total from program p, diff.program dp where p.md5sum = dp.md5sum"
    cur.execute(sql)
    row = cur.fetchone()
    ret = row["total"] == 1
    if not ret:
      sql = "select count(*) total from (select * from functions except select * from diff.functions) x"
      cur.execute(sql)
      row = cur.fetchone()
      ret = row["total"] == 0
    else:
      log("Same MD5 in both databases")
    cur.close()
    return ret

  def add_program_data(self, type_name, key, value):
    cur = self.db_cursor()
    sql = "insert into main.program_data (name, type, value) values (?, ?, ?)"
    values = (key, type_name, value)
    cur.execute(sql, values)
    cur.close()

  def get_instruction_id(self, addr):
    cur = self.db_cursor()
    sql = "select id from instructions where address = ?"
    cur.execute(sql, (str(addr),))
    row = cur.fetchone()
    rowid = None
    if row is not None:
      rowid = row["id"]
    cur.close()
    return rowid

  def get_bb_id(self, addr):
    cur = self.db_cursor()
    sql = "select id from basic_blocks where address = ?"
    cur.execute(sql, (str(addr),))
    row = cur.fetchone()
    rowid = None
    if row is not None:
      rowid = row["id"]
    cur.close()
    return rowid

  def save_function(self, props):
    cur = self.db_cursor()
    new_props = []
    for prop in props[:len(props)-2]:
      # XXX: Fixme! This is a hack for 64 bit architectures kernels
      if type(prop) is long and prop > 0xFFFFFFFF:
        prop = str(prop)

      if type(prop) is list or type(prop) is set:
        new_props.append(json.dumps(list(prop)))
      else:
        new_props.append(prop)

    sql = """insert into main.functions (name, nodes, edges, indegree, outdegree, size,
                                    instructions, mnemonics, names, prototype,
                                    cyclomatic_complexity, primes_value, address,
                                    comment, mangled_function, bytes_hash, pseudocode,
                                    pseudocode_lines, pseudocode_hash1, pseudocode_primes,
                                    function_flags, assembly, prototype2, pseudocode_hash2,
                                    pseudocode_hash3, strongly_connected, loops, rva,
                                    tarjan_topological_sort, strongly_connected_spp,
                                    clean_assembly, clean_pseudo, mnemonics_spp, switches,
                                    function_hash, bytes_sum)
                                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?)"""
    cur.execute(sql, new_props)
    func_id = cur.lastrowid

    if not self.function_summaries_only:
      bb_data, bb_relations = props[len(props)-2:]
      instructions_ids = {}
      sql = """insert into main.instructions (address, mnemonic, disasm, comment1, comment2, name, type)
                                 values (?, ?, ?, ?, ?, ?, ?)"""
      self_get_instruction_id = self.get_instruction_id
      cur_execute = cur.execute
      for key in bb_data:
        for insn in bb_data[key]:
          addr, mnem, disasm, cmt1, cmt2, name, mtype = insn
          db_id = self_get_instruction_id(str(addr))
          if db_id is None:
            cur_execute(sql, (str(addr), mnem, disasm, cmt1, cmt2, name, mtype))
            db_id = cur.lastrowid
          instructions_ids[addr] = db_id

      num = 0
      bb_ids = {}
      sql1 = "insert into main.basic_blocks (num, address) values (?, ?)"
      sql2 = "insert into main.bb_instructions (basic_block_id, instruction_id) values (?, ?)"

      self_get_bb_id = self.get_bb_id
      for key in bb_data:
        # Insert each basic block
        num += 1
        ins_ea = str(key)
        last_bb_id = self_get_bb_id(ins_ea)
        if last_bb_id is None:
          cur_execute(sql1, (num, ins_ea))
          last_bb_id = cur.lastrowid
        bb_ids[ins_ea] = last_bb_id

        # Insert relations between basic blocks and instructions
        for insn in bb_data[key]:
          ins_id = instructions_ids[insn[0]]
          cur_execute(sql2, (last_bb_id, ins_id))

      # Insert relations between basic blocks
      sql = "insert into main.bb_relations (parent_id, child_id) values (?, ?)"
      for key in bb_relations:
        for bb in bb_relations[key]:
          bb = str(bb)
          key = str(key)
          cur_execute(sql, (bb_ids[key], bb_ids[bb]))

      # And finally insert the functions to basic blocks relations
      sql = "insert into main.function_bblocks (function_id, basic_block_id) values (?, ?)"
      for key in bb_ids:
        bb_id = bb_ids[key]
        cur_execute(sql, (func_id, bb_id))

    cur.close()

  def get_valid_definition(self, defs):
    """ Try to get a valid structure definition by removing (yes) the 
        invalid characters typically found in IDA's generated structs."""
    ret = defs.replace("?", "_").replace("@", "_")
    ret = ret.replace("$", "_").replace("#", "_")
    return ret

  def prettify_asm(self, asm_source):
    asm = []
    for line in asm_source.split("\n"):
      if not line.startswith("loc_"):
        asm.append("\t" + line)
      else:
        asm.append(line)
    return "\n".join(asm)

  def re_sub(self, text, repl, string):
    if text not in self.re_cache:
      self.re_cache[text] = re.compile(text, flags=re.IGNORECASE)

    re_obj = self.re_cache[text]
    return re_obj.sub(repl, string)

  def get_cmp_asm_lines(self, asm):
    sio = StringIO(asm)
    lines = []
    get_cmp_asm = self.get_cmp_asm
    for line in sio.readlines():
      line = line.strip("\n")
      lines.append(get_cmp_asm(line))
    return "\n".join(lines)

  def get_cmp_pseudo_lines(self, pseudo):
    if pseudo is None:
      return pseudo

    # Remove all the comments
    tmp = self.re_sub(" // .*", "", pseudo)

    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    for rep in CMP_REPS:
      tmp = self.re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
    tmp = self.re_sub("v[0-9]+", "vXXX", tmp)
    tmp = self.re_sub("a[0-9]+", "aXXX", tmp)
    tmp = self.re_sub("arg_[0-9]+", "aXXX", tmp)
    return tmp

  def get_cmp_asm(self, asm):
    if asm is None:
      return asm

    # Ignore the comments in the assembly dump
    tmp = asm.split(";")[0]
    tmp = tmp.split(" # ")[0]
    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    for rep in CMP_REPS:
      tmp = self.re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

    # Remove dword ptr, byte ptr, etc...
    for rep in CMP_REMS:
      tmp = self.re_sub(rep + "[a-f0-9A-F]+", "", tmp)

    reps = ["\+[a-f0-9A-F]+h\+"]
    for rep in reps:
      tmp = self.re_sub(rep, "+XXXX+", tmp)
    tmp = self.re_sub("\.\.[a-f0-9A-F]{8}", "XXX", tmp)
    
    # Strip any possible remaining white-space character at the end of
    # the cleaned-up instruction
    tmp = self.re_sub("[ \t\n]+$", "", tmp)

    # Replace aName_XXX with aXXX, useful to ignore small changes in 
    # offsets created to strings
    tmp = self.re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)

    return tmp

  def compare_graphs_pass(self, bblocks1, bblocks2, colours1, colours2, is_second = False):
    dones1 = set()
    dones2 = set()

    # Now compare each basic block from the first function to all the
    # basic blocks in the 2nd function
    for key1 in bblocks1:
      if key1 in dones1:
        continue

      for key2 in bblocks2:
        if key2 in dones2:
          continue

        # Same number of instructions?
        if len(bblocks1[key1]) == len(bblocks2[key2]):
          mod = False
          partial = True
          i = 0
          for ins1 in bblocks1[key1]:
            ins2 = bblocks2[key2][i]
            # Same mnemonic? The change can be only partial
            if ins1[1] != ins2[1]:
              partial = False

            # Try to compare the assembly after doing some cleaning
            cmp_asm1 = self.get_cmp_asm(ins1[2])
            cmp_asm2 = self.get_cmp_asm(ins2[2])
            if cmp_asm1 != cmp_asm2:
              mod = True
              if not partial:
                continue
            i += 1

          if not mod:
            # Perfect match, we discovered a basic block equal in both
            # functions
            colours1[key1] = 0xffffff
            colours2[key2] = 0xffffff
            dones1.add(key1)
            dones2.add(key2)
            break
          elif not is_second and partial:
            # Partial match, we discovered a basic block with the same
            # mnemonics but something changed
            #
            # NOTE:
            # Do not add the partial matches to the dones lists, as we
            # can have complete matches after a partial match!
            colours1[key1] = 0xCCffff
            colours2[key2] = 0xCCffff
            break
    return colours1, colours2

  def compare_graphs(self, g1, ea1, g2, ea2):
    colours1 = {}
    colours2 = {}
    bblocks1 = g1[0]
    bblocks2 = g2[0]

    # Consider, by default, all blocks added, news
    for key1 in bblocks1:
      colours1[key1] = 0xCCCCFF
    for key2 in bblocks2:
      colours2[key2] = 0xCCCCFF

    colours1, colours2 = self.compare_graphs_pass(bblocks1, bblocks2, colours1, colours2, False)
    colours1, colours2 = self.compare_graphs_pass(bblocks1, bblocks2, colours1, colours2, True)
    return colours1, colours2

  def get_graph(self, ea1, primary=False):
    if primary:
      db = "main"
    else:
      db = "diff"
    cur = self.db_cursor()
    dones = set()
    sql = """ select bb.address bb_address, ins.address ins_address,
                     ins.mnemonic ins_mnem, ins.disasm ins_disasm
                from %s.function_bblocks fb,
                     %s.bb_instructions bbins,
                     %s.instructions ins,
                     %s.basic_blocks bb,
                     %s.functions f
               where ins.id = bbins.instruction_id
                 and bbins.basic_block_id = bb.id
                 and bb.id = fb.basic_block_id
                 and f.id = fb.function_id
                 and f.address = ?
               order by bb.address asc""" % (db, db, db, db, db)
    cur.execute(sql, (ea1,))
    bb_blocks = {}
    for row in result_iter(cur):
      bb_ea = str(int(row["bb_address"]))
      ins_ea = str(int(row["ins_address"]))
      mnem = row["ins_mnem"]
      dis = row["ins_disasm"]

      if ins_ea in dones:
        continue
      dones.add(ins_ea)

      try:
        bb_blocks[bb_ea].append([ins_ea, mnem, dis])
      except KeyError:
        bb_blocks[bb_ea] = [ [ins_ea, mnem, dis] ]

    sql = """ select (select address
                      from %s.basic_blocks
               where id = bbr.parent_id) ea1,
                   (select address
                      from %s.basic_blocks
               where id = bbr.child_id) ea2
              from %s.bb_relations bbr,
                   %s.function_bblocks fbs,
                   %s.basic_blocks bbs,
                   %s.functions f
             where f.id = fbs.function_id
               and bbs.id = fbs.basic_block_id
               and fbs.basic_block_id = bbr.child_id
               and f.address = ?
             order by 1 asc, 2 asc""" % (db, db, db, db, db, db)
    cur.execute(sql, (ea1, ))
    rows = result_iter(cur)

    bb_relations = {}
    for row in rows:
      bb_ea1 = str(row["ea1"])
      bb_ea2 = str(row["ea2"])
      try:
        bb_relations[bb_ea1].add(bb_ea2)
      except KeyError:
        bb_relations[bb_ea1] = set([bb_ea2])

    cur.close()
    return bb_blocks, bb_relations

  def delete_function(self, ea):
    cur = self.db_cursor()
    cur.execute("delete from functions where address = ?", (ea, ))
    cur.close()

  def is_auto_generated(self, name):
    for rep in CMP_REPS:
      if name.startswith(rep):
        return True
    return False

  def check_callgraph(self):
    cur = self.db_cursor()
    sql = """select callgraph_primes, callgraph_all_primes from program
             union all
             select callgraph_primes, callgraph_all_primes from diff.program"""
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) == 2:
      cg1 = decimal.Decimal(rows[0]["callgraph_primes"])
      cg_factors1 = json.loads(rows[0]["callgraph_all_primes"])
      cg2 = decimal.Decimal(rows[1]["callgraph_primes"])
      cg_factors2 = json.loads(rows[1]["callgraph_all_primes"])

      if cg1 == cg2:
        self.equal_callgraph = True
        log("Callgraph signature for both databases is equal, the programs seem to be 100% equal structurally")
        Warning("Callgraph signature for both databases is equal, the programs seem to be 100% equal structurally")
      else:
        FACTORS_CACHE[cg1] = cg_factors1
        FACTORS_CACHE[cg2] = cg_factors2
        diff = difference(cg1, cg2)
        total = sum(cg_factors1.values())
        percent = diff * 100. / total
        log("Callgraphs from both programs differ in %f%%" % percent)

    cur.close()

  def find_equal_matches(self):
    cur = self.db_cursor()
    # Start by calculating the total number of functions in both databases
    sql = """select count(*) total from functions
             union all
             select count(*) total from diff.functions"""
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) != 2:
      Warning("Malformed database, only %d rows!" % len(rows))
      raise Exception("Malformed database!")

    self.total_functions1 = rows[0]["total"]
    self.total_functions2 = rows[1]["total"]

    sql = "select address ea, mangled_function, nodes from (select * from functions intersect select * from diff.functions) x"
    cur.execute(sql)
    rows = cur.fetchall()
    choose = self.best_chooser
    if len(rows) > 0:
      for row in rows:
        name = row["mangled_function"]
        ea = row["ea"]
        nodes = int(row["nodes"])

        choose.add_item(CChooser.Item(ea, name, ea, name, "100% equal", 1, nodes, nodes))
        self.matched1.add(name)
        self.matched2.add(name)

    postfix = ""
    if self.ignore_small_functions:
      postfix = " and f.instructions > 5 and df.instructions > 5 "

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Same RVA and hash' description,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where df.rva = f.rva
                 and df.bytes_hash = f.bytes_hash
                 and df.instructions = f.instructions
                 and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                   or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))"""
    log_refresh("Finding with heuristic 'Same RVA and hash'")
    self.add_matches_from_query(sql, choose)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Same order and hash' description,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where df.id = f.id
                 and df.bytes_hash = f.bytes_hash
                 and df.instructions = f.instructions
                 and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                   or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))"""
    log_refresh("Finding with heuristic 'Same order and hash'")
    self.add_matches_from_query(sql, choose)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Function hash' description,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.function_hash = df.function_hash 
                 and f.instructions > 5 and df.instructions > 5 """
    log_refresh("Finding with heuristic 'Function hash'")
    self.add_matches_from_query(sql, choose)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Bytes hash and names' description,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.bytes_hash = df.bytes_hash
                 and f.names = df.names
                 and f.names != '[]'
                 and f.instructions > 5 and df.instructions > 5"""
    log_refresh("Finding with heuristic 'Bytes hash and names'")
    self.add_matches_from_query(sql, choose)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Bytes hash' description,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.bytes_hash = df.bytes_hash
                 and f.instructions > 5 and df.instructions > 5"""
    log_refresh("Finding with heuristic 'Bytes hash'")
    self.add_matches_from_query(sql, choose)

    if not self.ignore_all_names:
      self.find_same_name(self.partial_chooser)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Bytes sum' description,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.bytes_sum = df.bytes_sum
                 and f.size = df.size
                 and f.instructions > 5 and df.instructions > 5"""
    log_refresh("Finding with heuristic 'Bytes sum'")
    self.add_matches_from_query(sql, choose)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal pseudo-code' description,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.pseudocode = df.pseudocode
                and df.pseudocode is not null
                and f.pseudocode_lines >= 5 """ + postfix + """
              union
             select f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal assembly' description,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.assembly = df.assembly
                and df.assembly is not null
              """ + postfix
    log_refresh("Finding with heuristic 'Equal assembly or pseudo-code'")
    self.add_matches_from_query(sql, choose)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Same cleaned up assembly or pseudo-code' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.clean_assembly = df.clean_assembly
                  or f.clean_pseudo = df.clean_pseudo""" + postfix
    log_refresh("Finding with heuristic 'Same cleaned up assembly or pseudo-code'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same address, nodes, edges and mnemonics' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.rva = df.rva
                and f.instructions = df.instructions
                and f.nodes = df.nodes
                and f.edges = df.edges
                and f.mnemonics = df.mnemonics""" + postfix
    log_refresh("Finding with heuristic 'Same address, nodes, edges and mnemonics'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, None)

    cur.close()

  def ast_ratio(self, ast1, ast2):
    if not self.relaxed_ratio:
      return 0
    return ast_ratio(ast1, ast2)

  def check_ratio(self, ast1, ast2, pseudo1, pseudo2, asm1, asm2):
    fratio = quick_ratio
    decimal_values = "{0:.2f}"
    if self.relaxed_ratio:
      fratio = real_quick_ratio
      decimal_values = "{0:.1f}"

    v3 = 0
    ast_done = False
    if self.relaxed_ratio and ast1 is not None and ast2 is not None and max(len(ast1), len(ast2)) < 16:
      ast_done = True
      v3 = self.ast_ratio(ast1, ast2)
      if v3 == 1:
        return 1.0

    v1 = 0
    if pseudo1 is not None and pseudo2 is not None and pseudo1 != "" and pseudo2 != "":
      tmp1 = self.get_cmp_pseudo_lines(pseudo1)
      tmp2 = self.get_cmp_pseudo_lines(pseudo2)
      if tmp1 == "" or tmp2 == "":
        log("Error cleaning pseudo-code!")
      else:
        v1 = fratio(tmp1, tmp2)
        v1 = float(decimal_values.format(v1))
        if v1 == 1.0:
          # If real_quick_ratio returns 1 try again with quick_ratio
          # because it can result in false positives. If real_quick_ratio
          # says 'different', there is no point in continuing.
          if fratio == real_quick_ratio:
            v1 = quick_ratio(tmp1, tmp2)
            if v1 == 1.0:
              return 1.0

    tmp_asm1 = self.get_cmp_asm_lines(asm1)
    tmp_asm2 = self.get_cmp_asm_lines(asm2)
    v2 = fratio(tmp_asm1, tmp_asm2)
    v2 = float(decimal_values.format(v2))
    if v2 == 1:
      # Actually, same as the quick_ratio/real_quick_ratio check done
      # with the pseudo-code
      if fratio == real_quick_ratio:
        v2 = quick_ratio(tmp_asm1, tmp_asm2)
        if v2 == 1.0:
          return 1.0

    if self.relaxed_ratio and not ast_done:
      v3 = fratio(ast1, ast2)
      v3 = float(decimal_values.format(v3))
      if v3 == 1:
        return 1.0

    r = max(v1, v2, v3)
    return r

  def all_functions_matched(self):
    return len(self.matched1) == self.total_functions1 or \
           len(self.matched2) == self.total_functions2

  def add_matches_from_query_ratio(self, sql, best, partial, unreliable=None):
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      return

    i = 0
    t = time.time()
    while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
      if time.time() - t > self.timeout:
        log("Timeout")
        break

      i += 1
      if i % 50000 == 0:
        log("Processed %d rows..." % i)
      row = cur.fetchone()
      if row is None:
        break

      ea = str(row["ea"])
      name1 = row["name1"]
      ea2 = row["ea2"]
      name2 = row["name2"]
      desc = row["description"]
      pseudo1 = row["pseudo1"]
      pseudo2 = row["pseudo2"]
      asm1 = row["asm1"]
      asm2 = row["asm2"]
      ast1 = row["pseudo_primes1"]
      ast2 = row["pseudo_primes2"]
      bb1 = int(row["bb1"])
      bb2 = int(row["bb2"])

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2)
      if r == 1:
        self.best_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r >= 0.5:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r < 5 and unreliable is not None:
        unreliable.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      else:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()

  def add_matches_from_query_ratio_max(self, sql, best, partial, val):
    if self.all_functions_matched():
      return
    
    cur = self.db_cursor()
    try:
      cur.execute(sql)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      return

    i = 0
    t = time.time()
    while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
      if time.time() - t > self.timeout:
        log("Timeout")
        break

      i += 1
      if i % 50000 == 0:
        log("Processed %d rows..." % i)
      row = cur.fetchone()
      if row is None:
        break

      ea = str(row["ea"])
      name1 = row["name1"]
      ea2 = row["ea2"]
      name2 = row["name2"]
      desc = row["description"]
      pseudo1 = row["pseudo1"]
      pseudo2 = row["pseudo2"]
      asm1 = row["asm1"]
      asm2 = row["asm2"]
      ast1 = row["pseudo_primes1"]
      ast2 = row["pseudo_primes2"]
      bb1 = int(row["bb1"])
      bb2 = int(row["bb2"])

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2)

      if r == 1:
        self.best_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r > val:
        best.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif partial is not None:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()

  def add_matches_from_query(self, sql, choose):
    """ Warning: use this *only* if the ratio is known to be 1.00 """
    if self.all_functions_matched():
      return
    
    cur = self.db_cursor()
    try:
      cur.execute(sql)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      return

    i = 0
    while 1:
      i += 1
      if i % 1000 == 0:
        log("Processed %d rows..." % i)
      row = cur.fetchone()
      if row is None:
        break

      ea = str(row["ea"])
      name1 = row["name1"]
      ea2 = row["ea2"]
      name2 = row["name2"]
      desc = row["description"]
      bb1 = int(row["bb1"])
      bb2 = int(row["bb2"])

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      choose.add_item(CChooser.Item(ea, name1, ea2, name2, desc, 1, bb1, bb2))
      self.matched1.add(name1)
      self.matched2.add(name2)
    cur.close()

  def search_small_differences(self, choose):
    cur = self.db_cursor()
    
    # Same basic blocks, edges, mnemonics, etc... but different names
    sql = """ select distinct f.address ea, f.name name1, df.name name2,
                     f.names f_names, df.names df_names, df.address ea2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.names != '[]'"""
    cur.execute(sql)
    rows = result_iter(cur)
    for row in rows:
      ea = str(row["ea"])
      name1 = row["name1"]
      name2 = row["name2"]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      bb1 = int(row["bb1"])
      bb2 = int(row["bb2"])

      s1 = set(json.loads(row["f_names"]))
      s2 = set(json.loads(row["df_names"]))
      total = max(len(s1), len(s2))
      commons = len(s1.intersection(s2))
      ratio = (commons * 1.) / total
      if ratio >= 0.5:
        ea2 = row["ea2"]
        item = CChooser.Item(ea, name1, ea2, name2, "Nodes, edges, complexity and mnemonics with small differences", ratio, bb1, bb2)
        if ratio == 1.0:
          self.best_chooser.add_item(item)
        else:
          choose.add_item(item)
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()
    return

  def find_same_name(self, choose):
    cur = self.db_cursor()
    sql = """select f.address ea1, f.mangled_function mangled1,
                    d.address ea2, f.name name, d.name name2,
                    d.mangled_function mangled2,
                    f.pseudocode pseudo1, d.pseudocode pseudo2,
                    f.assembly asm1, d.assembly asm2,
                    f.pseudocode_primes primes1,
                    d.pseudocode_primes primes2,
                    f.nodes bb1, d.nodes bb2
               from functions f,
                    diff.functions d
              where d.mangled_function = f.mangled_function
                 or d.name = f.name"""
    log_refresh("Finding with heuristic 'Same name'")
    cur.execute(sql)
    rows = cur.fetchall()
    cur.close()

    if len(rows) > 0 and not self.all_functions_matched():
      for row in rows:
        ea = row["ea1"]
        name = row["mangled1"]
        ea2 = row["ea2"]
        name1 = row["name"]
        name2 = row["name2"]
        name2_1 = row["mangled2"]
        if name in self.matched1 or name1 in self.matched1 or \
           name2 in self.matched2 or name2_1 in self.matched2:
          continue

        if self.ignore_sub_names and name.startswith("sub_"):
          continue

        ast1 = row["primes1"]
        ast2 = row["primes2"]
        bb1 = row["bb1"]
        bb2 = row["bb2"]

        pseudo1 = row["pseudo1"]
        pseudo2 = row["pseudo2"]
        asm1 = row["asm1"]
        asm2 = row["asm2"]
        ratio = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2)
        if float(ratio) == 1.0:
          self.best_chooser.add_item(CChooser.Item(ea, name, ea2, name, "Perfect match, same name", 1, bb1, bb2))
        else:
          choose.add_item(CChooser.Item(ea, name, ea2, name, "Perfect match, same name", ratio, bb1, bb2))

        self.matched1.add(name)
        self.matched1.add(name1)
        self.matched2.add(name2)
        self.matched2.add(name2_1)

  def get_function_id(self, name, primary=True):
    cur = self.db_cursor()
    rid = None
    db_name = "main"
    if not primary:
      db_name = "diff"

    try:
      sql = "select id from %s.functions where name = ?" % db_name
      cur.execute(sql, (name,))
      row = cur.fetchone()
      if row:
        rid = row["id"]
    finally:
      cur.close()
    
    return rid

  def find_matches_in_hole(self, last, item, row):
    cur = self.db_cursor()
    try:

      postfix = ""
      if self.ignore_small_functions:
        postfix = " and instructions > 5"

      desc = "Call address sequence"
      id1 = row["id1"]
      id2 = row["id2"]
      sql = """ select * from functions where id = ? """ + postfix + """
                union all 
                select * from diff.functions where id = ? """ + postfix

      thresold = min(0.6, float(item[5]))
      done = False
      for j in range(0, min(10, id1 - last)):
        if done:
          break

        for i in range(0, min(10, id1 - last)):
          if done:
            break

          cur.execute(sql, (id1+j, id2+i))
          rows = cur.fetchall()
          if len(rows) == 2:
            name1 = rows[0]["name"]
            name2 = rows[1]["name"]
            if name1 in self.matched1 or name2 in self.matched2:
              continue

            r = self.check_ratio(rows[0]["pseudocode_primes"], rows[1]["pseudocode_primes"], \
                                 rows[0]["pseudocode"], rows[1]["pseudocode"], \
                                 rows[0]["assembly"], rows[1]["assembly"])
            if r < 0.5:
              if rows[0]["names"] != "[]" and rows[0]["names"] == rows[1]["names"]:
                r = 0.5001

            if r > thresold:
              ea = rows[0]["address"]
              ea2 = rows[1]["address"]
              bb1 = rows[0]["nodes"]
              bb2 = rows[1]["nodes"]

              if r == 1:
                self.best_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
              elif r > 0.5:
                self.partial_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
              else:
                self.unreliable_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
    finally:
      cur.close()

  def find_from_matches(self, the_items):
    # XXX: FIXME: This is wrong in many ways, but still works... FIX IT!
    # Rule 1: if a function A in program P is has id X and function B in
    # the same program is has id + 1, then, in program P2, function B
    # maybe the next function to A in P2.

    log_refresh("Finding with heuristic 'Call address sequence'")
    cur = self.db_cursor()
    try:
      # Create a copy of all the functions
      cur.execute("create temporary table best_matches (id, id1, ea1, name1, id2, ea2, name2)")

      # Insert each matched function into the temporary table
      i = 0
      for match in the_items:
        ea1 = match[1]
        name1 = match[2]
        ea2 = match[3]
        name2 = match[4]
        id1 = self.get_function_id(name1)
        id2 = self.get_function_id(name2, False)
        sql = """insert into best_matches (id, id1, ea1, name1, id2, ea2, name2)
                                   values (?, ?, ?, ?, ?, ?, ?)"""
        cur.execute(sql, (i, id1, ea1, name1, id2, ea2, name2))
        i += 1

      last = None
      cur.execute("select * from best_matches order by id1 asc")
      for row in cur:
        row_id = row["id1"]
        if last is None or last+1 == row_id:
          last = row_id
          continue

        item = the_items[row["id"]]
        self.find_matches_in_hole(last, item, row)
        last = row_id

      cur.execute("drop table best_matches")
    finally:
      cur.close()

    # Rule 2: given a match for a function F in programs P & P2, find
    # parents and children of the matched function using the parents and
    # children of program P.
    # TODO: Implement it.
    pass

  def find_matches(self):
    choose = self.partial_chooser

    postfix = ""
    if self.ignore_small_functions:
      postfix = " and f.instructions > 5 and df.instructions > 5 "

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2,
                    'All attributes' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.nodes = df.nodes 
                and f.edges = df.edges
                and f.indegree = df.indegree
                and f.outdegree = df.outdegree
                and f.size = df.size
                and f.instructions = df.instructions
                and f.mnemonics = df.mnemonics
                and f.names = df.names
                and f.prototype2 = df.prototype2
                and f.cyclomatic_complexity = df.cyclomatic_complexity
                and f.primes_value = df.primes_value
                and f.bytes_hash = df.bytes_hash
                and f.pseudocode_hash1 = df.pseudocode_hash1
                and f.pseudocode_primes = df.pseudocode_primes
                and f.pseudocode_hash2 = df.pseudocode_hash2
                and f.pseudocode_hash3 = df.pseudocode_hash3
                and f.strongly_connected = df.strongly_connected
                and f.loops = df.loops
                and f.tarjan_topological_sort = df.tarjan_topological_sort
                and f.strongly_connected_spp = df.strongly_connected_spp """ + postfix + """
              union 
             select f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Most attributes' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
               where f.nodes = df.nodes 
                 and f.edges = df.edges
                 and f.indegree = df.indegree
                 and f.outdegree = df.outdegree
                 and f.size = df.size
                 and f.instructions = df.instructions
                 and f.mnemonics = df.mnemonics
                 and f.names = df.names
                 and f.prototype2 = df.prototype2
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.primes_value = df.primes_value
                 and f.bytes_hash = df.bytes_hash
                 and f.strongly_connected = df.strongly_connected
                 and f.loops = df.loops
                 and f.tarjan_topological_sort = df.tarjan_topological_sort
                 and f.strongly_connected_spp = df.strongly_connected_spp """
    sql += postfix
    log_refresh("Finding with heuristic 'All or most attributes'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Switch structures' description,
                f.pseudocode pseudo1, df.pseudocode pseudo2,
                f.assembly asm1, df.assembly asm2,
                f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                f.nodes bb1, df.nodes bb2
           from functions f,
                diff.functions df
          where f.switches = df.switches
            and df.switches != '[]' """ + postfix
    log_refresh("Finding with heuristic 'Switch structures'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.2)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same address, nodes, edges and primes (re-ordered instructions)' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.rva = df.rva
                and f.instructions = df.instructions
                and f.nodes = df.nodes
                and f.edges = df.edges
                and f.primes_value = df.primes_value
                and f.nodes > 3""" + postfix
    log_refresh("Finding with heuristic 'Same address, nodes, edges and primes (re-ordered instructions)'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.5)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Import names hash' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.names = df.names
                 and f.names != '[]'
                 and f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.instructions = df.instructions""" + postfix
    log_refresh("Finding with heuristic 'Import names hash'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

    sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Nodes, edges, complexity, mnemonics, names, prototype2, in-degree and out-degree' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.names = df.names
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.prototype2 = df.prototype2
                 and f.indegree = df.indegree
                 and f.outdegree = df.outdegree
                 and f.nodes > 3
                 and f.edges > 3
                 and f.names != '[]'"""  + postfix + """
               union
              select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Nodes, edges, complexity, mnemonics, names and prototype2' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.names = df.names
                 and f.names != '[]'
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.prototype2 = df.prototype2""" + postfix
    log_refresh("Finding with heuristic 'Nodes, edges, complexity, mnemonics, names, prototype, in-degree and out-degree'")
    self.add_matches_from_query_ratio(sql, self.partial_chooser, self.partial_chooser)

    sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Mnemonics and names' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.mnemonics = df.mnemonics
                 and f.instructions = df.instructions
                 and f.names = df.names
                 and f.names != '[]'""" + postfix
    log_refresh("Finding with heuristic 'Mnemonics and names'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Mnemonics small-primes-product' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
                from functions f,
                     diff.functions df
               where f.mnemonics_spp = df.mnemonics_spp
                 and f.instructions = df.instructions
                 and df.instructions > 5"""
    log_refresh("Finding with heuristic 'Mnemonics small-primes-product'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    # Search using some of the previous criterias but calculating the
    # edit distance
    log_refresh("Finding with heuristic 'Small names difference'")
    self.search_small_differences(choose)

    if self.slow_heuristics:
      sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy hash' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where df.pseudocode_hash1 = f.pseudocode_hash1
                   or df.pseudocode_hash2 = f.pseudocode_hash2
                   or df.pseudocode_hash3 = f.pseudocode_hash3""" + postfix
      log_refresh("Finding with heuristic 'Pseudo-code fuzzy hashes'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, choose)
    else:
      sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy hash' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where df.pseudocode_hash1 = f.pseudocode_hash1""" + postfix
      log_refresh("Finding with heuristic 'Pseudo-code fuzzy hash'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

    sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar pseudo-code and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.pseudocode_lines = df.pseudocode_lines
                and f.names = df.names
                and df.names != '[]'
                and df.pseudocode_lines > 5
                and df.pseudocode is not null 
                and f.pseudocode is not null""" + postfix
    log_refresh("Finding with heuristic 'Similar pseudo-code and names'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

    if self.slow_heuristics:
      sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar pseudo-code' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.pseudocode_lines = df.pseudocode_lines
                  and df.pseudocode_lines > 5
                  and df.pseudocode is not null 
                  and f.pseudocode is not null""" + postfix
      log_refresh("Finding with heuristic 'Similar pseudo-code'")
      self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.6)

    sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy AST hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where df.pseudocode_primes = f.pseudocode_primes
                and f.pseudocode_lines > 3
                and length(f.pseudocode_primes) >= 35""" + postfix
    log_refresh("Finding with heuristic 'Pseudo-code fuzzy AST hash'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

    if self.slow_heuristics:
      sql = """  select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Partial pseudo-code fuzzy hash' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2
                   from functions f,
                        diff.functions df
                  where substr(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
                     or substr(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
                     or substr(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)""" + postfix
      log_refresh("Finding with heuristic 'Partial pseudo-code fuzzy hash'")
      self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Topological sort hash' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.strongly_connected = df.strongly_connected
                and f.tarjan_topological_sort = df.tarjan_topological_sort
                and f.strongly_connected > 3""" + postfix
    log_refresh("Finding with heuristic 'Topological sort hash'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

    sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity, prototype and names' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity >= 20
                  and f.prototype2 = df.prototype2
                  and df.names != '[]'""" + postfix
    log_refresh("Finding with heuristic 'Same high complexity, prototype and names'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity and names' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity >= 15
                  and df.names != '[]'""" + postfix
    log_refresh("Finding with heuristic 'Same high complexity and names'")
    self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

    if self.slow_heuristics:
      sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.strongly_connected = df.strongly_connected
                  and df.strongly_connected > 1
                  and f.nodes > 5 and df.nodes > 5
                  and f.strongly_connected_spp > 1
                  and df.strongly_connected_spp > 1""" + postfix
      log_refresh("Finding with heuristic 'Strongly connected components'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.80)

    sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components small-primes-product' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.strongly_connected_spp = df.strongly_connected_spp
                  and df.strongly_connected_spp > 1""" + postfix
    log_refresh("Finding with heuristic 'Strongly connected components small-primes-product'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

    if self.slow_heuristics:
      sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Loop count' description,
                  f.pseudocode pseudo1, df.pseudocode pseudo2,
                  f.assembly asm1, df.assembly asm2,
                  f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                  f.nodes bb1, df.nodes bb2
             from functions f,
                  diff.functions df
            where f.loops = df.loops
              and df.loops > 1
              and f.nodes > 3 and df.nodes > 3""" + postfix
      log_refresh("Finding with heuristic 'Loop count'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.49)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same nodes, edges and strongly connected components' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.nodes = df.nodes
                and f.edges = df.edges
                and f.strongly_connected = df.strongly_connected
                and df.nodes > 4""" + postfix
    log_refresh("Finding with heuristic 'Same nodes, edges and strongly connected components'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, choose, self.unreliable_chooser)

  def find_experimental_matches(self):
    choose = self.unreliable_chooser
    
    # Call address sequence heuristic
    self.find_from_matches(self.best_chooser.items)
    self.find_from_matches(self.partial_chooser.items)
    
    postfix = ""
    if self.ignore_small_functions:
      postfix = " and f.instructions > 5 and df.instructions > 5 "

    # XXX: FIXME: This heuristic looks wrong. The order is not being verified any where!!!
    sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same names and order' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and df.names != '[]'""" + postfix
    log_refresh("Finding with heuristic 'Same names and order'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    if self.slow_heuristics:
      sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar small pseudo-code' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.pseudocode_lines = df.pseudocode_lines
                  and df.pseudocode_lines <= 5
                  and df.pseudocode is not null 
                  and f.pseudocode is not null""" + postfix
      log_refresh("Finding with heuristic 'Similar small pseudo-code'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.49)

      sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Small pseudo-code fuzzy AST hash' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where df.pseudocode_primes = f.pseudocode_primes
                  and f.pseudocode_lines <= 5""" + postfix
      log_refresh("Finding with heuristic 'Small pseudo-code fuzzy AST hash'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

    sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal small pseudo-code' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2
               from functions f,
                    diff.functions df
              where f.pseudocode = df.pseudocode
                and df.pseudocode is not null
                and f.pseudocode_lines < 5""" + postfix
    log_refresh("Finding with heuristic 'Equal small pseudo-code'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

    sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity, prototype and names' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity < 20
                  and f.prototype2 = df.prototype2
                  and df.names != '[]'""" + postfix
    log_refresh("Finding with heuristic 'Same low complexity, prototype and names'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.5)

    sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same low complexity and names' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity < 15
                  and df.names != '[]'""" + postfix
    log_refresh("Finding with heuristic 'Same low complexity and names'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.5)
  
    if self.slow_heuristics:
      # For large databases (>25k functions) it may cause, for a reason,
      # the following error: OperationalError: database or disk is full
      sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                 'Same graph' description,
                 f.pseudocode pseudo1, df.pseudocode pseudo2,
                 f.assembly asm1, df.assembly asm2,
                 f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                 f.nodes bb1, df.nodes bb2
            from functions f,
                 diff.functions df
           where f.nodes = df.nodes 
             and f.edges = df.edges
             and f.indegree = df.indegree
             and f.outdegree = df.outdegree
             and f.cyclomatic_complexity = df.cyclomatic_complexity
             and f.strongly_connected = df.strongly_connected
             and f.loops = df.loops
             and f.tarjan_topological_sort = df.tarjan_topological_sort
             and f.strongly_connected_spp = df.strongly_connected_spp""" + postfix + """
           order by
                 case when f.size = df.size then 1 else 0 end +
                 case when f.instructions = df.instructions then 1 else 0 end +
                 case when f.mnemonics = df.mnemonics then 1 else 0 end +
                 case when f.names = df.names then 1 else 0 end +
                 case when f.prototype2 = df.prototype2 then 1 else 0 end +
                 case when f.primes_value = df.primes_value then 1 else 0 end +
                 case when f.bytes_hash = df.bytes_hash then 1 else 0 end +
                 case when f.pseudocode_hash1 = df.pseudocode_hash1 then 1 else 0 end +
                 case when f.pseudocode_primes = df.pseudocode_primes then 1 else 0 end +
                 case when f.pseudocode_hash2 = df.pseudocode_hash2 then 1 else 0 end +
                 case when f.pseudocode_hash3 = df.pseudocode_hash3 then 1 else 0 end DESC"""
      log_refresh("Finding with heuristic 'Same graph'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

  def find_unreliable_matches(self):
    choose = self.unreliable_chooser

    postfix = ""
    if self.ignore_small_functions:
      postfix = " and f.instructions > 5 and df.instructions > 5 "

    if self.slow_heuristics:
      sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where f.strongly_connected = df.strongly_connected
                  and df.strongly_connected > 2""" + postfix
      log_refresh("Finding with heuristic 'Strongly connected components'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.54)

      sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Loop count' description,
                  f.pseudocode pseudo1, df.pseudocode pseudo2,
                  f.assembly asm1, df.assembly asm2,
                  f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                  f.nodes bb1, df.nodes bb2
             from functions f,
                  diff.functions df
            where f.loops = df.loops
              and df.loops > 1""" + postfix
      log_refresh("Finding with heuristic 'Loop count'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges, complexity and mnemonics' description,
                       f.pseudocode pseudo1, df.pseudocode pseudo2,
                       f.assembly asm1, df.assembly asm2,
                       f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                       f.nodes bb1, df.nodes bb2
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.mnemonics = df.mnemonics
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.nodes > 1 and f.edges > 0""" + postfix
      log_refresh("Finding with heuristic 'Nodes, edges, complexity and mnemonics'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges, complexity and prototype' description,
                       f.pseudocode pseudo1, df.pseudocode pseudo2,
                       f.assembly asm1, df.assembly asm2,
                       f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                       f.nodes bb1, df.nodes bb2
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.prototype2 = df.prototype2
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.prototype2 != 'int()'""" + postfix
      log_refresh("Finding with heuristic 'Nodes, edges, complexity and prototype'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges, complexity, in-degree and out-degree' description,
                       f.pseudocode pseudo1, df.pseudocode pseudo2,
                       f.assembly asm1, df.assembly asm2,
                       f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                       f.nodes bb1, df.nodes bb2
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.nodes > 3 and f.edges > 2
                   and f.indegree = df.indegree
                   and f.outdegree = df.outdegree""" + postfix
      log_refresh("Finding with heuristic 'Nodes, edges, complexity, in-degree and out-degree'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges and complexity' description,
                       f.pseudocode pseudo1, df.pseudocode pseudo2,
                       f.assembly asm1, df.assembly asm2,
                       f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                       f.nodes bb1, df.nodes bb2
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.nodes > 1 and f.edges > 0""" + postfix
      log_refresh("Finding with heuristic 'Nodes, edges and complexity'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

      sql = """select f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar small pseudo-code' description,
                      f.pseudocode pseudo1, df.pseudocode pseudo2,
                      f.assembly asm1, df.assembly asm2,
                      f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                      f.nodes bb1, df.nodes bb2
                 from functions f,
                      diff.functions df
                where df.pseudocode is not null 
                  and f.pseudocode is not null
                  and f.pseudocode_lines = df.pseudocode_lines
                  and df.pseudocode_lines > 5""" + postfix
      log_refresh("Finding with heuristic 'Similar small pseudo-code'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.5)

      sql = """  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2
                   from functions f,
                        diff.functions df
                  where f.cyclomatic_complexity = df.cyclomatic_complexity
                    and f.cyclomatic_complexity >= 50""" + postfix
      log_refresh("Finding with heuristic 'Same high complexity'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

  def find_unmatched(self):
    cur = self.db_cursor()
    sql = "select name, address from functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      choose = self.chooser("Unmatched in secondary", self, False)
      for row in rows:
        name = row["name"]

        if name not in self.matched1:
          ea = row[1]
          choose.add_item(CChooser.Item(ea, name))
      self.unmatched_second = choose

    sql = "select name, address from diff.functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      choose = self.chooser("Unmatched in primary", self, False)
      for row in rows:
        name = row["name"]

        if name not in self.matched2:
          ea = row["address"]
          choose.add_item(CChooser.Item(ea, name))
      self.unmatched_primary = choose

    cur.close()

  def create_choosers(self):
    self.unreliable_chooser = self.chooser("Unreliable matches", self)
    self.partial_chooser = self.chooser("Partial matches", self)
    self.best_chooser = self.chooser("Best matches", self)

    self.unmatched_second = self.chooser("Unmatched in secondary", self, False)
    self.unmatched_primary = self.chooser("Unmatched in primary", self, False)

  def save_results(self, filename):
    if os.path.exists(filename):
      os.remove(filename)
      log("Previous diff results '%s' removed." % filename)

    results_db = sqlite3.connect(filename)
    results_db.text_factory = str

    cur = results_db.cursor()
    try:
      sql = "create table config (main_db text, diff_db text, version text, date text)"
      cur.execute(sql)

      sql = "insert into config values (?, ?, ?, ?)"
      cur.execute(sql, (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime()))

      sql = "create table results (type, line, address, name, address2, name2, ratio, bb1, bb2, description)"
      cur.execute(sql)

      sql = "create table unmatched (type, line, address, name)"
      cur.execute(sql)

      with results_db:
        results_sql   = "insert into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        unmatched_sql = "insert into unmatched values (?, ?, ?, ?)"

        for item in self.best_chooser.items:
          l = list(item)
          l.insert(0, 'best')
          cur.execute(results_sql, l)

        for item in self.partial_chooser.items:
          l = list(item)
          l.insert(0, 'partial')
          cur.execute(results_sql, l)

        for item in self.unreliable_chooser.items:
          l = list(item)
          l.insert(0, 'unreliable')
          cur.execute(results_sql, l)

        for item in self.unmatched_primary.items:
          l = list(item)
          l.insert(0, 'primary')
          cur.execute(unmatched_sql, l)

        for item in self.unmatched_second.items:
          l = list(item)
          l.insert(0, 'secondary')
          cur.execute(unmatched_sql, l)

      log("Diffing results saved in file '%s'." % filename)
    finally:
      cur.close()
      results_db.close()


  def diff(self, db):
    self.last_diff_db = db

    cur = self.db_cursor()
    cur.execute('attach "%s" as diff' % db)

    try:
      cur.execute("select value from diff.version")
    except:
      log("Error: %s " % sys.exc_info()[1])
      Warning("The selected file does not look like a valid SQLite exported database!")
      cur.close()
      return False

    row = cur.fetchone()
    if not row:
      Warning("Invalid database!")
      return False

    if row["value"] != VERSION_VALUE:
      Warning("The database is from a different version (current %s, database %s)!" % (VERSION_VALUE, row[0]))
      return False

    try:
      log_refresh("Performing diffing...", True)
      
      self.do_continue = True
      if self.equal_db():
        log("The databases seems to be 100% equal")

      if self.do_continue:
        # Compare the call graphs
        self.check_callgraph()

        # Find the unmodified functions
        log_refresh("Finding best matches...")
        self.find_equal_matches()

        # Find the modified functions
        log_refresh("Finding partial matches")
        self.find_matches()

        if self.unreliable:
          # Find using likely unreliable methods modified functions
          log_refresh("Finding probably unreliable matches")
          self.find_unreliable_matches()
        
        if self.experimental:
          # Find using experimental methods modified functions
          log_refresh("Finding experimental matches")
          self.find_experimental_matches()

        # Show the list of unmatched functions in both databases
        log_refresh("Finding unmatched functions")
        self.find_unmatched()

        log("Done")
    finally:
      cur.close()
    return True

if __name__ == "__main__":
  do_diff = True
  if os.getenv("DIAPHORA_AUTO_DIFF") is not None:
    db1 = os.getenv("DIAPHORA_DB1")
    if db1 is None:
      raise Exception("No database file specified!")

    db2 = os.getenv("DIAPHORA_DB2")
    if db2 is None:
      raise Exception("No database file to diff against specified!")

    diff_out = os.getenv("DIAPHORA_DIFF_OUT")
    if diff_out is None:
      raise Exception("No output file for diff specified!")
  elif is_ida:
    diaphora_dir = os.path.dirname(__file__)
    script = os.path.join(diaphora_dir, "diaphora_ida.py")
    execfile(script)
    do_diff = False
  else:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("db1")
    parser.add_argument("db2")
    parser.add_argument("-o", "--outfile", help="Write output to <outfile>")
    args = parser.parse_args()
    db1 = args.db1
    db2 = args.db2
    if args.outfile:
      diff_out = args.outfile
    else:
      diff_out = "{}_vs_{}.diaphora".format(
              os.path.basename(os.path.splitext(db1)[0]),
              os.path.basename(os.path.splitext(db2)[0]))

  if do_diff:
    bd = CBinDiff(db1)
    bd.db = sqlite3.connect(db1)
    bd.db.text_factory = str
    bd.db.row_factory = sqlite3.Row
    bd.diff(db2)
    bd.save_results(diff_out)
