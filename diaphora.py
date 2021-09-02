#!/usr/bin/python3

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015-2021, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import re
import sys
import time
import json
import decimal
import sqlite3
import threading

from threading import Thread
from io import StringIO
from difflib import SequenceMatcher
from multiprocessing import cpu_count

from diaphora_heuristics import *

from jkutils.kfuzzy import CKoretFuzzyHashing
from jkutils.factor import (FACTORS_CACHE, difference, difference_ratio,
                            primesbelow as primes)

try:
  import idaapi
  is_ida = True
except ImportError:
  is_ida = False

#-------------------------------------------------------------------------------
VERSION_VALUE = "2.0.8"
COPYRIGHT_VALUE="Copyright(c) 2015-2021 Joxean Koret"
COMMENT_VALUE="Diaphora diffing plugin for IDA version %s" % VERSION_VALUE

# Used to clean-up the pseudo-code and assembly dumps in order to get
# better comparison ratios
CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_", "flt_", "jpt_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]


#-------------------------------------------------------------------------------
def result_iter(cursor, arraysize=1000):
  """ An iterator that uses fetchmany to keep memory usage down. """
  while True:
    results = cursor.fetchmany(arraysize)
    if not results:
      break
    for result in results:
      yield result

#-------------------------------------------------------------------------------
def quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.quick_ratio()
  except:
    print("quick_ratio:", str(sys.exc_info()[1]))
    return 0

#-------------------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.real_quick_ratio()
  except:
    print("real_quick_ratio:", str(sys.exc_info()[1]))
    return 0

#-------------------------------------------------------------------------------
def ast_ratio(ast1, ast2):
  if ast1 == ast2:
    return 1.0
  elif ast1 is None or ast2 is None:
    return 0
  return difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))

#-------------------------------------------------------------------------------
def log(msg):
  if isinstance(threading.current_thread(), threading._MainThread):
    print(("[%s] %s" % (time.asctime(), msg)))

#-------------------------------------------------------------------------------
def log_refresh(msg, show=False, do_log=True):
  log(msg)

#-------------------------------------------------------------------------------
def debug_refresh(msg, show=False):
  if os.getenv("DIAPHORA_DEBUG"):
    log(msg)

#-------------------------------------------------------------------------------
class CChooser():
  class Item:
    def __init__(self, ea, name, ea2 = None, name2 = None, desc="100% equal", ratio = 0, bb1 = 0, bb2 = 0):
      self.ea = ea
      self.vfname = name
      self.ea2 = ea2
      self.vfname2 = name2
      self.description = desc
      self.ratio = ratio
      self.bb1 = int(bb1)
      self.bb2 = int(bb2)
      self.cmd_import_selected = None
      self.cmd_import_all = None
      self.cmd_import_all_funcs = None

    def __str__(self):
      return '%08x' % int(self.ea)

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


#-------------------------------------------------------------------------------
MAX_PROCESSED_ROWS = 1000000
TIMEOUT_LIMIT = 60 * 3

#-------------------------------------------------------------------------------
class bytes_encoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, bytes):
      return obj.decode("utf-8")
    return json.JSONEncoder.default(self, obj)

#-------------------------------------------------------------------------------
class CBinDiff:
  def __init__(self, db_name, chooser=CChooser):
    self.names = dict()
    self.primes = primes(2048*2048)
    self.db_name = db_name
    self.dbs_dict = {}
    self.db = None # Used exclusively by the exporter!
    self.open_db()
    self.matched1 = set()
    self.matched2 = set()
    self.matches_cache = {}
    self.total_functions1 = None
    self.total_functions2 = None
    self.equal_callgraph = False

    self.kfh = CKoretFuzzyHashing()
    # With this block size we're sure it will only apply to functions
    # somehow big
    self.kfh.bsize = 32

    self.pseudo = {}
    self.pseudo_hash = {}
    self.pseudo_comments = {}

    self.unreliable = self.get_value_for("unreliable", False)
    self.relaxed_ratio = self.get_value_for("relaxed_ratio", False)
    self.experimental = self.get_value_for("experimental", False)
    self.slow_heuristics = self.get_value_for("slow_heuristics", False)

    self.unreliable = False
    self.relaxed_ratio = False
    self.experimental = False
    self.slow_heuristics = False
    self.use_decompiler_always = True
    self.exclude_library_thunk = True
    self.project_script = None
    self.hooks = None

    # Create the choosers
    self.chooser = chooser
    # Create the choosers
    self.create_choosers()

    self.last_diff_db = None
    self.re_cache = {}

    ####################################################################
    # LIMITS
    #
    # Do not run heuristics for more than X seconds (by default, 3 minutes).
    self.timeout = self.get_value_for("TIMEOUT_LIMIT", TIMEOUT_LIMIT)
    # It's typical in SQL queries to get a cartesian product of the 
    # results in the functions tables. Do not process more than this
    # value per each 20k functions.
    self.max_processed_rows = self.get_value_for("MAX_PROCESSED_ROWS", MAX_PROCESSED_ROWS)
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
    self.ignore_all_names = self.get_value_for("ignore_all_names", True)
    # Ignore small functions?
    self.ignore_small_functions = self.get_value_for("ignore_small_functions", False)
    # Number of CPU threads/cores to use?
    cpus = cpu_count() - 1
    if cpus < 1:
      cpus = 1
    self.cpu_count = self.get_value_for("CPU_COUNT", cpus)
    ####################################################################

  def __del__(self):
    if self.db is not None:
      try:
        if self.last_diff_db is not None:
          tid = threading.current_thread().ident
          if tid in self.dbs_dict:
            db = self.dbs_dict[tid]
            with db.cursor() as cur:
              cur.execute('detach "%s"' % self.last_diff_db)
      except:
        pass
      self.db_close()

  def get_value_for(self, value_name, default):
    # Try to search for a DIAPHORA_<value_name> environment variable
    value = os.getenv("DIAPHORA_%s" % value_name.upper())
    if value is not None:
      if type(value) != type(default):
        value = type(default)(value)
      return value
    return default

  def open_db(self):
    db = sqlite3.connect(self.db_name, check_same_thread=True)
    db.text_factory = str
    db.row_factory = sqlite3.Row

    tid = threading.current_thread().ident
    self.dbs_dict[tid] = db
    if isinstance(threading.current_thread(), threading._MainThread):
      self.db = db
      self.create_schema()
      try:
        db.execute("analyze")
      except:
        pass

  def get_db(self):
    tid = threading.current_thread().ident
    if not tid in self.dbs_dict:
      self.open_db()
      if self.last_diff_db is not None:
        self.attach_database(self.last_diff_db)
    return self.dbs_dict[tid]

  def db_cursor(self):
    db = self.get_db()
    return db.cursor()

  def db_close(self):
    tid = threading.current_thread().ident
    if tid in self.dbs_dict:
      self.dbs_dict[tid].close()
      del self.dbs_dict[tid]
    if isinstance(threading.current_thread(), threading._MainThread):
      self.db.close()

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
                        bytes_sum integer,
                        md_index text,
                        constants text,
                        constants_count integer,
                        segment_rva text,
                        assembly_addrs text,
                        kgh_hash text,
                        userdata text) """
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
                type text,
                pseudocomment text,
                pseudoitp integer) """
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

    sql = """ create table if not exists bb_instructions (
                id integer primary key,
                basic_block_id integer references basic_blocks(id) on delete cascade,
                instruction_id integer references instructions(id) on delete cascade)"""
    cur.execute(sql)

    sql = """ create table if not exists function_bblocks (
                id integer primary key,
                function_id integer not null references functions(id) on delete cascade,
                basic_block_id integer not null references basic_blocks(id) on delete cascade)"""
    cur.execute(sql)
    
    sql = """create table if not exists callgraph (
                id integer primary key,
                func_id integer not null references functions(id) on delete cascade,
                address text not null,
                type text not null)"""
    cur.execute(sql)

    sql = """create table if not exists constants (
                id integer primary key,
                func_id integer not null references functions(id) on delete cascade,
                constant text not null)"""
    cur.execute(sql)

    cur.execute("select 1 from version")
    row = cur.fetchone()
    if not row:
      cur.execute("insert into main.version values ('%s')" % VERSION_VALUE)

    cur.close()

  def create_indexes(self):
    cur = self.db_cursor()
    
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

    sql = "create index if not exists idx_md_index on functions(md_index)"
    cur.execute(sql)

    sql = "create index if not exists idx_kgh_hash on functions(kgh_hash)"
    cur.execute(sql)

    sql = "create index if not exists idx_constants on functions(constants_count, constants)"
    cur.execute(sql)

    sql = "create index if not exists idx_mdindex_constants on functions(md_index, constants_count, constants)"
    cur.execute(sql)

    sql = "create index if not exists idx_instructions_address on instructions (address)"
    cur.execute(sql)

    sql = "create index if not exists idx_bb_relations on bb_relations(parent_id, child_id)"
    cur.execute(sql)

    sql = "create index if not exists idx_bb_instructions on bb_instructions (basic_block_id, instruction_id)"
    cur.execute(sql)

    sql = "create index if not exists id_function_blocks on function_bblocks (function_id, basic_block_id)"
    cur.execute(sql)

    sql = "create index if not exists idx_constants on constants (constant)"
    cur.execute(sql)

    sql = "analyze"
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
    if props == False:
      log("WARNING: Trying to save a non resolved function?")
      return

    # Phase 1: Fix data types and insert the function row.
    cur = self.db_cursor()
    new_props = []
    # The last 4 fields are callers, callees, basic_blocks_data & bb_relations
    for prop in props[:len(props)-4]:
      # XXX: Fixme! This is a hack for 64 bit architectures kernels
      if type(prop) is int and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
        prop = str(prop)
      elif type(prop) is bytes:
        prop = prop.encode("utf-8")

      if type(prop) is list or type(prop) is set:
        new_props.append(json.dumps(list(prop), ensure_ascii=False, cls=bytes_encoder))
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
                                    function_hash, bytes_sum, md_index, constants,
                                    constants_count, segment_rva, assembly_addrs, kgh_hash,
                                    userdata)
                                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

    try:
      cur.execute(sql, new_props)
    except:
      print("Props???", new_props)
      raise

    func_id = cur.lastrowid

    # Phase 2: Save the callers and callees of the function
    callers, callees = props[len(props)-4:len(props)-2]
    sql = "insert into callgraph (func_id, address, type) values (?, ?, ?)"
    for caller in callers:
      cur.execute(sql, (func_id, str(caller), 'caller'))
    
    for callee in callees:
      cur.execute(sql, (func_id, str(callee), 'callee'))

    # Phase 3: Insert the constants of the function
    sql = "insert into constants (func_id, constant) values (?, ?)"
    props_dict = self.create_function_dictionary(props)
    for constant in props_dict["constants"]:
      should_add = False
      if type(constant) in [str, bytes] and len(constant) > 4:
        should_add = True
      elif type(constant) in [int, float, decimal.Decimal]:
        should_add = True
        constant = str(constant)

      if should_add:
        cur.execute(sql, (func_id, constant))

    # Phase 4: Save the basic blocks relationships
    if not self.function_summaries_only:
      # The last 2 fields are basic_blocks_data & bb_relations
      bb_data, bb_relations = props[len(props)-2:]
      instructions_ids = {}
      sql = """insert into main.instructions (address, mnemonic, disasm,
                                              comment1, comment2, name,
                                              type, pseudocomment,
                                              pseudoitp)
                                values (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
      self_get_instruction_id = self.get_instruction_id
      cur_execute = cur.execute
      for key in bb_data:
        for insn in bb_data[key]:
          addr, mnem, disasm, cmt1, cmt2, name, mtype = insn
          db_id = self_get_instruction_id(str(addr))
          if db_id is None:
            pseudocomment = None
            pseudoitp = None
            if addr in self.pseudo_comments:
              pseudocomment, pseudoitp = self.pseudo_comments[addr]

            cur_execute(sql, (str(addr), mnem, disasm, cmt1, cmt2, name, mtype, pseudocomment, pseudoitp))
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
          cur_execute(sql1, (num, str(ins_ea)))
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
          try:
            cur_execute(sql, (bb_ids[key], bb_ids[bb]))
          except:
            # key doesnt exist because it doesnt have forward references to any bb
            log("Error: %s" % str(sys.exc_info()[1]))

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
    ret = ret.replace("$", "_")
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
    cur.execute(sql, (str(ea1),))
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
    cur.execute(sql, (str(ea1), ))
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
    cur.execute("delete from functions where address = ?", (str(ea), ))
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
        if total == 0 or diff == 0:
          log("Callgraphs are 100% equal")
        else:
          percent = diff * 100. / total
          if percent >= 100:
            log("Callgraphs are absolutely different")
          else:
            log("Callgraphs from both programs differ in %f%%" % percent)

    cur.close()

  def find_equal_matches_parallel(self):
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
    if len(rows) > 0:
      for row in rows:
        name = row["mangled_function"]
        ea = row["ea"]
        nodes = int(row["nodes"])

        self.best_chooser.add_item(CChooser.Item(ea, name, ea, name, "100% equal", 1, nodes, nodes))
        self.matched1.add(name)
        self.matched2.add(name)
    cur.close()

    if not self.ignore_all_names:
      self.find_same_name(self.partial_chooser)

    self.run_heuristics_for_category("Best")

  def run_heuristics_for_category(self, arg_category):
    total_cpus = self.cpu_count
    if total_cpus < 1:
      total_cpus = 1

    mode = "[Parallel]"
    if total_cpus == 1:
      mode = "[Single thread]"

    postfix = ""
    if self.ignore_small_functions:
      postfix = " and f.instructions > 5 and df.instructions > 5 "

    if self.hooks is not None:
      if 'get_queries_postfix' in dir(self.hooks):
        postfix = self.hooks.get_queries_postfix(arg_category, postfix)

    threads_list = []
    heuristics = list(HEURISTICS)
    if self.hooks is not None:
      if 'get_heuristics' in dir(self.hooks):
        heuristics = self.hooks.get_heuristics(arg_category, heuristics)

    for heur in heuristics:
      if len(self.matched1) == self.total_functions1 or len(self.matched2) == self.total_functions2:
        log("All functions matched in at least one database, finishing.")
        break

      category = heur["category"]
      if category != arg_category:
        continue

      name  = heur["name"]
      sql   = heur["sql"]
      ratio = heur["ratio"]
      min_value = 0.0
      if ratio == HEUR_TYPE_RATIO_MAX:
        min_value = heur["min"]

      flags = heur["flags"]
      if flags & HEUR_FLAG_UNRELIABLE == HEUR_FLAG_UNRELIABLE and not self.unreliable:
        log_refresh("Skipping unreliable heuristic '%s'" % name)
        continue

      if flags & HEUR_FLAG_SLOW == HEUR_FLAG_SLOW and not self.slow_heuristics:
        log_refresh("Skipping slow heuristic '%s'" % name)
        continue

      if arg_category == "Unreliable":
        best = self.partial_chooser
        partial = self.unreliable_chooser
      else:
        best = self.best_chooser
        partial = self.partial_chooser

      log_refresh("%s Finding with heuristic '%s'" % (mode, name))
      sql = sql.replace("%POSTFIX%", postfix)

      if self.hooks is not None:
        if 'on_launch_heuristic' in dir(self.hooks):
          sql = self.hooks.on_launch_heuristic(name, sql)

      if ratio == HEUR_TYPE_NO_FPS:
        t = Thread(target=self.add_matches_from_query, args=(sql, best))
      elif ratio == HEUR_TYPE_RATIO:
        t = Thread(target=self.add_matches_from_query_ratio, args=(sql, best, partial))
      elif ratio == HEUR_TYPE_RATIO_MAX:
        t = Thread(target=self.add_matches_from_query_ratio_max, args=(sql, min_value))
      else:
        raise Exception("Invalid heuristic ratio calculation value!")

      t.name = name
      t.time = time.monotonic()
      t.start()
      threads_list.append(t)

      if total_cpus == 1:
        t.join()
        threads_list = []

      while len(threads_list) >= total_cpus:
        for i, t in enumerate(threads_list):
          if not t.is_alive():
            debug_refresh("[Parallel] Heuristic '%s' took %f..." % (t.name, time.monotonic() - t.time))
            del threads_list[i]
            debug_refresh("[Parallel] Waiting for any of %d thread(s) running to finish..." % len(threads_list))
            break
          else:
            log_refresh("[Parallel] %d thread(s) running, waiting for at least one to finish..." % len(threads_list), do_log=False)
            t.join(0.1)
            if is_ida:
              self.refresh()

    if len(threads_list) > 0:
      log_refresh("[Parallel] Waiting for remaining %d thread(s) to finish..." % len(threads_list), do_log=False)

      do_cancel = False
      times = 0
      while len(threads_list) > 0 and not do_cancel:
        times += 1
        for i, t in enumerate(threads_list):
          t.join(0.1)
          if not t.is_alive():
            debug_refresh("[Parallel] Heuristic '%s' took %f..." % (t.name, time.monotonic() - t.time))
            del threads_list[i]
            debug_refresh("[Parallel] Waiting for remaining %d thread(s) to finish..." % len(threads_list))
            break

          t.join(0.1)
          if time.monotonic() - t.time > TIMEOUT_LIMIT:
            do_cancel = True
            try:
              log_refresh("Timeout, cancelling queries...")
              self.get_db().interrupt()
            except:
              print(("database.interrupt(): %s" % str(sys.exc_info()[1])))

        if times % 50 == 0:
          names = []
          for x in threads_list:
            names.append(x.name)
          log_refresh("[Parallel] %d thread(s) still running:\n\n%s" % (len(threads_list), ", ".join(names)))

  def ast_ratio(self, ast1, ast2):
    if not self.relaxed_ratio:
      return 0
    return ast_ratio(ast1, ast2)

  def check_ratio(self, ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2):
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
      if v3 == 1.0:
        return v3

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

    v4 = 0.0
    if md1 == md2 and md1 > 0.0:
      # A MD-Index >= 10.0 is somehow rare
      if self.relaxed_ratio and md1 > 10.0:
        return 1.0
      v4 = min((v1 + v2 + v3 + 3.0) / 5, 1.0)

    r = max(v1, v2, v3, v4)
    if r == 1.0 and md1 != md2:
      # We cannot assign a 1.0 ratio if both MD indices are different, that's an
      # error
      r = 0
      for v in [v1, v2, v3, v4]:
        if v != 1.0 and v > r:
          r = v

    return r

  def all_functions_matched(self):
    return len(self.matched1) == self.total_functions1 or \
           len(self.matched2) == self.total_functions2

  def add_matches_from_query_ratio(self, sql, best, partial, unreliable=None, debug=False):
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      return

    i = 0
    t = time.monotonic()
    while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
      if time.monotonic() - t > self.timeout:
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
      md1 = row["md1"]
      md2 = row["md2"]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2)
      if debug:
        print("0x%x 0x%x %d" % (int(ea), int(ea2), r))

      should_add = True
      if self.hooks is not None:
        if 'on_match' in dir(self.hooks):
          d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
          d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
          should_add, r = self.hooks.on_match(d1, d2, desc, r)

      if not should_add or name1 in self.matched1 or name2 in self.matched2:
        continue

      if r == 1.0:
        self.best_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r >= 0.5:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r < 0.5 and unreliable is not None:
        unreliable.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      else:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()

  def add_matches_from_query_ratio_max(self, sql, val):
    if self.all_functions_matched():
      return
    
    cur = self.db_cursor()
    try:
      cur.execute(sql)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      return

    i = 0
    t = time.monotonic()
    while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
      if time.monotonic() - t > self.timeout:
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
      md1 = row["md1"]
      md2 = row["md2"]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2)

      should_add = True
      if self.hooks is not None:
        if 'on_match' in dir(self.hooks):
          d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
          d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
          should_add, r = self.hooks.on_match(d1, d2, desc, r)

      if not should_add or name1 in self.matched1 or name2 in self.matched2:
        continue

      if r == 1.0:
        self.best_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r >= 0.5:
        self.partial_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r < 0.5 and r > val:
        self.unreliable_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()

  def add_matches_from_cursor_ratio_max(self, cur, best, partial, val):
    if self.all_functions_matched():
      return

    matches = []
    i = 0
    t = time.monotonic()
    while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
      if time.monotonic() - t > self.timeout:
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
      md1 = row["md1"]
      md2 = row["md2"]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2)

      should_add = True
      if self.hooks is not None:
        if 'on_match' in dir(self.hooks):
          d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
          d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
          should_add, r = self.hooks.on_match(d1, d2, desc, r)

      if not should_add or name1 in self.matched1 or name2 in self.matched2:
        continue

      good_ratio = False
      if r == 1.0:
        item = CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2)
        good_ratio = True
        self.best_chooser.add_item(item)
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r > val:
        item = CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2)
        good_ratio = True
        best.add_item(item)
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif partial is not None:
        item = CChooser.Item(ea, name1, ea2, name2, desc, r, bb1, bb2)
        good_ratio = True
        partial.add_item(item)
        self.matched1.add(name1)
        self.matched2.add(name2)
      
      if good_ratio:
        matches.append([0, "0x%x" % int(ea), name1, ea2, name2])

    return matches

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
      ea2 = str(row["ea2"])
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
      md1 = row["md1"]
      md2 = row["md2"]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      should_add = True
      if self.hooks is not None:
        if 'on_match' in dir(self.hooks):
          d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
          d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
          should_add, r = self.hooks.on_match(d1, d2, desc, 1.0)

      if not should_add or name1 in self.matched1 or name2 in self.matched2:
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
                     f.nodes bb1, df.nodes bb2,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     cast(f.md_index as real) md1, cast(df.md_index as real) md2
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
        pseudo1 = row["pseudo1"]
        pseudo2 = row["pseudo2"]
        asm1 = row["asm1"]
        asm2 = row["asm2"]
        ast1 = row["pseudo_primes1"]
        ast2 = row["pseudo_primes2"]
        md1 = row["md1"]
        md2 = row["md2"]
        desc = "Nodes, edges, complexity and mnemonics with small differences"

        should_add = True
        if self.hooks is not None:
          if 'on_match' in dir(self.hooks):
            d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
            d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
            should_add, ratio = self.hooks.on_match(d1, d2, desc, ratio)

        if not should_add or name1 in self.matched1 or name2 in self.matched2:
          continue

        item = CChooser.Item(ea, name1, ea2, name2, desc, ratio, bb1, bb2)
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
    sql = """select distinct f.address ea1, f.mangled_function mangled1,
                    d.address ea2, f.name name, d.name name2,
                    d.mangled_function mangled2,
                    f.pseudocode pseudo1, d.pseudocode pseudo2,
                    f.assembly asm1, d.assembly asm2,
                    f.pseudocode_primes primes1,
                    d.pseudocode_primes primes2,
                    f.nodes bb1, d.nodes bb2,
                    cast(f.md_index as real) md1, cast(d.md_index as real) md2
               from functions f,
                    diff.functions d
              where (d.mangled_function = f.mangled_function
                 or d.name = f.name)
                and f.name not like 'nullsub_%'"""
    
    desc = "Perfect match, same name"
    log_refresh("Finding with heuristic '%s'" % desc)
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
        bb1 = int(row["bb1"])
        bb2 = int(row["bb2"])

        pseudo1 = row["pseudo1"]
        pseudo2 = row["pseudo2"]
        asm1 = row["asm1"]
        asm2 = row["asm2"]
        md1 = row["md1"]
        md2 = row["md2"]

        ratio = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2)

        should_add = True
        if self.hooks is not None:
          if 'on_match' in dir(self.hooks):
            d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
            d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
            should_add, ratio = self.hooks.on_match(d1, d2, desc, ratio)

        if not should_add or name1 in self.matched1 or name2 in self.matched2:
          continue

        if float(ratio) == 1.0 or (self.relaxed_ratio and md1 != 0 and md1 == md2):
          self.best_chooser.add_item(CChooser.Item(ea, name1, ea2, name2, desc, 1, bb1, bb2))
        else:
          choose.add_item(CChooser.Item(ea, name1, ea2, name2, desc, ratio, bb1, bb2))

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
      for j in range(0, min(10, id1 - last)):
        for i in range(0, min(10, id1 - last)):
          cur.execute(sql, (id1+j, id2+i))
          rows = cur.fetchall()
          if len(rows) == 2:
            name1 = rows[0]["name"]
            name2 = rows[1]["name"]
            if name1 in self.matched1 or name2 in self.matched2:
              continue

            r = self.check_ratio(rows[0]["pseudocode_primes"], rows[1]["pseudocode_primes"], \
                                 rows[0]["pseudocode"], rows[1]["pseudocode"], \
                                 rows[0]["assembly"], rows[1]["assembly"], \
                                 float(rows[0]["md_index"]), float(rows[1]["md_index"]))
            if r < 0.5:
              if rows[0]["names"] != "[]" and rows[0]["names"] == rows[1]["names"]:
                r = 0.5001

            if r > thresold:
              ea = rows[0]["address"]
              ea2 = rows[1]["address"]
              bb1 = rows[0]["nodes"]
              bb2 = rows[1]["nodes"]
              ast1 = rows[0]["pseudocode_primes"]
              ast2 = rows[1]["pseudocode_primes"]
              pseudo1 = rows[0]["pseudocode"]
              pseudo2 = rows[1]["pseudocode"]
              asm1 = rows[0]["assembly"]
              asm2 = rows[1]["assembly"]
              md1 = rows[0]["md_index"]
              md2 = rows[1]["md_index"]

              # Pretty much every single heuristic fails with small functions,
              # ignore them...
              if bb1 <= 3 or bb2 <= 3:
                continue

              should_add = True
              if self.hooks is not None:
                if 'on_match' in dir(self.hooks):
                  d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
                  d2 = {"ea": ea, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
                  should_add, r = self.hooks.on_match(d1, d2, desc, r)

              if not should_add or name1 in self.matched1 or name2 in self.matched2:
                continue

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

  def find_from_matches(self, the_items, same_name = False):
    # XXX: FIXME: This is wrong in many ways, but still works... FIX IT!
    # Rule 1: if a function A in program P has id X, and function B in
    # the same program has id + 1, then, in program P2, function B maybe
    # the next function to A in P2.

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
        ratio = float(match[5])
        if not same_name:
          if ratio < 0.5:
            continue
        elif name1 != name2:
          continue

        id1 = self.get_function_id(name1)
        id2 = self.get_function_id(name2, False)
        sql = """insert into best_matches (id, id1, ea1, name1, id2, ea2, name2)
                                   values (?, ?, ?, ?, ?, ?, ?)"""
        cur.execute(sql, (i, id1, str(ea1), name1, id2, str(ea2), name2))
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

  def find_callgraph_matches(self):
    best_items = list(self.best_chooser.items)
    self.find_callgraph_matches_from(best_items, 0.60)

    partial_items = list(self.partial_chooser.items)
    self.find_callgraph_matches_from(partial_items, 0.80)

  def find_callgraph_matches_from(self, the_items, min_value):
    sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Callgraph match (%s)' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    cast(f.md_index as real) md1, cast(df.md_index as real) md2,
                    df.tarjan_topological_sort, df.strongly_connected_spp
               from functions f,
                    diff.functions df
              where  f.address in (%s)
                and df.address in (%s)
                and  f.name not like 'nullsub_%%'
                and df.name not like 'nullsub_%%'
                and abs(f.md_index - df.md_index) < 1
                and ((f.nodes > 5 and df.nodes > 5) 
                  or (f.instructions > 10 and df.instructions > 10))"""

    main_callers_sql = """select address from main.callgraph where func_id = ? and type = ?"""
    diff_callers_sql = """select address from diff.callgraph where func_id = ? and type = ?"""

    cur = self.db_cursor()
    dones = set()

    prev_best_matches = len(self.best_chooser.items)
    prev_part_matches = len(self.partial_chooser.items)

    total_dones = 0
    while len(the_items) > 0:
      total_dones += 1
      if total_dones % 1000 == 0:
        log("Processed %d callgraph matches..." % total_dones)

        curr_best_matches = len(self.best_chooser.items)
        curr_part_matches = len(self.partial_chooser.items)
        fmt = "Queued item(s) %d, Best matches %d, Partial Matches %d (Previously %d and %d)"
        log(fmt % (len(the_items), curr_best_matches, curr_part_matches, prev_best_matches, prev_part_matches))

      match = the_items.pop()
      ea1 = match[1]
      name1 = match[2]
      name2 = match[4]

      if ea1 in dones:
        continue
      dones.add(ea1)

      id1 = self.get_function_id(name1)
      id2 = self.get_function_id(name2, False)

      for call_type in ['caller', 'callee']:
        cur.execute(main_callers_sql, (id1, call_type))
        main_address_set = set()
        for row in cur.fetchall():
          main_address_set.add("'%s'" % row[0])

        cur.execute(diff_callers_sql, (id2, call_type))
        diff_address_set = set()
        for row in cur.fetchall():
          diff_address_set.add("'%s'" % row[0])

        if len(main_address_set) > 0 and len(diff_address_set) > 0:
          tname1 = name1.replace("'", "''")
          tname2 = name2.replace("'", "''")
          cur.execute(sql % (("%s of %s/%s" % (call_type, tname1, tname2)), ",".join(main_address_set), ",".join(diff_address_set)))
          matches = self.add_matches_from_cursor_ratio_max(cur, self.partial_chooser, None, min_value)
          if matches is not None and len(matches) > 0 and self.unreliable:
            the_items.extend(matches)

  def find_matches_parallel(self):
    self.run_heuristics_for_category("Partial")

    # Search using some of the previous criterias but calculating the
    # edit distance
    log_refresh("Finding with heuristic 'Small names difference'")
    self.search_small_differences(self.partial_chooser)

  def find_brute_force(self):
    cur = self.db_cursor()
    sql = "create temp table unmatched(id integer null primary key, address, main)"
    cur.execute(sql)

    # Find functions not matched in the primary database
    sql = "select name, address from functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      for row in rows:
        name = row["name"]
        if name not in self.matched1:
          ea = row[1]
          sql = "insert into unmatched(address,main) values(?,?)"
          cur.execute(sql, (ea, 1))

    # Find functions not matched in the secondary database
    sql = "select name, address from diff.functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      for row in rows:
        name = row["name"]
        if name not in self.matched2:
          ea = row[1]
          sql = "insert into unmatched(address,main) values(?,?)"
          cur.execute(sql, (ea, 0))
    cur.close()

    cur = self.db_cursor()
    sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Brute forcing' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    cast(f.md_index as real) md1, cast(df.md_index as real) md2,
                    df.tarjan_topological_sort, df.strongly_connected_spp
               from functions f,
                    diff.functions df,
                    unmatched um
              where ((f.address = um.address and um.main = 1)
                 or (df.address = um.address and um.main = 0))
                and ((f.md_index = df.md_index
                and f.md_index > 1 and df.md_index > 1)
                or (f.kgh_hash = df.kgh_hash
                and f.kgh_hash > 7 and df.kgh_hash > 7))"""
    cur.execute(sql)
    log_refresh("Finding via brute-forcing...")
    self.add_matches_from_cursor_ratio_max(cur, self.unreliable_chooser, None, 0.5)

  def find_experimental_matches(self):
    self.run_heuristics_for_category("Experimental")

    # Find using brute-force
    log_refresh("Brute-forcing...")
    self.find_brute_force()

  def find_unreliable_matches(self):
    self.run_heuristics_for_category("Unreliable")

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

    results_db = sqlite3.connect(filename, check_same_thread=True)
    results_db.text_factory = str

    cur = results_db.cursor()
    try:
      sql = "create table config (main_db text, diff_db text, version text, date text)"
      cur.execute(sql)

      sql = "insert into config values (?, ?, ?, ?)"
      cur.execute(sql, (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime()))

      sql = "create table results (type, line, address, name, address2, name2, ratio, bb1, bb2, description)"
      cur.execute(sql)

      sql = "create unique index uq_results on results(address, address2)"
      cur.execute(sql)

      sql = "create table unmatched (type, line, address, name)"
      cur.execute(sql)

      with results_db:
        results_sql   = "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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

  def try_attach(self, cur, db):
    try:
      cur.execute('attach "%s" as diff' % db)
    except:
      pass

  def diff(self, db):
    self.last_diff_db = db
    cur = self.db_cursor()
    self.try_attach(cur, db)

    try:
      cur.execute("select value from diff.version")
    except:
      log("Error: %s " % sys.exc_info()[1])
      log("The selected file does not look like a valid Diaphora exported database!")
      cur.close()
      return False

    row = cur.fetchone()
    if not row:
      log("Invalid database!")
      return False

    if row["value"] != VERSION_VALUE:
      log("WARNING: The database is from a different version (current %s, database %s)!" % (VERSION_VALUE, row[0]))

    try:
      t0 = time.monotonic()
      log_refresh("Diffing...", True)

      self.do_continue = True
      if self.equal_db():
        log("The databases seems to be 100% equal")

      if self.do_continue:
        # Compare the call graphs
        self.check_callgraph()

        if self.project_script is not None:
          log("Loading project specific Python script...")
          if not self.load_hooks():
            return False

        # Find the unmodified functions
        log_refresh("Finding best matches...")
        self.find_equal_matches_parallel()

        # Find the modified functions
        log_refresh("Finding partial matches")
        self.find_matches_parallel()

        # Call address sequence heuristic
        self.find_from_matches(self.best_chooser.items)
        self.find_from_matches(self.partial_chooser.items, same_name = True)

        if self.slow_heuristics:
          # Find the functions from the callgraph
          log_refresh("Finding with heuristic 'Callgraph matches'")
          self.find_callgraph_matches()

        if self.unreliable:
          # Find using likely unreliable methods modified functions
          log_refresh("Finding probably unreliable matches")
          self.find_unreliable_matches()

        if self.experimental:
          # Find using experimental methods modified functions
          log_refresh("Finding experimental matches")
          self.find_from_matches(self.partial_chooser.items)
          self.find_experimental_matches()

        # Show the list of unmatched functions in both databases
        log_refresh("Finding unmatched functions")
        self.find_unmatched()

        if self.hooks is not None:
          if 'on_finish' in dir(self.hooks):
            self.hooks.on_finish()

        log("Done. Took {} seconds.".format(time.monotonic() - t0))
    finally:
      cur.close()
    return True

if __name__ == "__main__":
  version_info = sys.version_info
  if version_info[0] == 2:
    log("WARNING: You are using Python 2 instead of Python 3. The main branch of Diaphora works exclusively with Python 3.")
    log("TIP: There are other branches that contain backward compatability.")

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
    exec(compile(open(script, "rb").read(), script, 'exec'))
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
    if not is_ida:
      bd.ignore_all_names = False
    bd.db = sqlite3.connect(db1, check_same_thread=True)
    bd.db.text_factory = str
    bd.db.row_factory = sqlite3.Row
    bd.diff(db2)
    bd.save_results(diff_out)
