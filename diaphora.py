#!/usr/bin/python3

"""
Diaphora, a binary diffing tool
Copyright (c) 2015-2023, Joxean Koret

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
import logging
import decimal
import sqlite3
import datetime
import importlib
import threading
import traceback

from io import StringIO
from threading import Thread, Lock
from multiprocessing import cpu_count
from difflib import SequenceMatcher, unified_diff

import diaphora_config as config
importlib.reload(config)

import diaphora_heuristics
importlib.reload(diaphora_heuristics)
from diaphora_heuristics import *

import database
importlib.reload(database)

from database import schema
importlib.reload(schema)

from pygments.lexers import NasmLexer, CppLexer, DiffLexer
from pygments.formatters import HtmlFormatter

from jkutils.kfuzzy import CKoretFuzzyHashing
from jkutils.factor import (FACTORS_CACHE, difference, difference_ratio,
                            primesbelow as primes)

try:
  import idaapi
  is_ida = True
except ImportError:
  is_ida = False

if hasattr(sys, "set_int_max_str_digits"):
  sys.set_int_max_str_digits(0)

#-------------------------------------------------------------------------------
VERSION_VALUE = "3.0.0"
COPYRIGHT_VALUE="Copyright(c) 2015-2023 Joxean Koret"
COMMENT_VALUE="Diaphora diffing plugin for IDA version %s" % VERSION_VALUE

# Used to clean-up the pseudo-code and assembly dumps in order to get
# better comparison ratios
CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_", "flt_", "jpt_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]

ITEM_MAIN_EA = 0
ITEM_MAIN_NAME = 1
ITEM_DIFF_EA = 2
ITEM_DIFF_NAME = 3
ITEM_DESCRIPTION = 4
ITEM_RATIO = 5
ITEM_MAIN_BBLOCKS = 6
ITEM_DIFF_BBLOCKS = 7

# Yes, yes, I know, parsing C/C++ with regular expressions is wrong and cannot
# be done, but we don't need to parse neither real nor complete C/C++, and we
# just want to extract potential function names from matching lines of assembly
# and pseudo-code that, also, can be partial or non C/C++ compliant but, for a
# reason, in a format supported by IDA.
CPP_NAMES_RE = "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)"


#-------------------------------------------------------------------------------
import logging
fmt ='[Diaphora: %(asctime)s] %(levelname)s: %(message)s'
logging.basicConfig(format=fmt, level=logging.INFO)

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
    log("quick_ratio: %s" % str(sys.exc_info()[1]))
    return 0

#-------------------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
  try:
    if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
      return 0
    s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
    return s.real_quick_ratio()
  except:
    log("real_quick_ratio: %s" % str(sys.exc_info()[1]))
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
    if is_ida or os.getenv("DIAPHORA_LOG_PRINT") is not None:
      print(("[Diaphora: %s] %s" % (time.asctime(), msg)))
    else:
      logging.info(msg)

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
    self.primary = True
    if title == "Unmatched in secondary":
      self.primary = False

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
      dec_vals = "%." + config.DECIMAL_VALUES
      self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname,
                        "%08x" % int(item.ea2), item.vfname2, dec_vals % item.ratio,
                        "%d" % item.bb1, "%d" % item.bb2, item.description])
    self.n += 1

  def get_color(self):
    if self.title.startswith("Best"):
      return config.HIGHLIGHT_FUNCTION_BEST
    elif self.title.startswith("Partial"):
      return config.HIGHLIGHT_FUNCTION_PARTIAL
    elif self.title.startswith("Unreliable"):
      return config.HIGHLIGHT_FUNCTION_UNRELIABLE

#-------------------------------------------------------------------------------
class bytes_encoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, bytes):
      return obj.decode("utf-8")
    return json.JSONEncoder.default(self, obj)

#-------------------------------------------------------------------------------
if "_DATABASES" in globals():
  if len(_DATABASES) > 0:
    for key in dict(_DATABASES):
      log("Closing previously opened database %s" % key)
      tmp_db = _DATABASES[key]
      tmp_db.close()
      del _DATABASES[key]
else:
  _DATABASES = {}

def sqlite3_connect(db_name):
  global _DATABASES
  db = sqlite3.connect(db_name, check_same_thread=False)
  db.text_factory = str
  db.row_factory = sqlite3.Row
  _DATABASES[db_name] = db
  return db

#-------------------------------------------------------------------------------
class CBinDiff:
  def __init__(self, db_name, chooser=CChooser):
    self.names = dict()
    self.primes = primes(2048*2048)
    self.db_name = db_name
    self.dbs_dict = {}
    self.db = None # Used exclusively by the exporter!
    self.open_db()

    self.all_matches = {"best":[], "partial":[], "unreliable":[]}
    self.matched_primary = {}
    self.matched_secondary = {}

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

    self.microcode = {}

    self.unreliable = self.get_value_for("unreliable", config.DIFFING_ENABLE_UNRELIABLE)
    self.relaxed_ratio = self.get_value_for("relaxed_ratio", config.DIFFING_ENABLE_RELAXED_RATIO)
    self.experimental = self.get_value_for("experimental", config.DIFFING_ENABLE_EXPERIMENTAL)
    self.slow_heuristics = self.get_value_for("slow_heuristics", config.DIFFING_ENABLE_SLOW_HEURISTICS)
    self.exclude_library_thunk = self.get_value_for("exclude_library_thunk", config.EXPORTING_EXCLUDE_LIBRARY_THUNK)
    self.use_decompiler = self.get_value_for("use_decompiler", config.EXPORTING_USE_DECOMPILER)
    self.project_script = self.get_value_for("project_script", None)
    self.hooks = None

    # Create the choosers
    self.chooser = chooser
    # Create the choosers
    self.create_choosers()

    self.last_diff_db = None
    self.re_cache = {}
    self._funcs_cache = {}
    self.items_lock = Lock()

    self.is_symbols_stripped = False
    self.is_patch_diff = False
    self.is_same_processor = False

    ####################################################################
    # LIMITS
    #
    # Do not run heuristics for more than SQL_TIMEOUT_LIMIT seconds.
    self.timeout = self.get_value_for("SQL_TIMEOUT_LIMIT", config.SQL_TIMEOUT_LIMIT)
    # It's typical in SQL queries to get a cartesian product of the results in
    # the functions tables. Do not process more than this number of rows.
    self.SQL_MAX_PROCESSED_ROWS = self.get_value_for("SQL_MAX_PROCESSED_ROWS", config.SQL_MAX_PROCESSED_ROWS)
    # Limits to filter the functions to export
    self.min_ea = 0
    self.max_ea = 0
    # Export only non IDA automatically generated function names? I.e.,
    # excluding these starting with sub_*
    self.ida_subs = config.EXPORTING_ONLY_NON_IDA_SUBS
    # Export only function summaries instead of also exporting both the
    # basic blocks and all instructions used by functions?
    self.function_summaries_only = config.EXPORTING_FUNCTION_SUMMARIES_ONLY
    # Ignore IDA's automatically generated sub_* names for heuristics
    # like the 'Same name'?
    self.ignore_sub_names = config.DIFFING_IGNORE_SUB_FUNCTION_NAMES
    # Ignore any and all function names for the 'Same name' heuristic?
    self.ignore_all_names = self.get_value_for("ignore_all_names", config.DIFFING_IGNORE_ALL_FUNCTION_NAMES)
    # Ignore small functions?
    self.ignore_small_functions = self.get_value_for("ignore_small_functions", config.DIFFING_IGNORE_SMALL_FUNCTIONS)

    # Export microcode instructions?
    self.export_microcode = self.get_value_for("export_microcode", config.EXPORTING_USE_MICROCODE)

    # Number of CPU threads/cores to use?
    cpus = cpu_count() - 1
    if cpus < 1:
      cpus = 1
    self.cpu_count = self.get_value_for("CPU_COUNT", cpus)

    # XXX: FIXME: Parallel diffing is broken outside of IDA due to parallelism problems
    if not is_ida:
      self.cpu_count = 1
    
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
        # Ignore any error at this point
        pass

      self.db_close()

  def get_value_for(self, value_name, default):
    """
    Try to search for a DIAPHORA_<value_name> environment variable.
    """
    value = os.getenv("DIAPHORA_%s" % value_name.upper())
    if value is not None:
      if type(value) != type(default):
        value = type(default)(value)
      return value
    return default

  def open_db(self):
    """
    Open the database @self.db_name.
    """
    db = sqlite3_connect(self.db_name)

    tid = threading.current_thread().ident
    self.dbs_dict[tid] = db
    if isinstance(threading.current_thread(), threading._MainThread):
      self.db = db
      self.create_schema()

  def get_db(self):
    """
    Return the current thread's assigned database object.
    """
    tid = threading.current_thread().ident
    if not tid in self.dbs_dict:
      self.open_db()
      if self.last_diff_db is not None:
        self.attach_database(self.last_diff_db)
    return self.dbs_dict[tid]

  def db_cursor(self):
    """
    Get a database cursors. This is the preferred method to use instead of doing
    db.cursor() every time one cursor is required somewhere.
    """
    db = self.get_db()
    return db.cursor()

  def db_close(self):
    """
    Close the main database.
    """
    tid = threading.current_thread().ident
    if tid in self.dbs_dict:
      self.dbs_dict[tid].close()
      del self.dbs_dict[tid]
    if isinstance(threading.current_thread(), threading._MainThread):
      self.db.close()

  def create_schema(self):
    """
    Create the database schema.
    """
    cur = self.db_cursor()
    try:
      cur.execute("PRAGMA foreign_keys = ON")

      for sql in schema.TABLES:
        cur.execute(sql)

      cur.execute("select 1 from version")
      row = cur.fetchone()
      if not row:
        cur.execute("insert into main.version values ('%s')" % VERSION_VALUE)
        cur.execute("commit")
    finally:
      cur.close()

  def create_indices(self):
    """
    Create the required indices for the exported database.
    """
    cur = self.db_cursor()
    template = "create index if not exists idx_{index} on {table}({fields})"
    try:
      for i, index in enumerate(schema.INDICES):
        table, fields = index
        sql = template.format(index=i, table=table, fields=fields)
        cur.execute(sql)

      sql = "analyze"
      cur.execute(sql)
    finally:
      cur.close()

  def attach_database(self, diff_db):
    """
    Attach @diff_db as the diffing database.
    """
    cur = self.db_cursor()
    try:
      cur.execute('attach "%s" as diff' % diff_db)
    finally:
      cur.close()

  def equal_db(self):
    """
    Check if both opened databases (main and diff) are equal.
    """
    cur = self.db_cursor()
    ret = None
    try:
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
    finally:
      cur.close()

    return ret

  def add_program_data(self, type_name, key, value):
    """
    Add a row of program data to the database.
    """
    cur = self.db_cursor()
    try:
      sql = "insert into main.program_data (name, type, value) values (?, ?, ?)"
      values = (key, type_name, value)
      cur.execute(sql, values)
    finally:
      cur.close()

  def get_instruction_id(self, addr):
    """
    Get the id of the given instruction with address @addr
    """
    cur = self.db_cursor()
    rowid = None
    try:
      sql = "select id from instructions where address = ?"
      cur.execute(sql, (str(addr),))
      row = cur.fetchone()
      rowid = None
      if row is not None:
        rowid = row["id"]
    finally:
      cur.close()
    return rowid

  def get_bb_id(self, addr):
    """
    Get the id of the given basic block at address @addr
    """
    cur = self.db_cursor()
    rowid = None
    try:
      sql = "select id from basic_blocks where address = ?"
      cur.execute(sql, (str(addr),))
      row = cur.fetchone()
      rowid = None
      if row is not None:
        rowid = row["id"]
    finally:
      cur.close()

    return rowid

  def get_valid_prop(self, prop):
    # This is a hack for 64 bit architectures kernels
    if type(prop) is int and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
      prop = str(prop)
    elif type(prop) is bytes:
      prop = prop.encode("utf-8")
    return prop

  def save_instructions_to_database(self, cur, bb_data, prop, func_id):
    """
    Save all the native assembly instructions in the basic block @bb_data to the
    database.
    """
    instructions_ids = {}
    sql = """insert into main.instructions (address, mnemonic, disasm,
                                            comment1, comment2, operand_names, name,
                                            type, pseudocomment, pseudoitp, func_id,
                                            asm_type)
                              values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'native')"""
    cur_execute = cur.execute
    for key in bb_data:
      for instruction in bb_data[key]:
        instruction_properties = []
        for instruction_property in instruction:
          prop = self.get_valid_prop(prop)
          if type(instruction_property) is list or type(instruction_property) is set:
            instruction_properties.append(json.dumps(list(instruction_property), ensure_ascii = False, cls = bytes_encoder))
          else:
            instruction_properties.append(instruction_property)
    
        addr, mnem, disasm, cmt1, cmt2, operand_names, name, mtype = instruction
        pseudocomment = None
        pseudoitp = None
        if addr in self.pseudo_comments:
          pseudocomment, pseudoitp = self.pseudo_comments[addr]
  
        instruction_properties.append(pseudocomment)
        instruction_properties.append(pseudoitp)
        instruction_properties.append(func_id)
        cur.execute(sql, instruction_properties)
        db_id = cur.lastrowid
        instructions_ids[addr] = db_id
    return cur_execute, instructions_ids

  def insert_basic_blocks_to_database(self, bb_data, cur_execute, cur, instructions_ids, bb_relations, func_id):
    """
    Insert basic blocks information as well as the relationship between assembly
    instructions and basic blocks.
    """
    num = 0
    bb_ids = {}
    sql1 = "insert into main.basic_blocks (num, address, asm_type) values (?, ?, 'native')"
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
      for instruction in bb_data[key]:
        ins_id = instructions_ids[instruction[0]]
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
    sql = "insert into main.function_bblocks (function_id, basic_block_id, asm_type) values (?, ?, 'native')"
    for key in bb_ids:
      bb_id = bb_ids[key]
      cur_execute(sql, (func_id, bb_id))

  def save_microcode_instructions(self, func_id, cur, cur_execute, microcode_bblocks, microcode_bbrelations):
    """
    Save all the microcode instructions in the basic block @bb_data to the database.
    """
    instructions_ids = {}
    sql_inst = """insert into main.instructions (address, mnemonic, disasm, comment1,
                                                 pseudocomment, func_id, asm_type)
                              values (?, ?, ?, ?, ?, ?, 'microcode')"""
    sql_bblock = "insert into main.basic_blocks (num, address, asm_type) values (?, ?, 'microcode')"
    sql_bbinst = "insert into main.bb_instructions (basic_block_id, instruction_id) values (?, ?)"
    sql_bbrelations = "insert into main.bb_relations (parent_id, child_id) values (?, ?)"
    sql_func_blocks = "insert into main.function_bblocks (function_id, basic_block_id, asm_type) values (?, ?, 'microcode')"
    num = 0
    for key in microcode_bblocks:
      # Create a new microcode basic block
      start_ea = self.get_valid_prop(microcode_bblocks[key]["start"])
      cur_execute(sql_bblock, [num, start_ea])
      bblock_id = cur.lastrowid
      microcode_bblocks[key]["bblock_id"] = bblock_id

      # Add the function -> basic block relation
      cur_execute(sql_func_blocks, (func_id, bblock_id))

      for line in microcode_bblocks[key]["lines"]:
        if line["mnemonic"] is not None:
          address = self.get_valid_prop(line["address"])
          mnemonic = line["mnemonic"]
          disasm = line["line"]
          comment1 = line["color_line"]
          pseudocomment = line["comments"]

          # Insert the microcode instruction
          args = [address, mnemonic, disasm, comment1, pseudocomment, func_id]
          cur_execute(sql_inst, args)

          inst_id = cur.lastrowid
          line["instruction_id"] = inst_id

          # Add the microcode instrution to the current basic block
          cur_execute(sql_bbinst, (bblock_id, inst_id))

      # Incrase the current basic block number
      num += 1

    # And, finally, insert the relationships between basic blocks
    for node in microcode_bbrelations:
      parent_id = microcode_bblocks[node]["bblock_id"]
      for children in microcode_bbrelations[node]:
        # Microcode generates empty basic blocks, we don't want to do anything
        # with them, just ignore...
        if children in microcode_bblocks:
          child_id = microcode_bblocks[children]["bblock_id"]
          cur_execute(sql_bbrelations, [parent_id, child_id])

  def save_function_to_database(self, props, cur, prop, func_id):
    """
    Save a single function to the database.
    """
    total_props = len(props)
    # The last 2 fields are basic_blocks_data & bb_relations for native assembly
    bb_data, bb_relations = props[total_props-2:]
    cur_execute, instructions_ids = self.save_instructions_to_database(cur, bb_data, prop, func_id)
    self.insert_basic_blocks_to_database(bb_data, cur_execute, cur, instructions_ids, bb_relations, func_id)

    microcode_bblocks, microcode_bbrelations = props[total_props-6:total_props-4]
    if len(microcode_bblocks) > 0 and len(microcode_bbrelations) > 0:
      self.save_microcode_instructions(func_id, cur, cur_execute, microcode_bblocks, microcode_bbrelations)

  def save_function(self, props):
    """
    Save the function with the given properties @props to the database.
    """
    if not props:
      log("WARNING: Trying to save a non resolved function?")
      return

    # Phase 1: Fix data types and insert the function row.
    cur = self.db_cursor()
    new_props = []
    try:
      # The last 6 fields are callers, callees, basic_blocks_data & bb_relations
      for prop in props[:len(props)-6]:
        prop = self.get_valid_prop(prop)

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
                                      source_file, userdata, microcode, clean_microcode,
                                      microcode_spp)
                                  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

      try:
        cur.execute(sql, new_props)
      except:
        logging.error("Error handling props in save_function(): %s" % str(new_props))
        traceback.print_exc()
        raise

      func_id = cur.lastrowid
      # Save a list of [ id, primes_value, pseudocode_primes ]
      self._funcs_cache[props[12]] = [ func_id, props[11], props[19] ]

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
        self.save_function_to_database(props, cur, prop, func_id)
    finally:
      cur.close()

  def get_valid_definition(self, defs):
    """ Try to get a valid structure definition by removing (yes) the 
        invalid characters typically found in IDA's generated structs."""
    ret = defs.replace("?", "_").replace("@", "_")
    ret = ret.replace("$", "_")
    return ret

  def prettify_asm(self, asm_source):
    """
    Get a prettified form of the given assembly source
    """
    asm = []
    for line in asm_source.split("\n"):
      if not line.startswith("loc_"):
        asm.append("\t" + line)
      else:
        asm.append(line)
    return "\n".join(asm)

  def re_sub(self, text, repl, string):
    """
    Internal re.sub wrapper to replace things in pseudocodes and assembly
    """
    if text not in self.re_cache:
      self.re_cache[text] = re.compile(text, flags=re.IGNORECASE)

    re_obj = self.re_cache[text]
    return re_obj.sub(repl, string)

  def get_cmp_asm_lines(self, asm):
    """
    Convert the input assembly @asm to an easier format to text diff using lists
    """
    sio = StringIO(asm)
    lines = []
    get_cmp_asm = self.get_cmp_asm
    for line in sio.readlines():
      line = line.strip("\n")
      lines.append(get_cmp_asm(line))
    return "\n".join(lines)

  def get_cmp_pseudo_lines(self, pseudo):
    """
    Convert the input pseudocode @pseudo to an easier format to text diff using lists
    """
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
    """
    Return a better string to diff assembly text for the given input @asm text
    """
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

    reps = [r"\+[a-f0-9A-F]+h\+"]
    for rep in reps:
      tmp = self.re_sub(rep, "+XXXX+", tmp)
    tmp = self.re_sub(r"\.\.[a-f0-9A-F]{8}", "XXX", tmp)
    
    # Strip any possible remaining white-space character at the end of
    # the cleaned-up instruction
    tmp = self.re_sub("[ \t\n]+$", "", tmp)

    # Replace aName_XXX with aXXX, useful to ignore small changes in 
    # offsets created to strings
    tmp = self.re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)

    # Replace the common microcode format for "mov #0xaddress.size, whatever"
    tmp = self.re_sub(r"\#0x[A-Z0-9]+", "0xXXX", tmp)

    return tmp

  def compare_graphs_pass(self, bblocks1, bblocks2, colours1, colours2, is_second = False):
    """
    Compare the given basic blocks and calculate each basic block's colour. It's
    used to, later on, create a nice looking graph view in IDA.
    """
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
            colours1[key1] = config.GRAPH_BBLOCK_MATCH_PERFECT
            colours2[key2] = config.GRAPH_BBLOCK_MATCH_PERFECT
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
            colours1[key1] = config.GRAPH_BBLOCK_MATCH_PARTIAL
            colours2[key2] = config.GRAPH_BBLOCK_MATCH_PARTIAL
            break
    return colours1, colours2

  def compare_graphs(self, g1, ea1, g2, ea2):
    """
    Compare two graphs (check `graph_diff` in diaphora_ida.py)
    """
    colours1 = {}
    colours2 = {}
    bblocks1 = g1[0]
    bblocks2 = g2[0]

    # Consider, by default, all blocks added, news
    for key1 in bblocks1:
      colours1[key1] = config.GRAPH_BBLOCK_MATCH_NONE
    for key2 in bblocks2:
      colours2[key2] = config.GRAPH_BBLOCK_MATCH_NONE

    colours1, colours2 = self.compare_graphs_pass(bblocks1, bblocks2, colours1, colours2, False)
    colours1, colours2 = self.compare_graphs_pass(bblocks1, bblocks2, colours1, colours2, True)
    return colours1, colours2

  def get_graph(self, ea1, primary=False, asm_type="native"):
    """
    Get the graph representation of the function at address @ea1
    """
    db = "diff"
    if primary:
      db = "main"

    cur = self.db_cursor()
    dones = set()
    bb_blocks = {}
    bb_relations = {}

    try:
      sql = """ select bb.address bb_address, ins.address ins_address,
                      ins.mnemonic ins_mnem, ins.disasm ins_disasm
                 from {db}.function_bblocks fb,
                      {db}.bb_instructions bbins,
                      {db}.instructions ins,
                      {db}.basic_blocks bb,
                      {db}.functions f
                where ins.id = bbins.instruction_id
                  and bbins.basic_block_id = bb.id
                  and bb.id = fb.basic_block_id
                  and f.id = fb.function_id
                  and fb.asm_type = bb.asm_type
                  and ins.asm_type = bb.asm_type
                  and f.address = ?
                  and bb.asm_type = ?
                  and ins.address is not null
                order by bb.address asc""".format(db=db)
      cur.execute(sql, (str(ea1), asm_type))
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
                          from {db}.basic_blocks
                         where id = bbr.parent_id) ea1,
                       (select address
                          from {db}.basic_blocks
                         where id = bbr.child_id) ea2
                  from {db}.bb_relations bbr,
                       {db}.function_bblocks fbs,
                       {db}.basic_blocks bbs,
                       {db}.functions f
                 where f.id = fbs.function_id
                   and bbs.id = fbs.basic_block_id
                   and fbs.basic_block_id = bbr.child_id
                   and f.address = ?
                   and fbs.asm_type = ?
                   and bbs.asm_type = fbs.asm_type
                 order by 1 asc, 2 asc""".format(db=db)
      cur.execute(sql, (str(ea1), asm_type))
      rows = result_iter(cur)

      for row in rows:
        bb_ea1 = str(row["ea1"])
        bb_ea2 = str(row["ea2"])
        try:
          bb_relations[bb_ea1].add(bb_ea2)
        except KeyError:
          bb_relations[bb_ea1] = set([bb_ea2])
    finally:
      cur.close()

    return bb_blocks, bb_relations

  def delete_function(self, ea):
    """
    Delete the function at address @ea from the database
    """
    cur = self.db_cursor()
    try:
      cur.execute("delete from functions where address = ?", (str(ea), ))
    finally:
      cur.close()

  def is_auto_generated(self, name):
    """
    Check if the function name looks like an IDA's auto-generated one
    """
    for rep in CMP_REPS:
      if name.startswith(rep):
        return True
    return False

  def get_callgraph_difference(self):
    """
    Get the percent of difference between the main and diff databases
    """
    cur = self.db_cursor()
    try:
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
          msg = "Call graph signature for both databases is equal, the programs seem to be 100% equal structurally"
          log(msg)
          Warning(msg)
          return 0
        else:
          FACTORS_CACHE[cg1] = cg_factors1
          FACTORS_CACHE[cg2] = cg_factors2
          diff = difference(cg1, cg2)
          total = sum(cg_factors1.values())
          if total == 0 or diff == 0:
            return 0
          else:
            percent = diff * 100. / total
            return percent
      else:
        raise Exception("Not enough rows in databases! Size is %d" % len(rows))
    finally:
      cur.close()

  def check_callgraph(self):
    """
    Compare the call graphs of both databases and print out how different they are
    """
    percent = self.get_callgraph_difference()
    if percent == 0:
      log("Call graphs are 100% equal")
    elif percent >= 100:
      log("Call graphs are absolutely different")
    else:
      log("Call graphs from both programs differ in %f%%" % percent)

  def add_match(self, name1, name2, ratio, item, chooser):
    """
    Add a single match to the internal lists before really adding them to the
    choosers list.

    NOTE: Always call `add_match`, don't try to handle this manually at all ever!
    """
    with self.items_lock:
      # If the function names are the same, it's a best match, regardless of the
      # ratio we got for the match, so fake the ratio as if it was 1.0.
      if name1 == name2:
        ratio = 1.0

      if self.has_better_match(name1, name2, ratio):
        return

      if name1 in self.matched_primary:
        if self.matched_primary[name1]["ratio"] < ratio:
          old_ratio = self.matched_primary[name1]["ratio"]
          debug_refresh("Found a better match for function %s -> %s, %f with %f" % (name1, name2, old_ratio, ratio))

      if chooser is not None:
        if item not in self.all_matches[chooser]:
          self.all_matches[chooser].append(item)

        self.matched_primary[name1]   = {"name":name2, "ratio":ratio}
        self.matched_secondary[name2] = {"name":name1, "ratio":ratio}

  def has_best_match(self, name1, name2):
    """
    Check if we have a best match for the given two functions (not for the pair).
    """
    if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] == 1.0:
      return True
    elif name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] == 1.0:
      return True
    return False

  def has_better_match(self, name1, name2, ratio):
    """
    Check if there if we found a better match already for either @name1 or @name2.
    """
    ratio = float(ratio)
    if name1 in self.matched_primary and self.matched_primary[name1]["ratio"] > ratio:
      return True
    elif name2 in self.matched_secondary and self.matched_secondary[name2]["ratio"] > ratio:
      return True

    # If we have a match by name, that's the best match    
    if not name1.startswith("sub_") and not name2.startswith("sub_"):
      if name1 in self.matched_primary and self.matched_primary[name1]["name"] == name1:
        return True
    return False

  def find_equal_matches(self):
    """
    Find 100% equal matches in both databases
    """
    cur = self.db_cursor()
    try:
      # Start by calculating the total number of functions in both databases
      sql = """select count(*) total from functions
              union all
              select count(*) total from diff.functions"""
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) != 2:
        Warning("Malformed database, only %d rows!" % len(rows))
        cur.close()
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

          item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]
          self.add_match(name, name, 1.0, item, "best")
    finally:
      cur.close()

    if not self.ignore_all_names:
      self.find_same_name("partial")

  def run_heuristics_for_category(self, arg_category, total_cpus = None):
    """
    Run a total of @total_cpus threads running SQL heuristics for category @arg_category
    """
    if total_cpus is None:
      total_cpus = self.cpu_count

    if total_cpus < 1:
      total_cpus = 1

    mode = "[Parallel]"
    if total_cpus == 1:
      mode = "[Single thread]"

    postfix = ""
    if self.ignore_small_functions:
      postfix = config.SQL_DEFAULT_POSTFIX

    if self.hooks is not None:
      if 'get_queries_postfix' in dir(self.hooks):
        postfix = self.hooks.get_queries_postfix(arg_category, postfix)

    threads_list = []
    heuristics = list(HEURISTICS)
    if self.hooks is not None:
      if 'get_heuristics' in dir(self.hooks):
        heuristics = self.hooks.get_heuristics(arg_category, heuristics)

    for heur in heuristics:
      if len(self.matched_primary) == self.total_functions1 or \
         len(self.matched_secondary) == self.total_functions2:
        log("All functions matched in at least one database, finishing.")
        break

      category = heur["category"]
      if category != arg_category:
        continue

      name  = heur["name"]
      sql   = heur["sql"]
      ratio = heur["ratio"]
      min_value = 0.0
      if ratio in [HEUR_TYPE_RATIO_MAX, HEUR_TYPE_RATIO_MAX_TRUSTED]:
        min_value = heur["min"]

      flags = heur["flags"]
      if HEUR_FLAG_UNRELIABLE in flags and not self.unreliable:
        log_refresh("Skipping unreliable heuristic '%s'" % name)
        continue

      if HEUR_FLAG_SLOW in flags and not self.slow_heuristics:
        log_refresh("Skipping slow heuristic '%s'" % name)
        continue

      if HEUR_FLAG_SAME_CPU in flags and not self.is_same_processor:
        log_refresh("Skipping processor specific heuristic '%s'" % name)
        continue

      if arg_category.lower() == "unreliable":
        best = "partial"
        partial = "unreliable"
      else:
        best = "best"
        partial = "partial"

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
        t = Thread(target=self.add_matches_from_query_ratio_max, args=(sql, best, partial, min_value))
      elif ratio == HEUR_TYPE_RATIO_MAX_TRUSTED:
        t = Thread(target=self.add_matches_from_query_ratio_max_trusted, args=(sql, min_value))
      else:
        traceback.print_exc()
        raise Exception("Invalid heuristic ratio calculation value!")

      t.name = name
      t.timeout = False
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

    # XXX: FIXME: THIS CODE IS TERRIBLE, REFACTOR IT!!!
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
          if time.monotonic() - t.time > config.SQL_TIMEOUT_LIMIT:
            do_cancel = True
            try:
              log_refresh("Timeout, cancelling queries...")
              t.timeout = True
              self.get_db().interrupt()
            except:
              log(("database.interrupt(): %s" % str(sys.exc_info()[1])))

        if times % 50 == 0:
          names = []
          for x in threads_list:
            names.append(x.name)
          log_refresh("[Parallel] %d thread(s) still running:\n%s" % (len(threads_list), ", ".join(names)))
          self.show_summary()

    self.cleanup_matches()
    self.show_summary()

  def cleanup_matches(self):
    """
    Check in all the matches for duplicates and bad matches and remove them.
    """
    dones = {}
    d = {}
    ea_ratios = {}
    for key in self.all_matches:
      d[key] = []
      l = sorted(self.all_matches[key], key=lambda x: float(x[5]), reverse=True)
      for item in l:
        # An example item:
        # item = [ea, name, ea, name, "100% equal", 1, nodes, nodes]
        ea = item[0]
        name1 = item[1]
        name2 = item[3]
        ratio = item[5]

        # Ignore duplicated matches (might happen due to parallelism)
        match = "%s-%s" % (name1, name2)
        if match in dones:
          continue

        if name1 == name2:
          debug_refresh("Using a fake 1.0 ratio for match %s - %s" % (name1, name2))
          ratio = 1.0

        dones[match] = ratio

        # If the previous ratio for a match with function @ea is worst, ignore
        # this match
        if ea in ea_ratios and ea_ratios[ea] > ratio:
          continue
        else:
          ea_ratios[ea] = ratio

        d[key].append(item)

    # Update know the dict of matched functions for both databases
    self.matched_primary = {}
    self.matched_secondary = {}
    for key in d:
      l = d[key]
      for item in l:
        name1 = item[1]
        name2 = item[3]
        ratio = item[5]
        self.matched_primary[name1] = {"name":name2, "ratio":ratio}
        self.matched_secondary[name2] = {"name":name1, "ratio":ratio}

    self.all_matches = d

  def count_different_matches(self, l):
    """
    Return the total number of different items using the first field.
    """
    dones = set()
    for item in l:
      dones.add(item[0])
    return len(dones)

  def get_total_matches_for(self, category):
    """
    Return the total number of matches found, so far, for the given category
    """
    return self.count_different_matches(self.all_matches[category])

  def show_summary(self):
    """
    Show a summary of how many functions Diaphora found so far and how big the
    main binary is
    """
    best = self.get_total_matches_for("best")
    partial = self.get_total_matches_for("partial")
    unreliable = self.get_total_matches_for("unreliable")
    total = best + partial + unreliable
    percent = (total * 100) / self.total_functions1
    log("Current results: Best %d, Partial %d, Unreliable %d" % (best, partial, unreliable))
    log("Matched %1.2f%% of main binary functions (%d out of %d)" % (percent, total, self.total_functions1))

  def ast_ratio(self, ast1, ast2):
    """
    Wrapper for comparing Abstract Syntax Trees
    """
    if not self.relaxed_ratio:
      return 0
    return ast_ratio(ast1, ast2)

  def check_ratio(self, ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2,\
                  clean_asm1, clean_asm2, clean_pseudo1, clean_pseudo2,
                  clean_micro1, clean_micro2):
    """
    Compare two functions and generate a similarity ratio from 0.0 to 1.0 where
    1.0 would be the best possible match and 0.0 would be the worst one.
    """
    md1 = float(md1)
    md2 = float(md2)

    fratio = quick_ratio
    decimal_values = "{0:.%s}" % config.DECIMAL_VALUES
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
      if clean_pseudo1 == "" or clean_pseudo2 == "":
        log("Error cleaning pseudo-code!")
      else:
        v1 = fratio(clean_pseudo1, clean_pseudo2)
        v1 = float(decimal_values.format(v1))
        if v1 == 1.0:
          # If real_quick_ratio returns 1 try again with quick_ratio
          # because it can result in false positives. If real_quick_ratio
          # says 'different', there is no point in continuing.
          if fratio == real_quick_ratio:
            v1 = quick_ratio(clean_pseudo1, clean_pseudo2)
            if v1 == 1.0:
              return 1.0

    v2 = fratio(clean_asm1, clean_asm2)
    v2 = float(decimal_values.format(v2))
    if v2 == 1:
      # Actually, same as the quick_ratio/real_quick_ratio check done
      # with the pseudo-code
      if fratio == real_quick_ratio:
        v2 = quick_ratio(clean_asm1, clean_asm2)
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
      if self.relaxed_ratio and md1 > config.MINIMUM_RARE_MD_INDEX:
        return 1.0
      v4 = min((v1 + v2 + v3 + 3.0) / 5, 1.0)

    v5 = 0.0
    if clean_micro1 is not None and clean_micro2 is not None:
      v5 = fratio(clean_micro1, clean_micro2)
      v5 = float(decimal_values.format(v5))
      if v5 == 1:
        return 1.0

    r = max(v1, v2, v3, v4, v5)
    if r == 1.0 and md1 != md2:
      # We cannot assign a 1.0 ratio if both MD indices are different, that's an
      # error
      r = 0
      for v in [v1, v2, v3, v4, v5]:
        if v != 1.0 and v > r:
          r = v

    return r

  def all_functions_matched(self):
    """
    Did we match already all the functions?
    """
    return len(self.matched_primary)   == self.total_functions1 or \
           len(self.matched_secondary) == self.total_functions2

  def check_match(self, row, ratio = None, debug=False):
    """
    Check a single SQL heuristic match and return whether it should be ignored
    or not, and also the similarity ratio for this match.
    """
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
    clean_asm1 = row["clean_asm1"]
    clean_asm2 = row["clean_asm2"]
    clean_pseudo1 = row["clean_pseudo1"]
    clean_pseudo2 = row["clean_pseudo2"]
    clean_micro1 = row["clean_micro1"]
    clean_micro2 = row["clean_micro2"]

    nullsub = "nullsub_"
    if name1.startswith(nullsub) or name2.startswith(nullsub):
      return False, 0.0

    # Do we already have a 1.0 match for any of these functions?
    if self.has_best_match(name1, name2):
      return False, 0.0

    if ratio is None:
      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2, \
                           clean_asm1, clean_asm2, clean_pseudo1, clean_pseudo2, \
                           clean_micro1, clean_micro2)
      if debug:
        logging.debug("0x%x 0x%x %d" % (int(ea), int(ea2), r))
    else:
      r = ratio

    # Do we have a previous match with a better comparison ratio than this?
    if self.has_better_match(name1, name2, r):
      return False, 0.0

    should_add = True
    if self.hooks is not None:
      if 'on_match' in dir(self.hooks):
        d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
        d2 = {"ea": ea2, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
        should_add, r = self.hooks.on_match(d1, d2, desc, r)

    return should_add, r

  def add_matches_internal(self, cur, best, partial, val=None, unreliable=None, debug=False):
    """
    Wrapper for various functions that find matches based on SQL queries. Always
    use this function when issuing SQL heuristics (if it's possible).
    """
    i = 0
    matches = []
    cur_thread = threading.current_thread()
    t = time.monotonic()
    while self.SQL_MAX_PROCESSED_ROWS == 0 or (self.SQL_MAX_PROCESSED_ROWS != 0 and i < self.SQL_MAX_PROCESSED_ROWS):
      if time.monotonic() - t > self.timeout or cur_thread.timeout:
        log("Timeout")
        break

      i += 1
      if i % 50000 == 0:
        log("Processed %d rows..." % i)
      row = cur.fetchone()
      if row is None:
        break

      # Check the row match
      should_add, r = self.check_match(row, debug=debug)
      if not should_add:
        continue

      ea = str(row["ea"])
      name1 = row["name1"]
      ea2 = row["ea2"]
      name2 = row["name2"]
      desc = row["description"]
      bb1 = int(row["bb1"])
      bb2 = int(row["bb2"])

      done = True
      chooser = None
      item = None

      if val is None:
        val = config.DEFAULT_PARTIAL_RATIO

      if r == 1.0:
        chooser = best
        item = [ea, name1, ea2, name2, desc, r, bb1, bb2]
      elif r >= val and partial is not None:
        chooser = partial
        item = [ea, name1, ea2, name2, desc, r, bb1, bb2]
      else:
        done = False

      if done:
        matches.append([0, "0x%x" % int(ea), name1, ea2, name2])
        self.add_match(name1, name2, r, item, chooser)
      else:
        chooser = None
        item = None
        if r < config.DEFAULT_PARTIAL_RATIO and r > val and unreliable is not None:
          chooser = "unreliable"
          item = [ea, name1, ea2, name2, desc, r, bb1, bb2]
          matches.append([0, "0x%x" % int(ea), name1, ea2, name2])
        
        if chooser is not None:
          self.add_match(name1, name2, r, item, chooser)

    return matches

  def add_matches_from_query_ratio(self, sql, best, partial, unreliable=None, debug=False):
    """
    Find matches using the query @sql and the usual rules.
    """
    if self.all_functions_matched():
      return
    
    cur = self.db_cursor()
    try:
      cur.execute(sql)
      self.add_matches_internal(cur, best=best, partial=partial, unreliable=unreliable, debug=debug)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      print("*"*80)
      print(sql)
      print("*"*80)
      traceback.print_exc()
      raise
    finally:
      cur.close()

  def add_matches_from_query_ratio_max(self, sql, best, partial, val):
    """
    Find matches using the query @sql with a ratio >= @val.
    """
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
      self.add_matches_internal(cur, best=best, partial=partial, val=val, unreliable="unreliable")
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      print("*"*80)
      print(sql)
      print("*"*80)
      traceback.print_exc()
      raise
    finally:
      cur.close()

  def add_matches_from_query_ratio_max_trusted(self, sql, val):
    """
    Find matches using the query @sql with a ratio >= @val and assign those with
    a bad ratio to the partial chooser, because they are reliable anyway.
    """
    if self.all_functions_matched():
      return

    cur = self.db_cursor()
    try:
      cur.execute(sql)
      self.add_matches_internal(cur, best="best", partial="partial", val=val, unreliable="partial")
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      raise
    finally:
      cur.close()

  def add_matches_from_cursor_ratio_max(self, cur, best, partial, val):
    """
    Find matches using the cursor @sql with a ratio >= @val and assign matches
    to the corresponding lists.
    """
    if self.all_functions_matched():
      return

    matches = self.add_matches_internal(cur, best=best, partial=partial, val=val)
    return matches

  def add_matches_from_query(self, sql, category):
    """
    Add all matches from this SQL query without performing any check.

    Warning: use this *only* if the ratio is known to be 1.00.
    """
    if self.all_functions_matched():
      return

    cur_thread = threading.current_thread()
    cur = self.db_cursor()
    try:
      cur.execute(sql)

      i = 0
      while not cur_thread.timeout:
        i += 1
        if i % 1000 == 0:
          log("Processed %d rows..." % i)
        row = cur.fetchone()
        if row is None:
          break

        # Check the row match
        should_add, r = self.check_match(row)
        if not should_add:
          continue

        ea = str(row["ea"])
        name1 = row["name1"]
        ea2 = row["ea2"]
        name2 = row["name2"]
        bb1 = int(row["bb1"])
        bb2 = int(row["bb2"])
        desc = row["description"]

        item = [ea, name1, ea2, name2, desc, 1, bb1, bb2]
        self.add_match(name1, name2, 1.0, item, category)
        if r < config.DEFAULT_PARTIAL_RATIO:
          debug_refresh("Warning: Best match 0x%s:%s -> 0x%sx:%s have a bad ratio: %f" % (ea, name1, ea2, name2, r))
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
    finally:
      cur.close()

  def search_small_differences(self, choose):
    """
    Find matches where most used names are the same.
    """
    cur = self.db_cursor()
    
    # Same basic blocks, edges, mnemonics, etc... but different names
    name = 'Nodes, edges, complexity and mnemonics with small differences'
    sql = """ select """ + get_query_fields(name) + """ ,
                     f.names  f_names,
                     df.names df_names
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.names != '[]' """
    
    try:
      cur.execute(sql)
      rows = result_iter(cur)
      for row in rows:
        ea = str(row["ea"])
        name1 = row["name1"]
        name2 = row["name2"]

        bb1 = int(row["bb1"])
        bb2 = int(row["bb2"])

        s1 = set(json.loads(row["f_names"]))
        s2 = set(json.loads(row["df_names"]))
        total = max(len(s1), len(s2))
        commons = len(s1.intersection(s2))
        ratio = (commons * 1.) / total
        if self.has_better_match(name1, name2, ratio):
          continue

        if ratio >= config.DEFAULT_PARTIAL_RATIO:
          # Check the row match
          should_add, ratio2 = self.check_match(row)
          if not should_add:
            continue

          ea = str(row["ea"])
          name1 = row["name1"]
          ea2 = row["ea2"]
          name2 = row["name2"]
          desc = row["description"]
          bb1 = int(row["bb1"])
          bb2 = int(row["bb2"])

          item = [ea, name1, ea2, name2, desc, ratio, bb1, bb2]
          if ratio == 1.0:
            the_chooser = "best"
          else:
            the_chooser = choose

          self.add_match(name1, name2, ratio, item, the_chooser)
    finally:
      cur.close()

  def find_same_name(self, choose):
    """
    Find matches by searching for the same name using both mangled and unmangled names.
    """
    cur = self.db_cursor()
    desc = "Perfect match, same name"
    sql = """select distinct """ + get_query_fields(desc) + """
               from functions f,
                    diff.functions df
              where (df.mangled_function = f.mangled_function
                 or df.name = f.name)
                and f.name not like 'nullsub_%'"""

    log_refresh("Finding with heuristic '%s'" % desc)
    try:
      cur.execute(sql)
      rows = cur.fetchall()

      if len(rows) > 0 and not self.all_functions_matched():
        for row in rows:
          name = row["mangled1"]
          name1 = row["name1"]
          name2 = row["name2"]
          if self.ignore_sub_names and name.startswith("sub_"):
            continue

          # Check the row match
          should_add, ratio = self.check_match(row)
          if not should_add:
            continue

          ea = str(row["ea"])
          name1 = row["name1"]
          ea2 = row["ea2"]
          name2 = row["name2"]
          desc = row["description"]
          bb1 = int(row["bb1"])
          bb2 = int(row["bb2"])
          md1 = row["md1"]
          md2 = row["md2"]
          if float(ratio) == 1.0 or (self.relaxed_ratio and md1 != 0 and md1 == md2):
            the_chooser = "best"
            item = [ea, name1, ea2, name2, desc, 1, bb1, bb2]
          else:
            the_chooser = choose
            if ratio + config.MATCHES_BONUS_RATIO < 1.0:
              ratio += config.MATCHES_BONUS_RATIO

            item = [ea, name1, ea2, name2, desc, ratio, bb1, bb2]

          self.add_match(name1, name2, ratio, item, the_chooser)
    finally:
      cur.close()

  def get_function_id(self, name, primary=True):
    """
    Get the function id for the function with name @name at either the main or
    diff function.
    """
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

  def get_function_id_by_address(self, ea, primary=True):
    """
    Get the function id for the function with address @ea at either the main or
    diff function.
    """
    cur = self.db_cursor()
    rid = None
    db_name = "main"
    if not primary:
      db_name = "diff"

    try:
      sql = "select id from %s.functions where address = ?" % db_name
      cur.execute(sql, (ea,))
      row = cur.fetchone()
      if row:
        rid = row["id"]
    finally:
      cur.close()
    
    return rid

  def find_callgraph_matches(self):
    best_items = list(self.all_matches["best"])
    self.find_callgraph_matches_from(best_items, 0.60)

    partial_items = list(self.all_matches["partial"])
    self.find_callgraph_matches_from(partial_items, 0.80)

  def run_thread(self, target, args, name):
    t = Thread(target=target, args=args)
    t.timeout = False
    t.name = name
    t.start()
    t.join()

  def find_partial_matches(self):
    """
    Find matches using all heuristics assigned to the 'partial' category.
    """
    self.run_heuristics_for_category("Partial")

    if self.slow_heuristics:
      # Search using some of the previous criterias but calculating the edit distance
      log_refresh("Finding with heuristic 'Small names difference'")
      self.search_small_differences("partial")

  def find_brute_force(self):
    """
    Brute force the unmatched functions. This is unreliable at best.
    """
    cur = self.db_cursor()
    sql = "create temporary table unmatched(id integer null primary key, address, main)"
    cur.execute(sql)

    # Find functions not matched in the primary database
    sql = "select name, address from functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      for row in rows:
        name = row["name"]
        if name not in self.matched_primary:
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
        if name not in self.matched_secondary:
          ea = row[1]
          sql = "insert into unmatched(address,main) values(?,?)"
          cur.execute(sql, (ea, 0))

    if self.slow_heuristics:
      heur = 'Brute forcing (MD-Index and KOKA hash)'
      sql = """select """ + get_query_fields(heur) + """
                from functions f,
                      diff.functions df,
                      unmatched um
                where ((f.address = um.address and um.main = 1)
                  or (df.address = um.address and um.main = 0))
                  and ((f.md_index = df.md_index
                  and f.md_index > 1 and df.md_index > 1)
                  or (f.kgh_hash = df.kgh_hash
                  and f.kgh_hash > 7 and df.kgh_hash > 7))
                  """
      cur.execute(sql)
      log_refresh("Finding via brute-forcing (MD-Index and KOKA hash)...")
      self.add_matches_from_cursor_ratio_max(cur, best="unreliable", partial=None, val=config.DEFAULT_PARTIAL_RATIO)

    heur = 'Brute forcing (Compilation Unit)'
    sql = """select """ + get_query_fields(heur) + """
               from functions f,
                    diff.functions df,
                    unmatched um
              where ((f.address = um.address and um.main = 1)
                 or (df.address = um.address and um.main = 0))
                and f.source_file = df.source_file
                and f.source_file != ''
                and df.source_file is not null
                and f.kgh_hash > 7 and df.kgh_hash > 7 """
    cur.execute(sql)
    log_refresh("Finding via brute-forcing (Compilation Unit)...")
    self.add_matches_from_cursor_ratio_max(cur, best="unreliable", partial=None, val=config.DEFAULT_PARTIAL_RATIO)

    if cur.connection.in_transaction:
      cur.execute("commit")
    cur.close()

  def find_experimental_matches(self):
    self.run_heuristics_for_category("Experimental")

  def find_unreliable_matches(self):
    self.run_heuristics_for_category("Unreliable")
    if self.slow_heuristics and self.unreliable:
      # Find using brute-force
      log_refresh("Brute-forcing...")
      self.find_brute_force()

  def find_unmatched(self):
    cur = self.db_cursor()
    try:
      sql = "select name, address from functions"
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) > 0:
        choose = self.chooser("Unmatched in primary", self, False)
        for row in rows:
          name = row["name"]

          if name not in self.matched_primary:
            ea = row[1]
            choose.add_item(CChooser.Item(ea, name))
        self.unmatched_second = choose

      sql = "select name, address from diff.functions"
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) > 0:
        choose = self.chooser("Unmatched in secondary", self, False)
        for row in rows:
          name = row["name"]

          if name not in self.matched_secondary:
            ea = row["address"]
            choose.add_item(CChooser.Item(ea, name))
        self.unmatched_primary = choose
    finally:
      cur.close()

  def create_choosers(self):
    """
    Create the IDA choosers that Diaphora will use to show the diffing results.
    """
    self.unreliable_chooser = self.chooser("Unreliable matches", self)
    self.partial_chooser = self.chooser("Partial matches", self)
    self.best_chooser = self.chooser("Best matches", self)
    self.multimatch_chooser = self.chooser("Problematic matches", self)

    self.unmatched_second = self.chooser("Unmatched in secondary", self, False)
    self.unmatched_primary = self.chooser("Unmatched in primary", self, False)

  def save_results(self, filename):
    """
    Save all the results (best, partial, unreliable, multimatches and unmatched)
    to the file @filename.
    """
    if os.path.exists(filename):
      os.remove(filename)
      log("Previous diff results '%s' removed." % filename)

    results_db = sqlite3_connect(filename)

    cur = results_db.cursor()
    try:
      sql = "create table config (main_db text, diff_db text, version text, date text)"
      cur.execute(sql)

      sql = "insert into config values (?, ?, ?, ?)"
      cur.execute(sql, (self.db_name, self.last_diff_db, VERSION_VALUE, time.asctime()))

      sql = """create table results (type, line, address, name, address2, name2,
                                     ratio, bb1, bb2, description)"""
      cur.execute(sql)

      sql = "create unique index uq_results on results(address, address2)"
      cur.execute(sql)

      sql = "create table unmatched (type, line, address, name)"
      cur.execute(sql)

      with results_db:
        results_sql   = "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        unmatched_sql = "insert into unmatched values (?, ?, ?, ?)"

        d = {"best"      : [self.best_chooser, results_sql],
             "partial"   : [self.partial_chooser, results_sql],
             "unreliable": [self.unreliable_chooser, results_sql],
             "multimatch": [self.multimatch_chooser, results_sql],
             "primary"   : [self.unmatched_primary, unmatched_sql],
             "secondary" : [self.unmatched_second, unmatched_sql]}

        for category in d:
          chooser, sql_cmd = d[category]
          for item in chooser.items:
            l = list(item)
            l.insert(0, category)
            cur.execute(sql_cmd, l)

      log("Diffing results saved in file '%s'." % filename)
    finally:
      cur.close()
      results_db.close()

  def try_attach(self, cur, db):
    """
    Try attaching the diff database and ignore errors...

    NOTE: Yes, this looks odd, it is yet another workaround for an old IDA bug.
    See this issue for more details:

    https://github.com/joxeankoret/diaphora/issues/151
    """
    try:
      cur.execute('attach "%s" as diff' % db)
    except:
      pass

  def get_function_row(self, name, db_name="main"):
    """
    Get the full table row for the given function with name @name in the database
    @db_name.
    """
    row = None
    cur = self.db_cursor()
    try:
      sql = "select * from {db}.functions where name = ?".format(db=db_name)
      cur.execute(sql, [name])
      row = cur.fetchone()
    except:
      log("ERROR at get_function_row: %s" % str(sys.exc_info()[1]))
    finally:
      cur.close()
    return row

  def compare_function_rows(self, main_row, diff_row):
    """
    Compare the functions of one SQL match.
    """
    name1 = main_row["name"]
    name2 = main_row["name"]
    pseudo1 = main_row["pseudocode"]
    pseudo2 = diff_row["pseudocode"]
    asm1 = main_row["assembly"]
    asm2 = diff_row["assembly"]
    ast1 = main_row["pseudocode_primes"]
    ast2 = diff_row["pseudocode_primes"]
    bb1 = int(main_row["nodes"])
    bb2 = int(diff_row["nodes"])
    md1 = main_row["md_index"]
    md2 = diff_row["md_index"]
    source1 = main_row["source_file"]
    source2 = diff_row["source_file"]
    clean_asm1 = main_row["clean_assembly"]
    clean_asm2 = diff_row["clean_assembly"]
    clean_pseudo1 = main_row["clean_pseudo"]
    clean_pseudo2 = diff_row["clean_pseudo"]
    clean_micro1 = main_row["clean_microcode"]
    clean_micro2 = diff_row["clean_microcode"]

    ratio = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2,\
                             clean_asm1, clean_asm2, clean_pseudo1, clean_pseudo2, \
                             clean_micro1, clean_micro2)
    return ratio

  def search_just_stripped_binaries(self):
    """
    Suppose we have a binary with symbols and the same binary with the symbols
    stripped. This 'dirty' heuristic tries to find if it's such a binary and
    then match functions with the same address.
    """
    ret = False
    total = self.total_functions1
    cur = self.db_cursor()

    try:
      sql = """select count(0)
                 from main.functions f,
                      diff.functions df
                where f.address = df.address """
      cur.execute(sql)
      row = cur.fetchone()
      matches = row[0]
    
      # If more than 99% of the best matches share the same exact address it is
      # clear it's the same binary with very little changes like, probably, just
      # symbols stripped.
      percent = (matches*100) / total
      if percent >= 99:
        self.is_symbols_stripped = True
        msg = "A total of %d matches out of %d, %f%% percent have the same address" % (matches, total, percent)
        log("Symbols stripped detected: %s" % msg)

        heur = "Same binary with symbols stripped"
        sql = """
        select distinct """ + get_query_fields(heur) + """
          from functions f,
               diff.functions df
         where f.address = df.address"""
        log_refresh("Finding via %s..." % repr(heur))

        self.add_matches_from_query(sql, "best")
        ret = True
    finally:
      cur.close()

    return ret

  def search_patchdiff_with_symbols(self):
    """
    Suppose we are diffing 2 different versions of the exact same binary with
    symbols and the number of functions with the same name is 99% or more. In
    such a case we can just match by name all the functions that are the same
    and then brute force the remaining functions that should be just a few.
    """
    ret = False
    total = self.total_functions1
    cur = self.db_cursor()

    try:
      sql = """select count(0)
                 from main.functions f,
                      diff.functions df
                where f.mangled_function = df.mangled_function """
      cur.execute(sql)
      row = cur.fetchone()
      matches = row[0]

      # If more than 90% of the best matches share the same exact mangled name
      # it is clear where patch diffing 2 different versions of the same binary.
      percent = (matches*100) / total
      if percent > 90:
        # We already have them matched, just instruct the heuristic engine to
        # finish by doing brute forcing with the remaining functions and that's
        # about it.
        self.is_patch_diff = True
        msg = "A total of %d matches out of %d, %f%% percent have the same name" % (matches, total, percent)
        log("Patch diffing detected: %s" % msg)
        ret = True
    finally:
      cur.close()

    return ret

  def apply_dirty_heuristics(self):
    """
    Apply what internally are called dirty heuristics (aka "speed ups").
    """
    if self.search_just_stripped_binaries():
      return True
    if self.search_patchdiff_with_symbols():
      return True
    return False

  def get_unmatched_functions(self):
    """
    Get the list of unmatched functions in both databases.
    """
    main = list()
    diff = list()
    cur = self.db_cursor()
    try:
      sql = """select 'main' db_name, name, address from main.functions
                union
               select 'diff' db_name, name, address from diff.functions
      """
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) > 0:
        for row in rows:
          name = row["name"]
          d = self.matched_primary
          l = main
          if row["db_name"] == "diff":
            d = self.matched_secondary
            l = diff

          if name not in d:
            ea = row["address"]
            key = [ea, name]
            if key not in main:
              l.append(key)
    finally:
      cur.close()
    return main, diff

  def search_remaining_functions(self, main_unmatched, diff_unmatched, config):
    """
    Search potentially renamed functions in a usual patch diffing session.
    """
    sql = """select """ + get_query_fields("?", quote=False) + """
               from main.functions f,
                    diff.functions df
              where f.address = ?
                and df.address = ?"""
    if not config["small"]:
      sql += " and f.nodes >= 3 and df.nodes >= 3 "

    cur = self.db_cursor()
    try:
      for ea1, name1 in main_unmatched:
        if config["only_sub"]:
          if not name1.startswith("sub_"):
            continue

        for ea2, name2 in diff_unmatched:
          cur.execute(sql, (config["heur"], ea1, ea2))
          self.add_matches_internal(cur, best="best", \
                                    partial="partial",\
                                    val=config["val"])
    finally:
      cur.close()

  def find_remaining_functions(self):
    """
    After using a dirty heuristic doing patch diffing try to find the remaining
    functions, if any.
    """
    main_unmatched, diff_unmatched = self.get_unmatched_functions()
    if self.is_patch_diff:
      heur = "Renamed function in patch diffing session"
      config = {"only_sub":True, "heur":heur, "small":False, "val":0.6}
      self.search_remaining_functions(main_unmatched, diff_unmatched, config)

  def itemize_for_chooser(self, item):
    """
    Get a CChoser.Item object from the given list @item.
    """
    ea1 = item[0]
    vfname1 = item[1]
    ea2 = item[2]
    vfname2 = item[3]
    ratio = item[4]
    bb1 = item[5]
    bb2 = item[6]
    desc = item[7]
    return CChooser.Item(ea1, vfname1, ea2, vfname2, ratio, bb1, bb2, desc)

  def add_multimatches_to_chooser(self, multi, ignore_list, dones):
    """
    Add the multimatches found in the list @multi and build the list of functions
    to be ignored (@ignore_list).
    """
    for ea in multi:
      if len(multi[ea]) > 1:
        for multi_match in multi[ea]:
          item = self.itemize_for_chooser(multi_match[2])
          key = "%s-%s" % (item.ea, item.ea2)
          if key not in dones:
            dones.add(key)
            self.multimatch_chooser.add_item(item)
            ignore_list.add(ea)
    return ignore_list, dones

  def find_unresolved_multimatches(self, max_main, multi_main, max_diff, multi_diff):
    # First pass, group them
    dones = set()
    for key in self.all_matches:
      l = sorted(self.all_matches[key], key=lambda x: float(x[5]), reverse=True)
      for match in l:
        ea1 = match[0]
        ea2 = match[2]
        ratio = match[5]
    
        key = "%s-%s" % (ea1, ea2)
        if key in dones:
          continue
        dones.add(key)

        if ea1 not in max_main:
          max_main[ea1] = ratio
    
        # If the previous ratio we got is less than this one, ignore
        if max_main[ea1] > ratio:
          continue
        max_main[ea1] = ratio
    
        item = [ea2, ratio, match]
        try:
          multi_main[ea1].append(item)
        except KeyError:
          multi_main[ea1] = [item]
    
        if ea2 not in max_diff:
          max_diff[ea2] = ratio        
        # If the previous ratio we got is less than this one, ignore
        if max_diff[ea2] > ratio:
          continue
        max_diff[ea2] = ratio
    
        item = [ea1, ratio, match]
        try:
          multi_diff[ea2].append(item)
        except KeyError:
          multi_diff[ea2] = [item]
    
    return max_main, multi_main, max_diff, multi_diff

  def find_multimatches(self):
    """
    Find all the multimatches that were not solved.
    """
    max_main = {}
    max_diff = {}
    multi_main = {}
    multi_diff = {}

    # First, find all the unresolved multimatches
    values = self.find_unresolved_multimatches(max_main, multi_main, max_diff, multi_diff)
    max_main, multi_main, max_diff, multi_diff = values

    # Now, add them to the corresponding chooser
    ignore_main = set()
    ignore_diff = set()
    dones = set()

    ignore_main, dones = self.add_multimatches_to_chooser(multi_main, ignore_main, dones)
    ignore_diff, dones = self.add_multimatches_to_chooser(multi_diff, ignore_diff, dones)

    return max_main, max_diff, ignore_main, ignore_diff

  def add_final_chooser_items(self, ignore_main, ignore_diff, max_main, max_diff):
    """
    Build the final matches list and add matches to the corresponding chooser.
    """
    CHOOSERS = {"best":self.best_chooser, "partial":self.partial_chooser,
                "unreliable":self.unreliable_chooser}
    for key in self.all_matches:
      l = self.all_matches[key]
      l = sorted(self.all_matches[key], key=lambda x: float(x[5]), reverse=True)
      for match in l:
        item = self.itemize_for_chooser(match)
        if item.ea in ignore_main or item.ea2 in ignore_diff:
          continue
        if item.ratio < max_main[item.ea]:
          continue
        if item.ratio < max_diff[item.ea2]:
          continue
        CHOOSERS[key].add_item(item)

  def final_pass(self):
    """
    Do the last pass:

    1. Remove duplicated or wrong matches.
    2. Find multimatches.
    3. Fill the choosers with the final cleaned up results.
    """
    self.cleanup_matches()

    max_main, max_diff, ignore_main, ignore_diff = self.find_multimatches()
    self.add_final_chooser_items(ignore_main, ignore_diff, max_main, max_diff)

  def same_processor_both_databases(self):
    """
    Check if the processor of both databases is the same.
    """
    ret = False
    cur = self.db_cursor()
    try:
      sql = """ select 1
                  from main.program mp,
                       diff.program dp
                 where mp.processor = dp.processor"""
      cur.execute(sql)
      row = cur.fetchone()
      if row is not None:
        ret = True
    finally:
      cur.close()
    return ret

  def functions_exists(self, name1, name2):
    l = []
    cur = self.db_cursor()
    try:
      sql = """select * from (
               select 'main' db_name, * from main.functions where name = ?
                union
               select 'diff' db_name, * from diff.functions where name = ?
               ) order by db_name desc
            """
      cur.execute(sql, (name1, name2))
      rows = cur.fetchall()
      ret = False
      if rows is not None:
        size = len(rows)
        ret = size == 2
        l = rows
    finally:
      cur.close()
    return ret, l

  def get_row_for_items(self, item):
    """
    Get the assembly source for the functions involved in a match
    """

    main_asm = self.get_function_row(item.vfname)
    diff_asm = self.get_function_row(item.vfname2, "diff")

    return main_asm, diff_asm

  def find_one_match_diffing(self, input_main_row, input_diff_row, field_name, item, heur, iteration, dones):
    """
    Diff the lines for the field @field_name and find matches of function names
    (only function names for now) to find new matches candidates.
    """
    main_lines = input_main_row[field_name].splitlines(keepends=False)
    diff_lines = input_diff_row[field_name].splitlines(keepends=False)
    df = unified_diff(main_lines, diff_lines, lineterm="")

    minus = []
    plus  = []

    for row in df:
      if len(row) == 0:
        continue

      c = row[0]
      if c == "-":
        minus.append(row)
      elif c == "+":
        plus.append(row)
      elif c == " ":
        if len(minus) > 0 and len(plus) > 0:
          matches1 = re.findall(CPP_NAMES_RE, "\n".join(minus), re.IGNORECASE)
          matches2 = re.findall(CPP_NAMES_RE, "\n".join(plus), re.IGNORECASE)
          minus = []
          plus = []

          size = min(len(matches1), len(matches2))
          for i in range(size):
            name1 = matches1[i][0]
            name2 = matches2[i][0]
            key = "%s-%s" % (name1, name2)
            if key in dones:
              continue
            dones.add(key)

            if name1.startswith("nullsub") or name2.startswith("nullsub"):
              # Ignore such functions
              continue

            size = len(dones)
            if size > 0 and size % 10000 == 0:
              log("%d callee matches processed so far..." % size)

            exists, l = self.functions_exists(name1, name2)
            if exists:
              main_row = l[0]
              diff_row = l[1]
              min_nodes = min(main_row["nodes"], diff_row["nodes"])
              max_nodes = max(main_row["nodes"], diff_row["nodes"])

              # If the number of basic blocks differ in more than 75% ignore...
              if ((min_nodes * 100) / max_nodes) < 25:
                continue
              
              # There is a high risk of false positives with small functions,
              # therefore, it's preferred to miss functions than having false
              # positives
              if main_row["nodes"] < 3 or diff_row["nodes"] < 3:
                continue

              r = self.compare_function_rows(main_row, diff_row)
              if r == 1.0:
                chooser = "best"
              elif r > config.DEFAULT_TRUSTED_PARTIAL_RATIO:
                chooser = "partial"
              else:
                continue

              if r + config.MATCHES_BONUS_RATIO < 1.0:
                r += config.MATCHES_BONUS_RATIO

              should_add = True
              if self.hooks is not None:
                if 'on_match' in dir(self.hooks):
                  desc = heur
                  ea = main_row["address"]
                  ea2 = diff_row["address"]
                  name1 = main_row["name"]
                  name2 = main_row["name"]
                  pseudo1 = main_row["pseudocode"]
                  pseudo2 = diff_row["pseudocode"]
                  asm1 = main_row["assembly"]
                  asm2 = diff_row["assembly"]
                  ast1 = main_row["pseudocode_primes"]
                  ast2 = diff_row["pseudocode_primes"]
                  bb1 = int(main_row["nodes"])
                  bb2 = int(diff_row["nodes"])
                  md1 = main_row["md_index"]
                  md2 = diff_row["md_index"]

                  d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
                  d2 = {"ea": ea2, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
                  should_add, r = self.hooks.on_match(d1, d2, desc, r)

              if should_add:
                heur_text = "%s (iteration #%d)" % (heur, iteration)
                ea1 = main_row["address"]
                ea2 = diff_row["address"]
                bb1 = int(main_row["nodes"])
                bb2 = int(diff_row["nodes"])
                new_item = [ea1, name1, ea2, name2, heur_text, r, bb1, bb2]
                self.add_match(name1, name2, r, new_item, chooser)

    return dones

  def find_matches_diffing_internal(self, heur, field_name):
    """
    Find funtions by diffing matches assembly or pseudo-codes.

    NOTE: Should this algorithm be parallelized?
    """
    log_refresh("Finding with heuristic '%s'" % heur)
    db = self.db_cursor()
    try:
      iteration = 1
      dones = set()
      # Should I let it run for some more iterations? There is a small chance of
      # hitting an infinite loop, so I'm hardcoding an upper limit.
      while iteration <= 3:
        old_total = len(self.all_matches["best"]) + len(self.all_matches["partial"])

        for key in ["best", "partial"]:
          l = sorted(self.all_matches[key], key=lambda x: float(x[5]), reverse=True)
          for match in l:
            match_key = "%s-%s" % (match[1], match[3])
            if match_key in dones:
              continue
            dones.add(match_key)

            item = self.itemize_for_chooser(match)
            main_row, diff_row = self.get_row_for_items(item)
            if main_row is not None and diff_row is not None:
              if main_row[field_name] is None:
                continue
              if diff_row[field_name] is None:
                continue

              dones = self.find_one_match_diffing(main_row, diff_row, field_name, item, heur, iteration, dones)

        self.cleanup_matches()
        self.show_summary()

        new_total = len(self.all_matches["best"]) + len(self.all_matches["partial"])
        if new_total == old_total:
          break

        log("New iteration with heuristic '%s'..." % heur)
        iteration += 1
    finally:
      db.close()

  def find_matches_diffing_assembly(self):
    heur = "Callee found diffing matches assembly"
    field_name = "assembly"
    self.find_matches_diffing_internal(heur, field_name)

  def find_matches_diffing_pseudo(self):
    heur = "Callee found diffing matches pseudo-code"
    field_name = "pseudocode"
    self.find_matches_diffing_internal(heur, field_name)

  def find_matches_diffing(self):
    # First, remove duplicates, etc... just to be sure
    self.cleanup_matches()

    # If the processor is the same for both databases, diff assembler to find
    # new matches
    if self.is_same_processor:
      self.find_matches_diffing_assembly()

    self.find_matches_diffing_pseudo()

  def find_functions_between(self, range1, range2):
    """
    Find the 'bester' matches in the functions gap specified by the given ranges
    """
    cur = self.db_cursor()
    sql = """select *
               from {db}.functions
              where address > ?
                and address < ?
              order by address desc"""
    try:
      heur_text = "Local affinity"

      # First, retrieve the main database functions in that area...
      cur.execute(sql.format(db="main"), range1)
      main_rows = list(cur.fetchall())
      size = len(main_rows)
      # If the number of functions in that gap is less than a hardcoded size, do
      # continue...
      if size > 0 and size <= config.MAX_FUNCTIONS_PER_GAP:
        # Then retrieve the diff database functions in that area...
        cur.execute(sql.format(db="diff"), range2)
        diff_rows = list(cur.fetchall())
        size = len(diff_rows)
        # Check again the same number of maximum hardcoded functions that we'll
        # consider for this heuristic...
        if size > 0 and size <= config.MAX_FUNCTIONS_PER_GAP:

          local_main_matched = set()
          main_score = {}
          local_diff_matched = set()
          diff_score = {}

          # And then, brute force all of these functions to find good matches
          # regardless of the position.
          for main_row in main_rows:
            for diff_row in diff_rows:
              name1 = main_row["name"]
              name2 = diff_row["name"]
              if name1.startswith("nullsub_") or name2.startswith("nullsub_"):
                continue
              if not name1.startswith("sub_") and not name2.startswith("sub_"):
                continue

              pseudocode_lines1 = main_row["pseudocode_lines"]
              pseudocode_lines2 = diff_row["pseudocode_lines"]
              if pseudocode_lines1 + pseudocode_lines2 != 0:
                if pseudocode_lines1 == 3 or pseudocode_lines2 == 3:
                  continue

              r = self.compare_function_rows(main_row, diff_row)
              if r == 1.0:
                chooser = "best"
              elif r >= config.DEFAULT_PARTIAL_RATIO:
                chooser = "partial"
              else:
                continue

              # If we have a previous match with the same score we discard this
              # second one, as this heuristics orders functions by address in
              # both functions and due to how compilers/linkers work, the first
              # matches are the best ones in this case.
              if name1 in local_main_matched and main_score[name1] >= r:
                continue
              if name2 in local_diff_matched and diff_score[name2] >= r:
                continue

              should_add = True
              if self.hooks is not None:
                if 'on_match' in dir(self.hooks):
                  desc = heur_text
                  ea = main_row["address"]
                  ea2 = diff_row["address"]
                  name1 = main_row["name"]
                  name2 = main_row["name"]
                  pseudo1 = main_row["pseudocode"]
                  pseudo2 = diff_row["pseudocode"]
                  asm1 = main_row["assembly"]
                  asm2 = diff_row["assembly"]
                  ast1 = main_row["pseudocode_primes"]
                  ast2 = diff_row["pseudocode_primes"]
                  bb1 = int(main_row["nodes"])
                  bb2 = int(diff_row["nodes"])
                  md1 = main_row["md_index"]
                  md2 = diff_row["md_index"]

                  d1 = {"ea": ea, "bb": bb1, "name": name1, "ast": ast1, "pseudo": pseudo1, "asm": asm1, "md": md1}
                  d2 = {"ea": ea2, "bb": bb2, "name": name2, "ast": ast2, "pseudo": pseudo2, "asm": asm2, "md": md2}
                  should_add, r = self.hooks.on_match(d1, d2, desc, r)

              if should_add:
                ea1 = main_row["address"]
                ea2 = diff_row["address"]
                name1 = main_row["name"]
                name2 = diff_row["name"]
                bb1 = int(main_row["nodes"])
                bb2 = int(diff_row["nodes"])
                new_item = [ea1, name1, ea2, name2, heur_text, r, bb1, bb2]
                self.add_match(name1, name2, r, new_item, chooser)

                local_main_matched.add(name1)
                main_score[name1] = r
                local_diff_matched.add(name2)
                diff_score[name2] = r
    finally:
      cur.close()

  def find_locally_affine_functions(self):
    """
    Try to find functions between the unmatched functions space inside two
    previously matched functions.

    So, let's suppose the following example:

      Bin1    Bin2    Matched?
      ---     ---     ---
      F1      F1'     Yes
      F2      F2'     No
      F3      F3'     No
      F4      F4'     Yes
    
    Considering how compilers & linkers (in general) work, chances are very high
    that functions F2 and F3 correspond to F2' and F3', so we try to find those
    functions that should correspond to the gap between unmatched functions and
    then brute force these subsets when they have a maximum hardcoded number of
    MAX_FUNCTIONS_PER_GAP. We don't consider bigger gaps. For now.
    """
    self.cleanup_matches()

    tmp_matches = list(self.all_matches["best"])
    tmp_matches.extend(list(self.all_matches["partial"]))
    tmp_matches = sorted(tmp_matches, key=lambda x: [int(x[0]), int(x[2])])

    size = len(tmp_matches)
    for i, match in enumerate(tmp_matches):
      if i == 0 or i == size:
        continue

      prev = tmp_matches[i-1]
      prev_ea1 = prev[0]
      prev_ea2 = prev[2]
      curr_ea1 = match[0]
      curr_ea2 = match[2]

      area1 = [prev_ea1, curr_ea1]
      area2 = [prev_ea2, curr_ea2]
      self.find_functions_between(area1, area2)

  def diff(self, db):
    """
    Diff the current two databases (main and diff).
    """
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
      cur_thread = threading.current_thread()
      cur_thread.timeout = False
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
        log_refresh("Finding equal matches...")
        self.find_equal_matches()

        skip_others = False
        self.is_same_processor = self.same_processor_both_databases()
        if self.experimental:
          # Dirty magic. Might or might not work...
          log_refresh("Checking 'dirty' heuristics...")
          skip_others = self.apply_dirty_heuristics()

        if skip_others:
          self.find_remaining_functions()
        else:
          log_refresh("Finding best matches...")
          self.run_heuristics_for_category("Best")

          # Find the modified functions
          log_refresh("Finding partial matches")
          self.find_partial_matches()

          if self.unreliable:
            # Find using likely unreliable methods modified functions
            log_refresh("Finding probably unreliable matches")
            self.find_unreliable_matches()

            #
            # Find using experimental methods modified functions.
            #
            # NOTES: While these are still called experimental, they aren't really
            # that experimental, as most of the code but the brute forcing using
            # compilation units has been tested since years ago.
            #
            log_refresh("Finding experimental matches")
            self.find_experimental_matches()

          # Find new matches by diffing assembly and pseudo-code of previously
          # found matches
          self.find_matches_diffing()

          # Find new matches in the functions between matches
          log_refresh("Finding locally affine functions")
          self.find_locally_affine_functions()

        self.final_pass()

        # Show the list of unmatched functions in both databases
        log_refresh("Finding unmatched functions")
        self.find_unmatched()

        if self.hooks is not None:
          if 'on_finish' in dir(self.hooks):
            self.hooks.on_finish()

        best = len(self.best_chooser.items)
        partial = len(self.partial_chooser.items)
        unreliable = len(self.unreliable_chooser.items)
        multi = len(self.multimatch_chooser.items)
        total = best + partial + unreliable
        percent = ((best + partial + unreliable) * 100) / self.total_functions1
        log("Final results: Best %d, Partial %d, Unreliable %d, Multimatches %d" % (best, partial, unreliable, multi))
        log("Matched %1.2f%% of main binary functions (%d out of %d)" % (percent, total, self.total_functions1))

        final_t = time.monotonic() - t0
        log("Done, time taken: {}.".format(datetime.timedelta(seconds=final_t)))

    finally:
      cur.close()
    return True

if __name__ == "__main__":
  version_info = sys.version_info
  if version_info[0] == 2:
    log("WARNING: You are using Python 2 instead of Python 3. The main branch of Diaphora works exclusively with Python 3.")
    log("TIP: There is a fork that contains backward compatibility, check the github's page.")

  do_diff = True
  debug_refresh("DIAPHORA_AUTO_DIFF=%s" % os.getenv("DIAPHORA_AUTO_DIFF"))
  debug_refresh("DIAPHORA_DB1=%s" % os.getenv("DIAPHORA_DB1"))
  debug_refresh("DIAPHORA_DB2=%s" % os.getenv("DIAPHORA_DB2"))
  debug_refresh("DIAPHORA_DIFF_OUT=%s" % os.getenv("DIAPHORA_DIFF_OUT"))
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
    buf = None
    with open(script, "rb") as f:
      buf = f.read()
    exec(compile(buf, script, 'exec'))
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
    
    bd.db = sqlite3_connect(db1)
    if os.getenv("DIAPHORA_PROFILE") is not None:
      log("*** Profiling export ***")
      import cProfile
      profiler = cProfile.Profile()
      profiler.runcall(bd.diff, db2)
      exported = True
      profiler.print_stats(sort="tottime")
    else:
      bd.diff(db2)
    bd.save_results(diff_out)
