#!/usr/bin/python

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015, Joxean Koret

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

KNOWN BUGS:

[ ] The choosers aren't updated when importing stuff.

TODO (for future versions):

[ ] Heuristics based on switchs (SPP with get_switch_info_ex(x).ncases?).
[ ] Instruction-level comment porting.
[ ] Import all names (global variables, etc...).

"""

import os
import sys
import time
import json
import decimal
import sqlite3
import traceback

from hashlib import md5
from difflib import SequenceMatcher, HtmlDiff

from pygments import highlight
from pygments.lexers import NasmLexer, CppLexer
from pygments.formatters import HtmlFormatter

from idc import *
from idaapi import *
from idautils import *

from PySide import QtGui

from others.tarjan_sort import strongly_connected_components, robust_topological_sort
from jkutils.kfuzzy import CKoretFuzzyHashing
from jkutils.factor import (FACTORS_CACHE, difference, difference_ratio,
                            primesbelow as primes)

#-----------------------------------------------------------------------
VERSION_VALUE = "1.0.2"
COPYRIGHT_VALUE="Copyright(c) 2015 Joxean Koret"
COMMENT_VALUE="Diaphora diffing plugin for IDA version %s" % VERSION_VALUE

# Constants unexported in IDA Python
PRTYPE_SEMI=0x0008

#-----------------------------------------------------------------------
def log(msg):
  Message("[%s] %s\n" % (time.asctime(), msg))

#-----------------------------------------------------------------------
def log_refresh(msg, show=False):
  if show:
    show_wait_box(msg)
  else:
    replace_wait_box(msg)
  log(msg)

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
class CHtmlViewer(PluginForm):
  def OnCreate(self, form):
    self.parent = self.FormToPySideWidget(form)
    self.PopulateForm()
    
    self.browser = None
    self.layout = None
    return 1
  
  def PopulateForm(self):
    self.layout = QtGui.QVBoxLayout()
    self.browser = QtGui.QTextBrowser()
    self.browser.setHtml(self.text)
    self.browser.setReadOnly(True)
    self.browser.setFontWeight(12)
    self.layout.addWidget(self.browser)
    self.parent.setLayout(self.layout)

  def Show(self, text, title):
    self.text = text
    return PluginForm.Show(self, title)

#-----------------------------------------------------------------------
class CChooser(Choose2):
  class Item:
    def __init__(self, ea, name, ea2 = None, name2 = None, desc="100% equal", ratio = 0):
      self.ea = ea
      self.vfname = name
      self.ea2 = ea2
      self.vfname2 = name2
      self.description = desc
      self.ratio = ratio
      self.cmd_import_selected = None
      self.cmd_import_all = None
      self.cmd_import_all_funcs = None

    def __str__(self):
      return '%08x' % self.ea

  def __init__(self, title, bindiff, show_commands=True):
    if title.startswith("Unmatched in"):
      Choose2.__init__(self, title, [ ["Line", 8], ["Address", 10], ["Name", 20] ], Choose2.CH_MULTI)
    else:
      Choose2.__init__(self, title, [ ["Line", 8], ["Address", 10], ["Name", 20], ["Address 2", 10], ["Name 2", 20], ["Ratio", 5], ["Description", 30] ], Choose2.CH_MULTI)

    if title == "Unmatched in primary":
      self.primary = False
    else:
      self.primary = True

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

  def OnClose(self):
    """space holder"""
    return True

  def OnEditLine(self, n):
    """space holder"""

  def OnInsertLine(self):
    pass

  def OnSelectLine(self, n):
    item = self.items[int(n)]
    if self.primary:
      try:
        jump_ea = int(item[1], 16)
        # Only jump for valid addresses
        if isEnabled(jump_ea):
          jumpto(jump_ea)
      except:
        print "OnSelectLine", sys.exc_info()[1]
    else:
      self.bindiff.show_asm(self.items[n], self.primary)

  def OnGetLine(self, n):
    try:
      return self.items[n]
    except:
      print "OnGetLine", sys.exc_info()[1]

  def OnGetSize(self):
    return len(self.items)

  def OnDeleteLine(self, n):
    try:
      del self.items[n]
      self.n -= 1
    except:
      pass
    return True

  def OnRefresh(self, n):
    return n

  def add_item(self, item):
    if self.title.startswith("Unmatched in"):
      self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname])
    else:
      self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname, "%08x" % int(item.ea2), item.vfname2, "%f" % item.ratio, item.description])
    self.n += 1

  def show(self, force=False):
    t = self.Show()
    if t < 0:
        return False
    
    if self.show_commands and (self.cmd_diff_asm is None or force):
      # create aditional actions handlers
      self.cmd_diff_asm = self.AddCommand("Diff assembly")
      self.cmd_diff_c = self.AddCommand("Diff pseudo-code")
      self.cmd_diff_graph = self.AddCommand("Diff assembly in a graph")
      self.cmd_import_selected = self.AddCommand("Import selected")
      self.cmd_import_all = self.AddCommand("Import *all* functions")
      self.cmd_import_all_funcs = self.AddCommand("Import *all* data for sub_* functions")
      self.cmd_highlight_functions = self.AddCommand("Highlight matches")
      self.cmd_unhighlight_functions = self.AddCommand("Unhighlight matches")
    elif not self.show_commands and (self.cmd_show_asm is None or force):
      self.cmd_show_asm = self.AddCommand("Show assembly")
      self.cmd_show_pseudo = self.AddCommand("Show pseudo-code")

    return True

  def get_color(self):
    if self.title.startswith("Best"):
      return 0xffff99
    elif self.title.startswith("Partial"):
      return 0x99ff99
    elif self.title.startswith("Unreliable"):
      return 0x9999ff

  def OnCommand(self, n, cmd_id):
    # Aditional right-click-menu commands handles
    if cmd_id == self.cmd_import_all:
      if askyn_c(1, "HIDECANCEL\nDo you really want to import all matched functions, comments, prototypes and definitions?") == 1:
        self.bindiff.import_all(self.items)
    elif cmd_id == self.cmd_import_all_funcs:
      if askyn_c(1, "HIDECANCEL\nDo you really want to import all IDA named matched functions, comments, prototypes and definitions?") == 1:
        self.bindiff.import_all_auto(self.items)
    elif cmd_id == self.cmd_import_selected:
      if len(self.selected_items) <= 1:
        self.bindiff.import_one(self.items[n])
      else:
        if askyn_c(1, "HIDECANCEL\nDo you really want to import all selected IDA named matched functions, comments, prototypes and definitions?") == 1:
          self.bindiff.import_selected(self.items, self.selected_items)
    elif cmd_id == self.cmd_diff_c:
      self.bindiff.show_pseudo_diff(self.items[n])
    elif cmd_id == self.cmd_diff_asm:
      self.bindiff.show_asm_diff(self.items[n])
    elif cmd_id == self.cmd_show_asm:
      self.bindiff.show_asm(self.items[n], self.primary)
    elif cmd_id == self.cmd_show_pseudo:
      self.bindiff.show_pseudo(self.items[n], self.primary)
    elif cmd_id == self.cmd_highlight_functions:
      if askyn_c(1, "HIDECANCEL\nDo you want to change the background color of each matched function?") == 1:
        color = self.get_color()
        for item in self.items:
          ea = int(item[1], 16)
          if not SetColor(ea, CIC_FUNC, color):
            print "Error setting color for %x" % ea
        Refresh()
    elif cmd_id == self.cmd_unhighlight_functions:
      for item in self.items:
        ea = int(item[1], 16)
        if not SetColor(ea, CIC_FUNC, 0xFFFFFF):
          print "Error setting color for %x" % ea
      Refresh()
    elif cmd_id == self.cmd_diff_graph:
      item = self.items[n]
      ea1 = int(item[1], 16)
      name1 = item[2]
      ea2 = int(item[3], 16)
      name2 = item[4]
      log("Diff graph for 0x%x - 0x%x" % (ea1, ea2))
      self.bindiff.graph_diff(ea1, name1, ea2, name2)
    return True

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list
  
  def OnGetLineAttr(self, n):
    if not self.title.startswith("Unmatched"):
      item = self.items[n]
      ratio = float(item[5])
      red = int(255 * (1 - ratio))
      green = int(128 * ratio)
      color = int("0x00%02x%02x" % (green, red), 16)
      return [color, 0]
    return [0xFFFFFF, 0]

#-----------------------------------------------------------------------
class CBinDiffExporterSetup(Form):
  def __init__(self):
    s = r"""Diaphora BinDiff
  Please select the path to the SQLite database to save the current IDA database and the path of the SQLite database to diff against.
  If no SQLite diff database is selected, it will just export the current IDA database to SQLite format. Leave the 2nd field empty if you are
  exporting the first database.

  SQLite databases:                                                                                                                    Export filter limits:  
  <#Select a file to export the current IDA database to SQLite format#Export IDA database to SQLite  :{iFileSave}> <#Minimum address to find functions to export#From address:{iMinEA}>
  <#Select the SQLite database to diff against                       #SQLite database to diff against:{iFileOpen}> <#Maximum address to find functions to export#To address  :{iMaxEA}>

  <Use the decompiler if available:{rUseDecompiler}>
  <#Enable if you want neither sub_* functions nor library functions to be exported#Export only non-IDA generated functions:{rNonIdaSubs}>
  <#Export only function summaries, not all instructions. Showing differences in a graph between functions will not be available.#Do not export instructions and basic blocks:{rFuncSummariesOnly}>
  <Use probably unreliable methods:{rUnreliable}>
  <Recommended to disable with databases with more than 5.000 functions#Use slow heuristics:{rSlowHeuristics}>
  <#Enable this option if you aren't interested in small changes#Relaxed calculations of differences ratios:{rRelaxRatio}>
  <Use experimental heuristics:{rExperimental}>
  <#Enable this option to ignore sub_* names for the 'Same name' heuristic.#Ignore automatically generated names:{rIgnoreSubNames}>
  <#Enable this option to ignore all function names for the 'Same name' heuristic.#Ignore all function names:{rIgnoreAllNames}>{cGroup1}>

  NOTE: Don't select IDA database files (.IDB, .I64) as only SQLite databases are considered.
"""
    def_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
    args = {'iFileSave': Form.FileInput(save=True, swidth=40, value=def_db),
            'iFileOpen': Form.FileInput(open=True, swidth=40),
            'iMinEA': Form.NumericInput(tp=Form.FT_ADDR, swidth=22),
            'iMaxEA': Form.NumericInput(tp=Form.FT_ADDR, swidth=22),
            'cGroup1'  : Form.ChkGroupControl(("rUseDecompiler",
                                               "rUnreliable",
                                               "rNonIdaSubs",
                                               "rSlowHeuristics",
                                               "rRelaxRatio",
                                               "rExperimental",
                                               "rFuncSummariesOnly",
                                               "rIgnoreSubNames",
                                               "rIgnoreAllNames"))}
    Form.__init__(self, s, args)

#-----------------------------------------------------------------------
try:
  class CAstVisitor(ctree_visitor_t):
    def __init__(self, cfunc):
      self.primes = primes(1024)
      ctree_visitor_t.__init__(self, CV_FAST)
      self.cfunc = cfunc
      self.primes_hash = 1
      return

    def visit_expr(self, expr):
      try:
        self.primes_hash *= self.primes[expr.op]
      except:
        traceback.print_exc()
      return 0

    def visit_insn(self, ins):
      try:
        self.primes_hash *= self.primes[ins.op]
      except:
        traceback.print_exc()
      return 0
except:
  # It seems it may cause "problems" with trial versions... may be it
  # causes problems too with versions without the decompiler???
  class CAstVisitor:
    pass

#-----------------------------------------------------------------------
class timeraction_t(object):
  def __init__(self, func, args, interval):
    self.func = func
    self.args = args
    self.interval = interval
    self.obj = idaapi.register_timer(self.interval, self)
    if self.obj is None:
      raise RuntimeError, "Failed to register timer"

  def __call__(self):
    if self.args is not None:
      self.func(self.args)
    else:
      self.func()
    return -1

#-----------------------------------------------------------------------
class uitimercallback_t(object):
  def __init__(self, g, interval):
    self.interval = interval
    self.obj = idaapi.register_timer(self.interval, self)
    if self.obj is None:
      raise RuntimeError, "Failed to register timer"
    self.g = g

  def __call__(self):
    if not "GetTForm" in dir(self.g):
      #log("Notice: IDA 6.6 doesn't support GetTForm, as so, it isn't possible to change the zoom.")
      return -1

    f = self.g.GetTForm()
    switchto_tform(f, 1)
    process_ui_action("GraphZoomFit", 0)
    return -1

#-----------------------------------------------------------------------
class CDiffGraphViewer(GraphViewer):
  def __init__(self, title, g, colours):
    try:
      GraphViewer.__init__(self, title, False)
      self.graph = g[0]
      self.relations = g[1]
      self.nodes = {}
      self.colours = colours
    except:
      Warning("CDiffGraphViewer: OnInit!!! " + str(sys.exc_info()[1]))

  def OnRefresh(self):
    try:
      self.Clear()
      self.nodes = {}

      for key in self.graph:
        self.nodes[key] = self.AddNode([key, self.graph[key]])
        
      for key in self.relations:
        if not key in self.nodes:
          self.nodes[key] = self.AddNode([key, [[0, 0, ""]]])
        parent_node = self.nodes[key]
        for child in self.relations[key]:
          if not child in self.nodes:
            self.nodes[child] = self.AddNode([child, [[0, 0, ""]]])
          child_node = self.nodes[child]
          self.AddEdge(parent_node, child_node)

      return True
    except:
      print "GraphViewer Error:", sys.exc_info()[1]
      return True

  def OnGetText(self, node_id):
    try:
      ea, rows = self[node_id]
      if ea in self.colours:
        colour = self.colours[ea]
      else:
        colour = 0xFFFFFF
      ret = []
      for row in rows:
        ret.append(row[2])
      label = "\n".join(ret)
      return (label, colour)
    except:
      print "GraphViewer.OnGetText:", sys.exc_info()[1]
      return ("ERROR", 0x000000)

  def Show(self):
    return GraphViewer.Show(self)

#-----------------------------------------------------------------------

g_bindiff = None
def show_choosers():
  global g_bindiff
  if g_bindiff is not None:
    g_bindiff.show_choosers(True)

#-----------------------------------------------------------------------
class CBinDiff:
  def __init__(self, db_name):
    self.names = dict(Names())
    self.primes = primes(1024*1024)
    self.db_name = db_name
    self.open_db()
    self.matched1 = set()
    self.matched2 = set()

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

    self.best_chooser = None
    self.partial_chooser = None
    self.unreliable_chooser = None
    self.unmatched_second = None
    self.unmatched_primary = None

    self.last_diff_db = None
    
    ####################################################################
    # LIMITS
    #
    # Do not run heuristics for more than 2 minutes
    self.timeout = 60 * 2
    # It's typical in SQL queries to get a cartesian product of the 
    # results in the functions tables. Do not process more than this
    # value.
    self.max_processed_rows = 1000000
    # Limits to filter the functions to export
    self.min_ea = MinEA()
    self.max_ea = MaxEA()
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
                        strongly_connected_spp text) """
    cur.execute(sql)

    sql = """ create table if not exists program (
                id integer primary key,
                callgraph_primes text,
                callgraph_all_primes text,
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
                comment2 text) """
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

    cur.close()

  def add_program_data(self, type_name, key, value):
    cur = self.db_cursor()
    sql = "insert into main.program_data (name, type, value) values (?, ?, ?)"
    values = (key, type_name, value)
    cur.execute(sql, values)
    cur.close()

  def read_function(self, f, discard=False):
    name = GetFunctionName(int(f))
    true_name = name
    demangled_name = Demangle(name, INF_SHORT_DN)
    if demangled_name is not None:
      name = demangled_name

    f = int(f)
    func = get_func(f)
    flow = FlowChart(func)
    size = func.endEA - func.startEA

    if not self.ida_subs:
      # Unnamed function, ignore it...
      if name.startswith("sub_") or name.startswith("j_") or name.startswith("unknown"):
        return False

      # Already recognized runtime's function?
      flags = GetFunctionFlags(f)
      if flags & FUNC_LIB or flags == -1:
        return False

    nodes = 0
    edges = 0
    instructions = 0
    mnems = []
    dones = {}
    names = set()
    
    bytes_hash = []
    outdegree = 0
    indegree = len(list(CodeRefsTo(f, 1)))
    assembly = {}
    basic_blocks_data = {}
    bb_relations = {}
    bb_topo_num = {}
    bb_topological = {}
    
    image_base = self.get_base_address()
    for block in flow:
      nodes += 1
      instructions_data = []

      block_ea = block.startEA - image_base
      idx = len(bb_topological)
      bb_topological[idx] = []
      bb_topo_num[block_ea] = idx

      for x in list(Heads(block.startEA, block.endEA)):
        mnem = GetMnem(x)
        disasm = GetDisasm(x)

        try:
          assembly[block_ea].append(disasm)
        except KeyError:
          if nodes == 1:
            assembly[block_ea] = [disasm]
          else:
            assembly[block_ea] = ["loc_%x:" % x, disasm]

        instructions += 1
        bytes_hash.append(chr(Byte(x)))
        outdegree += len(list(CodeRefsFrom(x, 0)))
        mnems.append(mnem)
        op_value = GetOperandValue(x, 1)
        if op_value == BADADDR:
          op_value = GetOperandValue(x, 0)

        if op_value != BADADDR and op_value in self.names:
          tmp_name = self.names[op_value]
          demangled_name = Demangle(name, INF_SHORT_DN)
          if demangled_name is not None:
            tmp_name = demangled_name
          if not tmp_name.startswith("sub_"):
            names.add(tmp_name)

        ins_cmt1 = GetCommentEx(x, 0)
        ins_cmt2 = GetCommentEx(x, 1)
        instructions_data.append([x - image_base, mnem, disasm, ins_cmt1, ins_cmt2])

      basic_blocks_data[block_ea] = instructions_data
      bb_relations[block_ea] = []
      for succ_block in block.succs():
        succ_base = succ_block.startEA - image_base
        bb_relations[block_ea].append(succ_base)
        edges += 1
        indegree += 1
        if not dones.has_key(succ_block.id):
          dones[succ_block] = 1

      for pred_block in block.preds():
        try:
          bb_relations[pred_block.startEA - image_base].append(block.startEA - image_base)
        except KeyError:
          bb_relations[pred_block.startEA - image_base] = [block.startEA - image_base]

        edges += 1
        outdegree += 1
        if not dones.has_key(succ_block.id):
          dones[succ_block] = 1

    for block in flow:
      block_ea = block.startEA - image_base
      for succ_block in block.succs():
        succ_base = succ_block.startEA - image_base
        bb_topological[bb_topo_num[block_ea]].append(bb_topo_num[succ_base])

    strongly_connected_spp = 0

    try:
      strongly_connected = strongly_connected_components(bb_relations)
      bb_topological = robust_topological_sort(bb_topological)
      bb_topological = json.dumps(bb_topological)
      strongly_connected_spp = 1
      for item in strongly_connected:
        val = len(item)
        if val > 1:
          strongly_connected_spp *= self.primes[val]
    except:
      # XXX: FIXME: The original implementation that we're using is 
      # recursive and can fail. We really need to create our own non
      # recursive version.
      strongly_connected = []
      bb_topological = None

    loops = 0
    for sc in strongly_connected:
      if len(sc) > 1:
        loops += 1
      else:
        if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
          loops += 1

    keys = assembly.keys()
    keys.sort()
    asm = []
    for key in keys:
      asm.extend(assembly[key])
    asm = "\n".join(asm)

    cc = edges - nodes + 2
    proto = self.guess_type(f)
    proto2 = GetType(f)
    prime = str(self.primes[cc])
    comment = GetFunctionCmt(f, 1)
    bytes_hash = md5("".join(bytes_hash)).hexdigest()
    function_flags = GetFunctionFlags(f)
    pseudo = None
    pseudo_hash1 = None
    pseudo_hash2 = None
    pseudo_hash3 = None
    pseudo_lines = 0
    pseudocode_primes = None
    if f in self.pseudo:
      pseudo = "\n".join(self.pseudo[f])
      pseudo_lines = len(self.pseudo[f])
      pseudo_hash1, pseudo_hash2, pseudo_hash3 = self.kfh.hash_bytes(pseudo).split(";")
      if pseudo_hash1 == "":
        pseudo_hash1 = None
      if pseudo_hash2 == "":
        pseudo_hash2 = None
      if pseudo_hash3 == "":
        pseudo_hash3 = None
      pseudocode_primes = str(self.pseudo_hash[f])

    # Not yet used; in the near future we will use RVA instead of full
    # addresses
    rva = f - self.get_base_address()
    return (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
             proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
             pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
             pseudo_hash2, pseudo_hash3, len(strongly_connected), loops, rva, bb_topological,
             strongly_connected_spp, 
             basic_blocks_data, bb_relations)

  def get_base_address(self):
    return idaapi.get_imagebase()

  def get_instruction_id(self, addr):
    cur = self.db_cursor()
    sql = "select id from instructions where address = ?"
    cur.execute(sql, (str(addr),))
    row = cur.fetchone()
    rowid = None
    if row is not None:
      rowid = row[0]
    cur.close()
    return rowid

  def get_bb_id(self, addr):
    cur = self.db_cursor()
    sql = "select id from basic_blocks where address = ?"
    cur.execute(sql, (str(addr),))
    row = cur.fetchone()
    rowid = None
    if row is not None:
      rowid = row[0]
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
                                    tarjan_topological_sort, strongly_connected_spp)
                                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    cur.execute(sql, new_props)
    func_id = cur.lastrowid

    if not self.function_summaries_only:
      bb_data, bb_relations = props[len(props)-2:]
      instructions_ids = {}
      sql = """insert into main.instructions (address, mnemonic, disasm, comment1, comment2)
                                 values (?, ?, ?, ?, ?)"""
      self_get_instruction_id = self.get_instruction_id
      cur_execute = cur.execute
      for key in bb_data:
        for insn in bb_data[key]:
          addr, mnem, disasm, cmt1, cmt2 = insn
          db_id = self_get_instruction_id(str(addr))
          if db_id is None:
            cur_execute(sql, (str(addr), mnem, disasm, cmt1, cmt2))
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

  def save_callgraph(self, primes, all_primes, md5sum):
    cur = self.db_cursor()
    sql = "insert into main.program (callgraph_primes, callgraph_all_primes, md5sum) values (?, ?, ?)"
    cur.execute(sql, (primes, all_primes, md5sum))
    cur.close()

  def export_structures(self):
    # It seems that GetMaxLocalType, sometimes, can return negative
    # numbers, according to one beta-tester. My guess is that it's a bug
    # in IDA. However, as we cannot reproduce, at least handle this
    # condition.
    local_types = GetMaxLocalType()
    if (local_types & 0x80000000) != 0:
      log("Warning: GetMaxLocalType returned a negative number (0x%x)!" % local_types)
      return

    for i in range(local_types):
      try:
        name = GetLocalTypeName(i+1)
        definition = GetLocalType(i+1, PRTYPE_MULTI|PRTYPE_TYPE|PRTYPE_SEMI|PRTYPE_PRAGMA)
        type_name = "struct"
        if definition.startswith("enum"):
          type_name = "enum"
        self.add_program_data(type_name, name, definition)
      except:
        pass

  def get_til_names(self):
    idb_path = GetIdbPath()
    filename, ext = os.path.splitext(idb_path)
    til_path = "%s.til" % filename

    with open(til_path, "rb") as f:
      line = f.readline()
      pos = line.find("Local type definitions")
      if pos > -1:
        tmp = line[pos+len("Local type definitions")+1:]
        pos = tmp.find("\x00")
        if pos > -1:
          defs = tmp[:pos].split(",")
          return defs
    return None

  def export_til(self):
    til_names = self.get_til_names()
    if til_names is not None:
      for til in til_names:
        self.add_program_data("til", til, None)

  def do_export(self):
    i = 0
    callgraph_primes = 1
    callgraph_all_primes = {}
    func_list = list(Functions(self.min_ea, self.max_ea))
    total_funcs = len(func_list)
    t = time.time()
    for func in func_list:
      i += 1
      if i % 100 == 0 or i == 1:
        line = "Exported %d function(s) out of %d total.\nElapsed %d second(s), remaining ~%d second(s)"
        elapsed = time.time() - t
        remaining = (elapsed / i) * (total_funcs - i)
        replace_wait_box(line % (i, total_funcs, int(elapsed), int(remaining)))
      props = self.read_function(func)
      if props == False:
        continue

      ret = props[11]
      callgraph_primes *= decimal.Decimal(ret)
      try:
        callgraph_all_primes[ret] += 1
      except KeyError:
        callgraph_all_primes[ret] = 1
      self.save_function(props)
    
    md5sum = GetInputFileMD5()
    self.save_callgraph(str(callgraph_primes), json.dumps(callgraph_all_primes), md5sum)
    self.export_structures()
    self.export_til()

  def export(self):
    try:
      show_wait_box("Exporting database")
      self.do_export()
    finally:
      hide_wait_box()

    self.db.commit()

    cur = self.db_cursor()
    cur.execute("analyze")
    cur.close()

    self.db_close()

  def import_til(self):
    log("Importing type libraries...")
    cur = self.db_cursor()
    sql = "select name from diff.program_data where type = 'til'"
    cur.execute(sql)
    for row in cur.fetchall():
      LoadTil(row[0])
    cur.close()
    Wait()

  def get_valid_definition(self, defs):
    """ Try to get a valid structure definition by removing (yes) the 
        invalid characters typically found in IDA's generated structs."""
    ret = defs.replace("?", "_").replace("@", "_")
    ret = ret.replace("$", "_")
    return ret

  def import_definitions(self):
    cur = self.db_cursor()
    sql = "select type, name, value from diff.program_data where type in ('structure', 'struct', 'enum')"
    cur.execute(sql)
    rows = cur.fetchall()

    new_rows = set()
    for row in rows:
      if GetStrucIdByName(row[1]) == BADADDR:
        type_name = "struct"
        if row[0] == "enum":
          type_name = "enum"
        new_rows.add(row)
        ret = ParseTypes("%s %s;" % (type_name, row[1]))
        if ret != 0:
          pass

    for i in xrange(10):
      for row in new_rows:
        if GetStrucIdByName(row[1]) == BADADDR:
          definition = self.get_valid_definition(row[2])
          ret = ParseTypes(definition)
          if ret != 0:
            pass

    cur.close()
    Wait()

  def import_one(self, item):
    ret = askyn_c(1, "AUTOHIDE DATABASE\nDo you want to import all the type libraries, structs and enumerations?")

    if ret == 1:
      # Import all the type libraries from the diff database
      self.import_til()
      # Import all the struct and enum definitions
      self.import_definitions()
    elif ret == -1:
      return

    # Import just the selected item
    ea1 = str(int(item[1], 16))
    ea2 = str(int(item[3], 16))
    self.do_import_one(ea1, ea2, True)

    new_func = self.read_function(str(ea1))
    self.delete_function(ea1)
    self.save_function(new_func)

    self.db.commit()

  def prettify_asm(self, asm_source):
    asm = []
    for line in asm_source.split("\n"):
      if not line.startswith("loc_"):
        asm.append("\t" + line)
      else:
        asm.append(line)
    return "\n".join(asm)

  def show_asm_diff(self, item):
    cur = self.db_cursor()
    sql = """select *
               from (
             select prototype, assembly, name, 1
               from functions
              where address = ?
                and assembly is not null
       union select prototype, assembly, name, 2
               from diff.functions
              where address = ?
                and assembly is not null)
              order by 4 asc"""
    ea1 = str(int(item[1], 16))
    ea2 = str(int(item[3], 16))
    cur.execute(sql, (ea1, ea2))
    rows = cur.fetchall()
    if len(rows) != 2:
      Warning("Sorry, there is no assembly available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      html_diff = HtmlDiff()
      asm1 = self.prettify_asm(row1[1])
      asm2 = self.prettify_asm(row2[1])
      buf1 = "%s proc near\n%s\n%s endp" % (row1[2], asm1, row1[2])
      buf2 = "%s proc near\n%s\n%s endp" % (row2[2], asm2, row2[2])
      src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))
      
      title = "Diff assembler %s - %s" % (row1[2], row2[2])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

    cur.close()

  def show_asm(self, item, primary):
    cur = self.db_cursor()
    if primary:
      db = "main"
    else:
      db = "diff"
    ea = str(int(item[1], 16))
    sql = "select prototype, assembly, name from %s.functions where address = ?"
    sql = sql % db
    cur.execute(sql, (ea, ))
    row = cur.fetchone()
    if row is None:
      Warning("Sorry, there is no assembly available for the selected function.")
    else:
      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = True
      asm = self.prettify_asm(row[1])
      final_asm = "; %s\n%s proc near\n%s\n%s endp\n"
      final_asm = final_asm % (row[0], row[2], asm, row[2])
      src = highlight(final_asm, NasmLexer(), fmt)
      title = "Assembly for %s" % row[2]
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)
    cur.close()

  def get_cmp_asm(self, asm):
    if asm is None:
      return asm

    tmp = asm.split(";")[0]
    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    reps = ["loc_", "sub_", "qword_", "dword_", "byte_", "word_", "off_", "unk_"]
    for rep in reps:
      tmp = re.sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)
    reps = ["\+[a-f0-9A-F]+h\+"]
    for rep in reps:
      tmp = re.sub(rep, "+XXXX+", tmp)
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

  def graph_diff(self, ea1, name1, ea2, name2):
    g1 = self.get_graph(str(ea1), True)
    g2 = self.get_graph(str(ea2))

    if g1 == ({}, {}) or g2 == ({}, {}):
      Warning("Sorry, graph information is not available for one of the databases.")
      return False

    colours = self.compare_graphs(g1, ea1, g2, ea2)

    title1 = "Graph for %s (primary)" % name1
    title2 = "Graph for %s (secondary)" % name2
    graph1 = CDiffGraphViewer(title1, g1, colours[0])
    graph2 = CDiffGraphViewer(title2, g2, colours[1])
    graph1.Show()
    graph2.Show()

    set_dock_pos(title1, title2, DP_RIGHT)
    uitimercallback_t(graph1, 100)
    uitimercallback_t(graph2, 100)

  def get_graph(self, ea1, primary=False):
    if primary:
      db = "main"
    else:
      db = "diff"
    cur = self.db_cursor()
    dones = set()
    sql = """ select bb.address, ins.address, ins.mnemonic, ins.disasm
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
    for row in cur.fetchall():
      bb_ea = str(int(row[0]))
      ins_ea = str(int(row[1]))
      mnem = row[2]
      dis = row[3]

      if ins_ea in dones:
        continue
      dones.add(ins_ea)

      try:
        bb_blocks[bb_ea].append([ins_ea, mnem, dis])
      except KeyError:
        bb_blocks[bb_ea] = [ [ins_ea, mnem, dis] ]

    sql = """ select (select address
                      from %s.basic_blocks
               where id = bbr.parent_id),
                   (select address
                      from %s.basic_blocks
               where id = bbr.child_id)
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
    rows = cur.fetchall()

    bb_relations = {}
    for row in rows:
      bb_ea1 = str(row[0])
      bb_ea2 = str(row[1])
      try:
        bb_relations[bb_ea1].add(bb_ea2)
      except KeyError:
        bb_relations[bb_ea1] = set([bb_ea2])

    cur.close()
    return bb_blocks, bb_relations

  def show_pseudo(self, item, primary):
    cur = self.db_cursor()
    if primary:
      db = "main"
    else:
      db = "diff"
    ea = str(int(item[1], 16))
    sql = "select prototype, pseudocode, name from %s.functions where address = ?"
    sql = sql % db
    cur.execute(sql, (str(ea), ))
    row = cur.fetchone()
    if row is None:
      Warning("Sorry, there is no pseudo-code available for the selected function.")
    else:
      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = True
      func = "%s\n%s" % (row[0], row[1])
      src = highlight(func, CppLexer(), fmt)
      title = "Pseudo-code for %s" % row[2]
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)
    cur.close()

  def show_pseudo_diff(self, item):
    cur = self.db_cursor()
    sql = """select *
               from (
             select prototype, pseudocode, name, 1
               from functions
              where address = ?
                and pseudocode is not null
       union select prototype, pseudocode, name, 2
               from diff.functions
              where address = ?
                and pseudocode is not null)
              order by 4 asc"""
    ea1 = str(int(item[1], 16))
    ea2 = str(int(item[3], 16))
    cur.execute(sql, (ea1, ea2))
    rows = cur.fetchall()
    if len(rows) != 2:
      Warning("Sorry, there is no pseudo-code available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      html_diff = HtmlDiff()
      buf1 = row1[0] + "\n" + row1[1]
      buf2 = row2[0] + "\n" + row2[1]
      src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))

      title = "Diff pseudo-code %s - %s" % (row1[2], row2[2])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

    cur.close()

  def delete_function(self, ea):
    cur = self.db_cursor()
    cur.execute("delete from functions where address = ?", (ea, ))
    cur.close()

  def do_import_one(self, ea1, ea2, force = False):
    cur = self.db_cursor()
    sql = "select prototype, comment, mangled_function, function_flags from diff.functions where address = ?"
    cur.execute(sql, (ea2,))
    row = cur.fetchone()
    if row is not None:
      proto = row[0]
      comment = row[1]
      name = row[2]
      flags = row[3]

      ea1 = int(ea1)
      if not name.startswith("sub_") or force:
        if not MakeNameEx(ea1, name, SN_NOWARN|SN_NOCHECK):
          for i in xrange(10):
            if MakeNameEx(ea1, "%s_%d" % (name, i), SN_NOWARN|SN_NOCHECK):
              break

      if proto is not None and proto != "int()":
        SetType(ea1, proto)

      if comment is not None and comment != "":
        SetFunctionCmt(ea1, comment, 1)

      if flags is not None:
        SetFunctionFlags(ea1, flags)

    cur.close()

  def import_selected(self, items, selected):
    # Import all the type libraries from the diff database
    self.import_til()
    # Import all the struct and enum definitions
    self.import_definitions()

    new_items = []
    for item in selected:
      new_items.append(items[item-1])
    self.import_items(new_items)

  def import_items(self, items):
    to_import = set()
    # Import all the function names and comments
    for item in items:
      ea1 = str(int(item[1], 16))
      ea2 = str(int(item[3], 16))
      self.do_import_one(ea1, ea2)
      to_import.add(ea1)

    try:
      show_wait_box("Updating primary database...")
      for ea in to_import:
        ea = str(ea)
        new_func = self.read_function(ea)
        self.delete_function(ea)
        self.save_function(new_func)
      self.db.commit()
    finally:
      hide_wait_box()

  def do_import_all(self, items):
    # Import all the type libraries from the diff database
    self.import_til()
    # Import all the struct and enum definitions
    self.import_definitions()
    # Import all the items in the chooser
    self.import_items(items)

  def do_import_all_auto(self, items):
    # Import all the type libraries from the diff database
    self.import_til()
    # Import all the struct and enum definitions
    self.import_definitions()

    # Import all the items in the chooser for sub_* functions
    new_items = []
    for item in items:
      name1 = item[2]
      if name1.startswith("sub_"):
        new_items.append(item)
    
    self.import_items(new_items)

  def re_diff(self):
    self.best_chooser.Close()
    self.partial_chooser.Close()
    if self.unreliable_chooser is not None:
      self.unreliable_chooser.Close()
    if self.unmatched_primary is not None:
      self.unmatched_primary.Close()
    if self.unmatched_second is not None:
      self.unmatched_second.Close()

    ret = askyn_c(1, "Do you want to show only the new matches?")
    if ret == -1:
      return
    elif ret == 0:
      self.matched1 = set()
      self.matched2 = set()

    self.diff(self.last_diff_db)

  def import_all(self, items):
    try:
      self.do_import_all(items)
      
      msg = "AUTOHIDE DATABASE\nHIDECANCEL\nAll functions were imported. Do you want to relaunch the diffing process?"
      if askyn_c(1, msg) == 1:
        self.db.execute("detach diff")
        # We cannot run that code here or otherwise IDA will crash corrupting the stack
        timeraction_t(self.re_diff, None, 1000)
    except:
      log("import_all(): %s" % str(sys.exc_info()[1]))
      traceback.print_exc()

  def import_all_auto(self, items):
    try:
      self.do_import_all_auto(items)
    except:
      log("import_all(): %s" % str(sys.exc_info()[1]))
      traceback.print_exc()

  def equal_db(self):
    cur = self.db_cursor()
    sql = "select count(*) from program p, diff.program dp where p.md5sum = dp.md5sum"
    cur.execute(sql)
    row = cur.fetchone()
    ret = row[0] == 1
    if not ret:
      sql = "select count(*) from (select * from functions except select * from diff.functions) x"
      cur.execute(sql)
      row = cur.fetchone()
    else:
      log("Same MD5 in both databases")
    cur.close()
    return row[0] == 0

  def check_callgraph(self):
    cur = self.db_cursor()
    sql = """select callgraph_primes, callgraph_all_primes from program
              union
             select callgraph_primes, callgraph_all_primes from diff.program"""
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) == 2:
      cg1 = decimal.Decimal(rows[0][0])
      cg_factors1 = json.loads(rows[0][1])
      cg2 = decimal.Decimal(rows[1][0])
      cg_factors2 = json.loads(rows[1][1])

      if cg1 == cg2:
        Warning("Callgraph signature for both databases is equal, the program seems to be 100% equal structurally")
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
    sql = "select address, mangled_function from (select * from functions intersect select * from diff.functions) x"
    cur.execute(sql)
    rows = cur.fetchall()
    choose = self.best_chooser
    if len(rows) > 0:
      for row in rows:
        name = row[1]
        ea = LocByName(name)
        ea2 = row[0]
        choose.add_item(CChooser.Item(ea, name, ea2, name, "100% equal", 1))
        self.matched1.add(name)
        self.matched2.add(name)

    sql = """select f.address, f.name, df.address, df.name, 'Equal pseudo-code' description
               from functions f,
                    diff.functions df
              where f.pseudocode = df.pseudocode
                and df.pseudocode is not null
                and f.pseudocode_lines >= 5"""
    log_refresh("Finding with heuristic 'Equal pseudo-code'")
    self.add_matches_from_query(sql, choose)

    sql = """select f.address, f.name, df.address, df.name, 'Equal assembly' description
               from functions f,
                    diff.functions df
              where f.assembly = df.assembly
                and df.assembly is not null"""
    log_refresh("Finding with heuristic 'Equal assembly'")
    self.add_matches_from_query(sql, choose)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Bytes hash and names' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
                from functions f,
                     diff.functions df
               where f.names = df.names
                 and f.bytes_hash = df.bytes_hash
                 and f.names != '[]'"""
    log_refresh("Finding with heuristic 'Bytes hash and names'")
    self.add_matches_from_query_ratio(sql, choose, self.partial_chooser)

    sql = """select f.address, f.name, df.address, df.name, 'Same address, nodes, edges and mnemonics' description,
                    f.pseudocode, df.pseudocode,
                    f.assembly, df.assembly,
                    f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.rva = df.rva
                and f.instructions = df.instructions
                and f.nodes = df.nodes
                and f.edges = df.edges
                and f.mnemonics = df.mnemonics"""
    log_refresh("Finding with heuristic 'Same address, nodes, edges and mnemonics'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, None)

    cur.close()

  def decompile_and_get(self, ea):
    if not init_hexrays_plugin():
      return False
    
    f = get_func(ea)
    if f is None:
      return False

    cfunc = decompile(f);
    if cfunc is None:
      # Failed to decompile
      return False

    visitor = CAstVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)
    self.pseudo_hash[ea] = visitor.primes_hash

    sv = cfunc.get_pseudocode();
    self.pseudo[ea] = []
    first_line = None
    for sline in sv:
      line = tag_remove(sline.line);
      if line.startswith("//"):
        continue
      
      if first_line is None:
        first_line = line
      else:
        self.pseudo[ea].append(line)
    return first_line

  def guess_type(self, ea):
    t = GuessType(ea)
    if not self.use_decompiler_always:
      return t
    else:
      try:
        ret = self.decompile_and_get(ea)
        if ret:
          t = ret
      except:
        log("Cannot decompile 0x%x: %s" % (ea, str(sys.exc_info()[1])))
    return t

  def ast_ratio(self, ast1, ast2):
    if not self.relaxed_ratio:
      return 0
    return ast_ratio(ast1, ast2)

  def check_ratio(self, ast1, ast2, pseudo1, pseudo2, asm1, asm2):
    fratio = quick_ratio
    if self.relaxed_ratio:
      fratio = real_quick_ratio

    v3 = 0
    ast_done = False
    if self.relaxed_ratio and ast1 is not None and ast2 is not None and max(len(ast1), len(ast2)) < 16:
      ast_done = True
      v3 = self.ast_ratio(ast1, ast2)
      if v3 == 1:
        return 1.0

    v1 = fratio(pseudo1, pseudo2)
    if v1 == 1:
      return 1.0
    v2 = fratio(self.get_cmp_asm(asm1), self.get_cmp_asm(asm2))
    if v2 == 1:
      return 1.0

    if self.relaxed_ratio and not ast_done:
      v3 = fratio(ast1, ast2)
      if v3 == 1:
        return 1.0

    r = max(v1, v2, v3)
    return r

  def add_matches_from_query_ratio(self, sql, best, partial, unreliable=None):
    cur = self.db_cursor()
    cur.execute(sql)

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

      ea = str(row[0])
      name1 = row[1]
      ea2 = row[2]
      name2 = row[3]
      desc = row[4]
      pseudo1 = row[5]
      pseudo2 = row[6]
      asm1 = row[7]
      asm2 = row[8]
      ast1 = row[9]
      ast2 = row[10]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2)
      if r == 1:
        best.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif r > 0.0 and unreliable is None:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()

  def add_matches_from_query_ratio_max(self, sql, best, partial, val):
    cur = self.db_cursor()
    cur.execute(sql)

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

      ea = str(row[0])
      name1 = row[1]
      ea2 = row[2]
      name2 = row[3]
      desc = row[4]
      pseudo1 = row[5]
      pseudo2 = row[6]
      asm1 = row[7]
      asm2 = row[8]
      ast1 = row[9]
      ast2 = row[10]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2)

      if r > val:
        best.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r))
        self.matched1.add(name1)
        self.matched2.add(name2)
      elif partial is not None:
        partial.add_item(CChooser.Item(ea, name1, ea2, name2, desc, r))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()

  def add_matches_from_query(self, sql, choose):
    """ Warning: use this *only* if the ratio is known to be 1.00 """
    cur = self.db_cursor()
    cur.execute(sql)

    i = 0
    while 1:
      i += 1
      if i % 1000 == 0:
        log("Processed %d rows..." % i)
      row = cur.fetchone()
      if row is None:
        break

      ea = str(row[0])
      name1 = row[1]
      ea2 = row[2]
      name2 = row[3]
      desc = row[4]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      choose.add_item(CChooser.Item(ea, name1, ea2, name2, desc, 1))
      self.matched1.add(name1)
      self.matched2.add(name2)
    cur.close()

  def search_small_differences(self, choose):
    cur = self.db_cursor()
    
    # Same basic blocks, edges, mnemonics, etc... but different names
    sql = """ select distinct f.address ea, f.name name1, df.name name2,
                     f.names, df.names, df.address ea2
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.names != '[]'"""
    cur.execute(sql)
    rows = cur.fetchall()
    for row in rows:
      ea = str(row[0])
      name1 = row[1]
      name2 = row[2]

      if name1 in self.matched1 or name2 in self.matched2:
        continue

      s1 = set(json.loads(row[3]))
      s2 = set(json.loads(row[4]))
      total = max(len(s1), len(s2))
      commons = len(s1.intersection(s2))
      ratio = (commons * 1.) / total
      if ratio >= 0.5:
        ea2 = row[5]
        choose.add_item(CChooser.Item(ea, name1, ea2, name2, "Nodes, edges, complexity and mnemonics with small differences", ratio))
        self.matched1.add(name1)
        self.matched2.add(name2)

    cur.close()
    return

  def find_matches(self):
    choose = self.partial_chooser

    if not self.ignore_all_names:
      cur = self.db_cursor()
      sql = """select f.address, f.mangled_function, d.address, f.name, d.name, d.mangled_function,
                      f.pseudocode, d.pseudocode,
                      f.assembly, d.assembly,
                      f.pseudocode_primes, d.pseudocode_primes
                 from functions f,
                      diff.functions d
                where (d.mangled_function = f.mangled_function
                    or d.name = f.name)"""
      log_refresh("Finding with heuristic 'Same name'")
      cur.execute(sql)
      rows = cur.fetchall()
      cur.close()

      if len(rows) > 0:
        for row in rows:
          ea = row[0]
          name = row[1]
          ea2 = row[2]
          name1 = row[3]
          name2 = row[4]
          name2_1 = row[5]
          if name in self.matched1 or name1 in self.matched1 or \
             name2 in self.matched2 or name2_1 in self.matched2:
            continue

          if self.ignore_sub_names and name.startswith("sub_"):
            continue

          ast1 = row[10]
          ast2 = row[11]
          pseudo1 = row[6]
          pseudo2 = row[7]
          asm1 = row[8]
          asm2 = row[9]
          ratio = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2)

          if float(ratio) == 1.0:
            self.best_chooser.add_item(CChooser.Item(ea, name, ea2, name, "Perfect match, same name", 1))
          else:
            choose.add_item(CChooser.Item(ea, name, ea2, name, "Perfect match, same name", ratio))

          self.matched1.add(name)
          self.matched1.add(name1)
          self.matched2.add(name2)
          self.matched2.add(name2_1)

    sql = """select f.address, f.name, df.address, df.name,
                    'Same address, nodes, edges and primes (re-ordered instructions)' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.rva = df.rva
                and f.instructions = df.instructions
                and f.nodes = df.nodes
                and f.edges = df.edges
                and f.primes_value = df.primes_value"""
    log_refresh("Finding with heuristic 'Same address, nodes, edges and primes (re-ordered instructions)'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.5)

    sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Import names hash',
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
                from functions f,
                     diff.functions df
               where f.names = df.names
                 and f.names != '[]'
                 and f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.instructions = df.instructions"""
    log_refresh("Finding with heuristic 'Import names hash'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

    sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Nodes, edges, complexity, mnemonics, names, prototype2, in-degree and out-degree',
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
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
                 and f.names != '[]'"""
    log_refresh("Finding with heuristic 'Nodes, edges, complexity, mnemonics, names, prototype, in-degree and out-degree'")
    self.add_matches_from_query_ratio(sql, self.partial_chooser, self.partial_chooser)

    sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Nodes, edges, complexity, mnemonics, names and prototype2' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.names = df.names
                 and f.names != '[]'
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.prototype2 = df.prototype2 """
    log_refresh("Finding with heuristic 'Nodes, edges, complexity, mnemonics, names and prototype'")
    self.add_matches_from_query_ratio(sql, self.partial_chooser, self.partial_chooser)

    sql = """ select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Mnemonics and names' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
                from functions f,
                     diff.functions df
               where f.mnemonics = df.mnemonics
                 and f.instructions = df.instructions
                 and f.names = df.names
                 and f.names != '[]'"""
    log_refresh("Finding with heuristic 'Mnemonics and names'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    # Search using some of the previous criterias but calculating the
    # edit distance
    log_refresh("Finding with heuristic 'Small names difference'")
    self.search_small_differences(choose)

    if self.slow_heuristics:
      sql = """select distinct f.address, f.name, df.address, df.name, 'Pseudo-code fuzzy hash' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where df.pseudocode_hash1 = f.pseudocode_hash1
                   or df.pseudocode_hash2 = f.pseudocode_hash2
                   or df.pseudocode_hash3 = f.pseudocode_hash3"""
      log_refresh("Finding with heuristic 'Pseudo-code fuzzy hashes'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, choose)
    else:
      sql = """select distinct f.address, f.name, df.address, df.name, 'Pseudo-code fuzzy hash' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where df.pseudocode_hash1 = f.pseudocode_hash1"""
      log_refresh("Finding with heuristic 'Pseudo-code fuzzy hash'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

    if self.slow_heuristics:
      sql = """select distinct f.address, f.name, df.address, df.name, 'Similar pseudo-code' description,
                      f.pseudocode, df.pseudocode,
                      f.pseudocode, df.pseudocode,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.pseudocode_lines = df.pseudocode_lines
                  and df.pseudocode_lines > 5
                  and df.pseudocode is not null 
                  and f.pseudocode is not null"""
      log_refresh("Finding with heuristic 'Similar pseudo-code'")
      self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.729)

    sql = """select distinct f.address, f.name, df.address, df.name, 'Pseudo-code fuzzy AST hash' description,
                    f.pseudocode, df.pseudocode,
                    f.assembly, df.assembly,
                    f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where df.pseudocode_primes = f.pseudocode_primes
                and f.pseudocode_lines > 5
                and length(f.pseudocode_primes) >= 35"""
    log_refresh("Finding with heuristic 'Pseudo-code fuzzy AST hash'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

    if self.slow_heuristics:
      sql = """  select distinct f.address, f.name, df.address, df.name, 'Partial pseudo-code fuzzy hash' description,
                        f.pseudocode, df.pseudocode,
                        f.assembly, df.assembly,
                        f.pseudocode_primes, df.pseudocode_primes
                   from functions f,
                        diff.functions df
                  where substr(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
                     or substr(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
                     or substr(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)"""
      log_refresh("Finding with heuristic 'Partial pseudo-code fuzzy hash'")
      self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

    sql = """select f.address, f.name, df.address, df.name,
                    'Topological sort hash' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.strongly_connected = df.strongly_connected
                and f.tarjan_topological_sort = df.tarjan_topological_sort
                and f.strongly_connected > 3"""
    log_refresh("Finding with heuristic 'Topological sort hash (first pass)'")
    self.add_matches_from_query_ratio_max(sql, self.best_chooser, None, 0.99)

    sql = """select f.address, f.name, df.address, df.name,
                    'Topological sort hash' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.strongly_connected = df.strongly_connected
                and f.tarjan_topological_sort = df.tarjan_topological_sort
                and f.strongly_connected > 3"""
    log_refresh("Finding with heuristic 'Topological sort hash (second pass)'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.4)

    sql = """  select f.address, f.name, df.address, df.name, 'Same high complexity, prototype and names' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity >= 20
                  and f.prototype2 = df.prototype2
                  and df.names != '[]'"""
    log_refresh("Finding with heuristic 'Same high complexity, prototype and names'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    sql = """  select f.address, f.name, df.address, df.name, 'Same high complexity and names' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity >= 15
                  and df.names != '[]'"""
    log_refresh("Finding with heuristic 'Same high complexity and names'")
    self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

    if self.slow_heuristics:
      sql = """select f.address, f.name, df.address, df.name, 'Strongly connected components' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.strongly_connected = df.strongly_connected
                  and df.strongly_connected > 1
                  and f.nodes > 3 and df.nodes > 3
                  and f.strongly_connected_spp > 1
                  and df.strongly_connected_spp > 1"""
      log_refresh("Finding with heuristic 'Strongly connected components'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.80)
    else:
      sql = """select f.address, f.name, df.address, df.name, 'Strongly connected components' description,
                    f.pseudocode, df.pseudocode,
                    f.assembly, df.assembly,
                    f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.strongly_connected = df.strongly_connected
                and df.strongly_connected > 3
                and f.nodes > 3 and df.nodes > 3
                and f.strongly_connected_spp > 1
                and df.strongly_connected_spp > 1"""
      log_refresh("Finding with heuristic 'Strongly connected components'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.80)

    if self.slow_heuristics:
      sql = """select f.address, f.name, df.address, df.name, 'Loop count' description,
                  f.pseudocode, df.pseudocode,
                  f.assembly, df.assembly,
                  f.pseudocode_primes, df.pseudocode_primes
             from functions f,
                  diff.functions df
            where f.loops = df.loops
              and df.loops > 1
              and f.nodes > 3 and df.nodes > 3"""
      log_refresh("Finding with heuristic 'Loop count'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.49)

    sql = """  select f.address, f.name, df.address, df.name, 'Strongly connected components small-primes-product' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.strongly_connected_spp = df.strongly_connected_spp
                  and df.strongly_connected_spp > 1"""
    log_refresh("Finding with heuristic 'Strongly connected components small-primes-product'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    sql = """  select f.address, f.name, df.address, df.name, 'Same names and order' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and df.names != '[]'"""
    log_refresh("Finding with heuristic 'Same names and order'")
    self.add_matches_from_query_ratio(sql, choose, choose)

    sql = """select f.address, f.name, df.address, df.name,
                    'Same nodes, edges and strongly connected components' description,
                     f.pseudocode, df.pseudocode,
                     f.assembly, df.assembly,
                     f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.nodes = df.nodes
                and f.edges = df.edges
                and f.strongly_connected = df.strongly_connected
                and df.nodes > 4"""
    log_refresh("Finding with heuristic 'Same nodes, edges and strongly connected components'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, choose, self.unreliable_chooser)

  def find_experimental_matches(self):
    choose = self.unreliable_chooser
    if self.slow_heuristics:
      sql = """select distinct f.address, f.name, df.address, df.name, 'Similar small pseudo-code' description,
                      f.pseudocode, df.pseudocode,
                      f.pseudocode, df.pseudocode,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.pseudocode_lines = df.pseudocode_lines
                  and df.pseudocode_lines <= 5
                  and df.pseudocode is not null 
                  and f.pseudocode is not null"""
      log_refresh("Finding with heuristic 'Similar small pseudo-code'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.49)

      sql = """select distinct f.address, f.name, df.address, df.name, 'Small pseudo-code fuzzy AST hash' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where df.pseudocode_primes = f.pseudocode_primes
                  and f.pseudocode_lines <= 5"""
      log_refresh("Finding with heuristic 'Small pseudo-code fuzzy AST hash'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

    sql = """select f.address, f.name, df.address, df.name, 'Equal small pseudo-code' description,
                    f.pseudocode, df.pseudocode,
                    f.assembly, df.assembly,
                    f.pseudocode_primes, df.pseudocode_primes
               from functions f,
                    diff.functions df
              where f.pseudocode = df.pseudocode
                and df.pseudocode is not null
                and f.pseudocode_lines < 5"""
    log_refresh("Finding with heuristic 'Equal small pseudo-code'")
    self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

    sql = """  select f.address, f.name, df.address, df.name, 'Same high complexity, prototype and names' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity < 20
                  and f.prototype2 = df.prototype2
                  and df.names != '[]'"""
    log_refresh("Finding with heuristic 'Same low complexity, prototype and names'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.5)

    sql = """  select f.address, f.name, df.address, df.name, 'Same low complexity and names' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.names = df.names
                  and f.cyclomatic_complexity = df.cyclomatic_complexity
                  and f.cyclomatic_complexity < 15
                  and df.names != '[]'"""
    log_refresh("Finding with heuristic 'Same low complexity and names'")
    self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.5)

  def find_unreliable_matches(self):
    choose = self.unreliable_chooser

    if self.slow_heuristics:
      sql = """select f.address, f.name, df.address, df.name, 'Strongly connected components' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where f.strongly_connected = df.strongly_connected
                  and df.strongly_connected > 2"""
      log_refresh("Finding with heuristic 'Strongly connected components'")
      self.add_matches_from_query_ratio_max(sql, self.partial_chooser, choose, 0.54)

      sql = """select f.address, f.name, df.address, df.name, 'Loop count' description,
                  f.pseudocode, df.pseudocode,
                  f.assembly, df.assembly,
                  f.pseudocode_primes, df.pseudocode_primes
             from functions f,
                  diff.functions df
            where f.loops = df.loops
              and df.loops > 1"""
      log_refresh("Finding with heuristic 'Loop count'")
      self.add_matches_from_query_ratio(sql, choose, choose)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Bytes hash' description,
                       f.pseudocode, df.pseudocode,
                       f.assembly, df.assembly,
                       f.pseudocode_primes, df.pseudocode_primes
                  from functions f,
                       diff.functions df
                 where f.bytes_hash = df.bytes_hash
                   and f.instructions = df.instructions"""
      log_refresh("Finding with heuristic 'Bytes hash'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, choose, self.unreliable_chooser)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges, complexity and mnemonics' description,
                       f.pseudocode, df.pseudocode,
                       f.assembly, df.assembly,
                       f.pseudocode_primes, df.pseudocode_primes
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.mnemonics = df.mnemonics
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.nodes > 1 and f.edges > 0"""
      log_refresh("Finding with heuristic 'Nodes, edges, complexity and mnemonics'")
      self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges, complexity and prototype' description,
                       f.pseudocode, df.pseudocode,
                       f.assembly, df.assembly,
                       f.pseudocode_primes, df.pseudocode_primes
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.prototype2 = df.prototype2
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.prototype2 != 'int()'"""
      log_refresh("Finding with heuristic 'Nodes, edges, complexity and prototype'")
      self.add_matches_from_query_ratio(sql, choose, choose)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges, complexity, in-degree and out-degree' description,
                       f.pseudocode, df.pseudocode,
                       f.assembly, df.assembly,
                       f.pseudocode_primes, df.pseudocode_primes
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.nodes > 1 and f.edges > 0
                   and f.indegree = df.indegree
                   and f.outdegree = df.outdegree"""
      log_refresh("Finding with heuristic 'Nodes, edges, complexity, in-degree and out-degree'")
      self.add_matches_from_query_ratio(sql, self.partial_chooser, choose)

      sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                       'Nodes, edges and complexity' description,
                       f.pseudocode, df.pseudocode,
                       f.assembly, df.assembly,
                       f.pseudocode_primes, df.pseudocode_primes
                  from functions f,
                       diff.functions df
                 where f.nodes = df.nodes
                   and f.edges = df.edges
                   and f.cyclomatic_complexity = df.cyclomatic_complexity
                   and f.nodes > 1 and f.edges > 0"""
      log_refresh("Finding with heuristic 'Nodes, edges and complexity'")
      self.add_matches_from_query_ratio(sql, choose, choose)

      sql = """select f.address, f.name, df.address, df.name, 'Similar small pseudo-code' description,
                      f.pseudocode, df.pseudocode,
                      f.assembly, df.assembly,
                      f.pseudocode_primes, df.pseudocode_primes
                 from functions f,
                      diff.functions df
                where df.pseudocode is not null 
                  and f.pseudocode is not null
                  and f.pseudocode_lines = df.pseudocode_lines
                  and df.pseudocode_lines > 5"""
      log_refresh("Finding with heuristic 'Similar pseudo-code'")
      self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

      sql = """  select f.address, f.name, df.address, df.name, 'Same high complexity' description,
                        f.pseudocode, df.pseudocode,
                        f.assembly, df.assembly,
                        f.pseudocode_primes, df.pseudocode_primes
                   from functions f,
                        diff.functions df
                  where f.cyclomatic_complexity = df.cyclomatic_complexity
                    and f.cyclomatic_complexity >= 50"""
      log_refresh("Finding with heuristic 'Same high complexity'")
      self.add_matches_from_query_ratio(sql, choose, choose)

  def find_unmatched(self):
    cur = self.db_cursor()
    sql = "select name from functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      choose = CChooser("Unmatched in secondary", self, False)
      for row in rows:
        name = row[0]
        demangled_name = Demangle(str(name), INF_SHORT_DN)
        if demangled_name is not None:
          name = demangled_name

        if name not in self.matched1:
          ea = LocByName(str(name))
          choose.add_item(CChooser.Item(ea, name))
      self.unmatched_second = choose

    sql = "select name, address from diff.functions"
    cur.execute(sql)
    rows = cur.fetchall()
    if len(rows) > 0:
      choose = CChooser("Unmatched in primary", self, False)
      for row in rows:
        name = row[0]
        demangled_name = Demangle(str(name), INF_SHORT_DN)
        if demangled_name is not None:
          name = demangled_name
        if name not in self.matched2:
          ea = row[1]
          choose.add_item(CChooser.Item(ea, name))
      self.unmatched_primary = choose

    cur.close()

  def create_choosers(self):
    self.unreliable_chooser = CChooser("Unreliable matches", self)
    self.partial_chooser = CChooser("Partial matches", self)
    self.best_chooser = CChooser("Best matches", self)

  def show_choosers(self, force=False):
    if len(self.best_chooser.items) > 0:
      self.best_chooser.show(force)
    if len(self.partial_chooser.items) > 0:
      self.partial_chooser.show(force)

    if self.unreliable_chooser is not None and len(self.unreliable_chooser.items) > 0:
      self.unreliable_chooser.show(force)
    if self.unmatched_primary is not None and len(self.unmatched_primary.items) > 0:
      self.unmatched_primary.show(force)
    if self.unmatched_second is not None and len(self.unmatched_second.items) > 0:
      self.unmatched_second.show(force)

  def register_menu(self):
    global g_bindiff
    g_bindiff = self

    idaapi.add_menu_item("Edit/Plugins/", "Diaphora - Show results", "F3", 0, show_choosers, ())
    Warning("""AUTOHIDE REGISTRY\nIf you close one tab you can always re-open it by pressing F3
or selecting Edit -> Plugins -> Diaphora - Show results""")

  def diff(self, db):
    self.last_diff_db = db

    cur = self.db_cursor()
    cur.execute('attach "%s" as diff' % db)

    try:
      cur.execute("select value from diff.version")
    except:
      log("Error: %s " % sys.exc_info()[1])
      Warning("The selected file does not like a valid SQLite exported database!")
      cur.close()
      return False

    row = cur.fetchone()
    if not row:
      Warning("Invalid database!")
      return False

    if row[0] != VERSION_VALUE:
      Warning("The database is from a different version (current %s, database %s)!" % (VERSION_VALUE, row[0]))
      return False

    # Create the choosers
    self.create_choosers()

    try:
      log_refresh("Performing diffing...", True)
      
      do_continue = True
      if self.equal_db():
        log("The databases seems to be 100% equal")
        if askyn_c(0, "HIDECANCEL\nThe databases seems to be 100% equal. Do you want to continue anyway?") != 1:
          do_continue = False

      if do_continue:
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

        # And, finally, show the list of best and partial matches and
        # register the hotkey for re-opening results
        self.show_choosers()
        self.register_menu()
        log("Done")
    finally:
      cur.close()
      hide_wait_box()
    return True

#-----------------------------------------------------------------------
def remove_file(filename):
  try:
    os.remove(filename)
  except:
    # Fix for Bug #5: https://github.com/joxeankoret/diaphora/issues/5
    #
    # For some reason, in Windows, the handle to the SQLite database is
    # not closed, and I really try to be sure that all the databases are 
    # detached, no cursor is leaked, etc... So, in case we cannot remove
    # the database file because it's still being used by IDA in Windows
    # for some unknown reason, just drop the database's tables and after
    # that continue normally.
    with sqlite3.connect(filename) as db:
      cur = db.cursor()
      try:
        funcs = ["functions", "program", "program_data", "version",
               "instructions", "basic_blocks", "bb_relations",
               "bb_instructions", "function_bblocks"]
        for func in funcs:
          db.execute("drop table if exists %s" % func)
      finally:
        cur.close()

#-----------------------------------------------------------------------
def diff_or_export():
  global g_bindiff

  if GetIdbPath() == "" or len(list(Functions())) == 0:
    Warning("No IDA database opened or no function in the database.\nPlease open an IDA database and create some functions before running this script.")
    return

  x = CBinDiffExporterSetup()
  x.Compile()
  x.rUseDecompiler.checked = True
  x.rUnreliable.checked = True
  x.iMinEA.value = MinEA()
  x.iMaxEA.value = MaxEA()
  # Disable by default slow heuristics for medium size databases
  x.rSlowHeuristics.checked = len(list(Functions())) < 2000
  x.rRelaxRatio.checked = False
  x.rExperimental.checked = False
  x.rNonIdaSubs.checked = False
  x.rIgnoreSubNames.checked = True
  x.rIgnoreAllNames.checked = False
  # Enable, by default, exporting only function summaries for huge dbs.
  x.rFuncSummariesOnly.checked = len(list(Functions())) > 100000
  if not x.Execute():
    return

  file_out = x.iFileSave.value
  file_in  = x.iFileOpen.value
  use_decompiler = x.rUseDecompiler.checked
  unreliable = x.rUnreliable.checked
  slow = x.rSlowHeuristics.checked
  relax = x.rRelaxRatio.checked
  experimental = x.rExperimental.checked
  min_ea = x.iMinEA.value
  max_ea = x.iMaxEA.value
  ida_subs = x.rNonIdaSubs.checked == False
  ignore_sub_names = x.rIgnoreSubNames.checked
  ignore_all_names = x.rIgnoreAllNames.checked
  func_summaries_only = x.rFuncSummariesOnly.checked

  if file_out == file_in:
    Warning("Both databases are the same file!")
    return
  elif file_out == "" or len(file_out) < 5:
    Warning("No output database selected or invalid filename. Please select a database file.")
    return
  elif file_out[len(file_out)-4:].lower() in [".idb", ".i64"] or file_in[len(file_in)-4:].lower() in [".idb", ".i64"]:
    Warning("One of the selected databases is an IDA database (IDB or I64), not a SQLite database!")
    return
  elif file_out.lower().endswith(".til") or file_in.lower().endswith(".id0") or file_in.lower().endswith(".id1") or file_in.lower().endswith(".nam"):
    Warning("One of the selected databases is an IDA temporary file, not a SQLite database!")
    return

  export = True
  if os.path.exists(file_out):
    ret = askyn_c(0, "Export database already exists. Do you want to overwrite it?")
    if ret == -1:
      log("Cancelled")
      return

    if ret == 0:
      export = False

    if export:
      if g_bindiff is not None:
        g_bindiff = None
      remove_file(file_out)
      log("Database %s removed" % repr(file_out))

  try:
    bd = CBinDiff(file_out)
    bd.use_decompiler_always = use_decompiler
    bd.unreliable = unreliable
    bd.slow_heuristics = slow
    bd.relaxed_ratio = relax
    bd.experimental = experimental
    bd.min_ea = min_ea
    bd.max_ea = max_ea
    bd.ida_subs = ida_subs
    bd.ignore_sub_names = ignore_sub_names
    bd.ignore_all_names = ignore_all_names
    bd.function_summaries_only = func_summaries_only
    if export:
      if os.getenv("DIAPHORA_PROFILE") is not None:
        log("*** Profiling export ***")
        import cProfile
        profiler = cProfile.Profile()
        profiler.runcall(bd.export)
        profiler.print_stats(sort="time")
      else:
        bd.export()
      log("Database exported")

    if file_in != "":
      if os.getenv("DIAPHORA_PROFILE") is not None:
        log("*** Profiling diff ***")
        import cProfile
        profiler = cProfile.Profile()
        profiler.runcall(bd.diff, file_in)
        profiler.print_stats(sort="time")
      else:
        bd.diff(file_in)
  except:
    print("Error: %s" % sys.exc_info()[1])
    traceback.print_exc()

  return bd

if __name__ == "__main__":
  if os.getenv("DIAPHORA_AUTO") is not None:
    file_out = os.getenv("DIAPHORA_EXPORT_FILE")
    if file_out is None:
      raise Exception("No export file specified!")

    use_decompiler = os.getenv("DIAPHORA_USE_DECOMPILER")
    if use_decompiler is None:
      use_decompiler = False
    bd = CBinDiff(file_out)
    bd.use_decompiler_always = use_decompiler
    if os.path.exists(file_out):
      if g_bindiff is not None:
        g_bindiff = None

      remove_file(file_out)
      log("Database %s removed" % repr(file_out))

    bd.export()
  else:
    diff_or_export()

