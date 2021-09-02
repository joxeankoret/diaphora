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
import sys
import imp
import time
import json
import decimal
import difflib
import sqlite3
import traceback
import threading
from hashlib import md5

import diaphora

from pygments import highlight
from pygments.lexers import NasmLexer, CppLexer, DiffLexer
from pygments.formatters import HtmlFormatter

from others.tarjan_sort import strongly_connected_components, robust_topological_sort

from jkutils.factor import primesbelow as primes
from jkutils.graph_hashes import CKoretKaramitasHash

from idc import *
from idaapi import *
from idautils import *

import idaapi

from PyQt5 import QtCore, QtGui, QtWidgets

#-------------------------------------------------------------------------------
# Constants unexported in IDA Python
PRTYPE_SEMI = 0x0008

# Messages
MSG_RELAXED_RATIO_ENABLED = """AUTOHIDE DATABASE\n
Relaxed ratio calculations can be enabled. It will ignore many small
modifications to functions and will match more functions with higher ratios.
Enable this option if you're only interested in the new functionality. Disable
it for patch diffing if you're interested in small modifications (like buffer
sizes).

This is recommended for diffing big databases (more than 20,000 functions in the
database).

You can disable it by un-checking the 'Relaxed calculations of differences
ratios' option."""

MSG_FUNCTION_SUMMARIES_ONLY = """AUTOHIDE DATABASE\n
Do not export basic blocks or instructions will be enabled. It will not export
the information relative to basic blocks or instructions and 'Diff assembly in a
graph' will not be available.

This is automatically done for exporting huge databases with more than 100,000
functions. You can disable it by un-checking the 'Do not export basic blocks or
instructions' option."""

LITTLE_ORANGE = 0x026AFD

#-------------------------------------------------------------------------------
def log(message):
  msg("[%s] %s\n" % (time.asctime(), message))

#-------------------------------------------------------------------------------
def log_refresh(msg, show=False, do_log=True):
  if show:
    show_wait_box(msg)
  else:
    replace_wait_box(msg)

  if do_log:
    log(msg)

#-------------------------------------------------------------------------------
# TODO: FIX hack
diaphora.log = log
diaphora.log_refresh = log_refresh

#-------------------------------------------------------------------------------
g_bindiff = None
def show_choosers():
  global g_bindiff
  if g_bindiff is not None:
    g_bindiff.show_choosers(False)

#-------------------------------------------------------------------------------
def save_results():
  global g_bindiff
  if g_bindiff is not None:
    filename = ask_file(1, "*.diaphora", "Select the file to store diffing results")
    if filename is not None:
      g_bindiff.save_results(filename)

#-------------------------------------------------------------------------------
def load_and_import_all_results(filename, main_db, diff_db):
  tmp_diff = CIDABinDiff(":memory:")

  if(os.path.exists(filename) and os.path.exists(main_db) and os.path.exists(diff_db)):
    tmp_diff.load_and_import_all_results(filename, main_db, diff_db)

  idaapi.qexit(0)

#-------------------------------------------------------------------------------
def load_results():
  tmp_diff = CIDABinDiff(":memory:")
  filename = ask_file(0, "*.diaphora", "Select the file to load diffing results")
  if filename is not None:
    tmp_diff.load_results(filename)

#-------------------------------------------------------------------------------
def import_definitions():
  tmp_diff = diaphora.CIDABinDiff(":memory:")
  filename = ask_file(0, "*.sqlite", "Select the file to import structures, unions and enumerations from")
  if filename is not None:
    if ask_yn(1, "HIDECANCEL\nDo you really want to import all structures, unions and enumerations?") == 1:
      tmp_diff.import_definitions_only(filename)

#-------------------------------------------------------------------------------
def diaphora_decode(ea):
  ins = idaapi.insn_t()
  decoded_size = idaapi.decode_insn(ins, ea)
  return decoded_size, ins

#-------------------------------------------------------------------------------
class CHtmlViewer(PluginForm):
  def OnCreate(self, form):
    self.parent = self.FormToPyQtWidget(form)
    self.PopulateForm()

    self.browser = None
    self.layout = None
    return 1

  def PopulateForm(self):
    self.layout = QtWidgets.QVBoxLayout()
    self.browser = QtWidgets.QTextBrowser()
    self.browser.setLineWrapMode(QtWidgets.QTextEdit.FixedColumnWidth)
    self.browser.setLineWrapColumnOrWidth(150)
    self.browser.setHtml(self.text)
    self.browser.setReadOnly(True)
    self.browser.setFontWeight(12)
    self.layout.addWidget(self.browser)
    self.parent.setLayout(self.layout)

  def Show(self, text, title):
    self.text = text
    return PluginForm.Show(self, title)

#-------------------------------------------------------------------------------
class CBasicChooser(Choose):
  def __init__(self, title):
      Choose.__init__(
          self,
          title,
          [ ["Id",   10 | Choose.CHCOL_PLAIN] ,
            ["Name", 30 | Choose.CHCOL_PLAIN] ])
      self.items = []

  def OnGetSize(self):
      return len(self.items)

  def OnGetLine(self, n):
      return self.items[n]

#-------------------------------------------------------------------------------
# Hex-Rays finally removed AddCommand(). Now, instead of a 1 line call, we need
# 2 classes...
class command_handler_t(ida_kernwin.action_handler_t):
  def __init__(self, obj, cmd_id, num_args = 2):
    self.obj = obj
    self.cmd_id = cmd_id
    self.num_args = num_args
    ida_kernwin.action_handler_t.__init__(self)

  def activate(self, ctx):
    if self.num_args == 1:
      return self.obj.OnCommand(self.cmd_id)
    if len(self.obj.selected_items) == 0:
      sel = 0
    else:
      sel = self.obj.selected_items[0]
    return self.obj.OnCommand(sel, self.cmd_id)

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
# Support for the removed AddCommand() API
class CDiaphoraChooser(diaphora.CChooser, Choose):
  def __init__(self, title, bindiff, show_commands = True):
    diaphora.CChooser.__init__(self, title, bindiff, show_commands)
    self.actions = []

  def AddCommand(self, menu_name, shortcut=None):
    if menu_name is not None:
      action_name = "Diaphora:%s" % menu_name.replace(" ", "")
    else:
      action_name = None
    self.actions.append([len(self.actions), action_name, menu_name, shortcut])
    return len(self.actions)-1

  def OnPopup(self, form, popup_handle):
    for num, action_name, menu_name, shortcut in self.actions:
      if menu_name is None:
        ida_kernwin.attach_action_to_popup(form, popup_handle, None)
      else:
        handler = command_handler_t(self, num, 2)
        desc = ida_kernwin.action_desc_t(action_name, menu_name, handler, shortcut)
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)

#-------------------------------------------------------------------------------
class CIDAChooser(CDiaphoraChooser):

  def __init__(self, title, bindiff, show_commands=True):
    CDiaphoraChooser  .__init__(self, title, bindiff, show_commands)
    if title.startswith("Unmatched in"):
      Choose.__init__(self, title, [ ["Line", 8], ["Address", 8], ["Name", 20] ], Choose.CH_MULTI)
    else:
      Choose.__init__(self, title, [ ["Line", 8], ["Address", 8], ["Name", 20], ["Address 2", 8], ["Name 2", 20],
                                      ["Ratio", 5], ["BBlocks 1", 5], ["BBlocks 2", 5], ["Description", 30] ], Choose.CH_MULTI)

  def OnSelectLine(self, n):
    item = self.items[n[0]]
    if self.primary:
      try:
        jump_ea = int(item[1], 16)
        # Only jump for valid addresses
        if is_mapped(jump_ea):
          jumpto(jump_ea)
      except:
        print("OnSelectLine", sys.exc_info()[1])
    else:
      self.bindiff.show_asm(self.items[n[0]], self.primary)

  def OnGetLine(self, n):
    try:
      return self.items[n]
    except:
      print("OnGetLine", sys.exc_info()[1])

  def OnGetSize(self):
    return len(self.items)

  def OnDeleteLine(self, items):
    for n in sorted(items, reverse=True):
      if n >= 0:
        name1 = self.items[n][2]
        name2 = self.items[n][4]

        del self.items[n]
        
        if name1 in self.bindiff.matched1:
          self.bindiff.matched1.remove(name1)
        if name2 in self.bindiff.matched2:
          self.bindiff.matched2.remove(name2)

    return [Choose.ALL_CHANGED] + items

  def show(self, force=False):
    if self.show_commands:
      self.items = sorted(self.items, key=lambda x: decimal.Decimal(x[5]), reverse=True)

    t = self.Show()
    if t < 0:
      return False

    if self.show_commands and (self.cmd_diff_asm is None or force):
      # create aditional actions handlers
      self.cmd_rediff = self.AddCommand("Diff again")
      self.cmd_save_results = self.AddCommand("Save results")
      self.cmd_add_manual_match = self.AddCommand("Add manual match")
      self.AddCommand(None)
      self.cmd_diff_asm = self.AddCommand("Diff assembly")
      self.cmd_diff_c = self.AddCommand("Diff pseudo-code")
      self.cmd_diff_graph = self.AddCommand("Diff assembly in a graph")
      self.cmd_diff_external = self.AddCommand("Diff using an external tool")
      self.cmd_diff_c_patch = self.AddCommand("Show pseudo-code patch")
      self.AddCommand(None)
      self.cmd_import_selected = self.AddCommand("Import selected", "Ctrl+Alt+i")
      self.cmd_import_selected_auto = self.AddCommand("Import selected sub_*")
      self.cmd_import_all = self.AddCommand("Import *all* functions")
      self.cmd_import_all_funcs = self.AddCommand("Import *all* data for sub_* functions")
      self.AddCommand(None)
      self.cmd_highlight_functions = self.AddCommand("Highlight matches")
      self.cmd_unhighlight_functions = self.AddCommand("Unhighlight matches")
    elif not self.show_commands and (self.cmd_show_asm is None or force):
      self.cmd_show_asm = self.AddCommand("Show assembly")
      self.cmd_show_pseudo = self.AddCommand("Show pseudo-code")

    return True

  def OnCommand(self, n, cmd_id):
    # Aditional right-click-menu commands handles
    if cmd_id == self.cmd_show_asm:
      self.bindiff.show_asm(self.items[n], self.primary)
    elif cmd_id == self.cmd_show_pseudo:
      self.bindiff.show_pseudo(self.items[n], self.primary)
    elif cmd_id == self.cmd_import_all:
      if ask_yn(1, "HIDECANCEL\nDo you really want to import all matched functions, comments, prototypes and definitions?") == 1:
        self.bindiff.import_all(self.items)
    elif cmd_id == self.cmd_import_all_funcs:
      if ask_yn(1, "HIDECANCEL\nDo you really want to import all IDA named matched functions, comments, prototypes and definitions?") == 1:
        self.bindiff.import_all_auto(self.items)
    elif cmd_id == self.cmd_import_selected or cmd_id == self.cmd_import_selected_auto:
      if len(self.selected_items) <= 1:
        self.bindiff.import_one(self.items[n])
      else:
        if ask_yn(1, "HIDECANCEL\nDo you really want to import all selected IDA named matched functions, comments, prototypes and definitions?") == 1:
          self.bindiff.import_selected(self.items, self.selected_items, cmd_id == self.cmd_import_selected_auto)
    elif cmd_id == self.cmd_diff_c:
      self.bindiff.show_pseudo_diff(self.items[n])
    elif cmd_id == self.cmd_diff_c_patch:
      self.bindiff.show_pseudo_diff(self.items[n], html=False)
    elif cmd_id == self.cmd_diff_asm:
      self.bindiff.show_asm_diff(self.items[n])
    elif cmd_id == self.cmd_highlight_functions:
      if ask_yn(1, "HIDECANCEL\nDo you want to change the background color of each matched function?") == 1:
        color = self.get_color()
        for item in self.items:
          ea = int(item[1], 16)
          if not set_color(ea, CIC_FUNC, color):
            print("Error setting color for %x" % ea)
        self.Refresh()
    elif cmd_id == self.cmd_unhighlight_functions:
      for item in self.items:
        ea = int(item[1], 16)
        if not set_color(ea, CIC_FUNC, 0xFFFFFF):
          print("Error setting color for %x" % ea)
      self.Refresh()
    elif cmd_id == self.cmd_diff_graph:
      item = self.items[n]
      ea1 = int(item[1], 16)
      name1 = item[2]
      ea2 = int(item[3], 16)
      name2 = item[4]
      log("Diff graph for 0x%x - 0x%x" % (ea1, ea2))
      self.bindiff.graph_diff(ea1, name1, ea2, name2)
    elif cmd_id == self.cmd_save_results:
      filename = ask_file(1, "*.diaphora", "Select the file to store diffing results")
      if filename is not None:
        self.bindiff.save_results(filename)
    elif cmd_id == self.cmd_add_manual_match:
      self.add_manual_match()
    elif cmd_id == self.cmd_rediff:
      self.bindiff.db.execute("detach diff")
      timeraction_t(self.bindiff.re_diff, None, 1000)
    elif cmd_id == self.cmd_diff_external:
      self.bindiff.diff_external(self.items[n])

    return True

  def get_diff_functions(self):
    cur = self.bindiff.db_cursor()
    cur.execute("select cast(id as text), name from diff.functions order by id")
    rows = list(cur.fetchall())
    rows = list(map(list, rows))
    cur.close()

    return rows

  def add_manual_match(self):
    f = choose_func("Select a function from the current database...", 0)
    if f is not None:
      diff_chooser = CBasicChooser("Select a function from the external database...")
      diff_funcs = self.get_diff_functions()
      diff_chooser.items = diff_funcs
      ret = diff_chooser.Show(modal=True)
      if ret > -1:
        name1 = get_func_name(f.start_ea)
        name2 = diff_funcs[ret][1]

        if name1 in self.bindiff.matched1 or name2 in self.bindiff.matched2:
          line = "Either the local function %s or the foreign function %s are already matched.\n" + \
                 "Please remove the previously assigned match before adding a manual match."
          warning(line % (repr(name1), repr(name2)))
        else:
          log("Adding manual match between %s and %s" % (name1, name2))
          sql = """ select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                           'Manual Match' description,
                           f.pseudocode pseudo1, df.pseudocode pseudo2,
                           f.assembly asm1, df.assembly asm2,
                           f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                           f.nodes bb1, df.nodes bb2,
                           cast(f.md_index as real) md1, cast(df.md_index as real) md2
                      from functions f,
                           diff.functions df
                     where f.name = %s
                       and df.name = %s""" % (repr(name1), repr(name2))
          self.bindiff.add_matches_from_query_ratio(sql, self.bindiff.best_chooser, self.bindiff.partial_chooser)
          for chooser in [self.bindiff.best_chooser, self.bindiff.partial_chooser, self.bindiff.unreliable_chooser]:
            chooser.Refresh()

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list

  def seems_false_positive(self, item):
    name1 = item[2]
    name2 = item[4]

    name1 = name1.rstrip("_0")
    name2 = name2.rstrip("_0")

    if not name1.startswith("sub_") and not name2.startswith("sub_"):
      if name1 != name2:
        if name2.find(name1) == -1 and not name1.find(name2) == -1:
          return True

    return False

  def OnGetLineAttr(self, n):
    if not self.title.startswith("Unmatched"):
      item = self.items[n]
      ratio = float(item[5])
      if self.seems_false_positive(item):
        return [LITTLE_ORANGE, 0]
      else:
        red = int(164 * (1 - ratio))
        green = int(128 * ratio)
        blue = int(255 * (1 - ratio))
        color = int("0x%02x%02x%02x" % (blue, green, red), 16)
      return [color, 0]
    return [0xFFFFFF, 0]

#-------------------------------------------------------------------------------
class CBinDiffExporterSetup(Form):
  def __init__(self):
    s = r"""Diaphora
  Please select the path to the SQLite database to save the current IDA database and the path of the SQLite database to diff against.
  If no SQLite diff database is selected, it will just export the current IDA database to SQLite format. Leave the 2nd field empty if you are
  exporting the first database.

  SQLite databases:                                                                                                                                     Export filter limits:
  <#Select a file to export the current IDA database to SQLite format#Export IDA database to SQLite  :{iFileSave}> <#Minimum address to find functions to export#From address:{iMinEA}>
  <#Select the SQLite database to diff against                       #SQLite database to diff against:{iFileOpen}> <#Maximum address to find functions to export#To address  :{iMaxEA}>

  <Use the decompiler if available:{rUseDecompiler}>
  <Do not export library and thunk functions:{rExcludeLibraryThunk}>
  <#Enable if you want neither sub_* functions nor library functions to be exported#Export only non-IDA generated functions:{rNonIdaSubs}>
  <#Export only function summaries, not all instructions. Showing differences in a graph between functions will not be available.#Do not export instructions and basic blocks:{rFuncSummariesOnly}>
  <Use probably unreliable methods:{rUnreliable}>
  <Recommended to disable with databases with more than 5.000 functions#Use slow heuristics:{rSlowHeuristics}>
  <#Enable this option if you aren't interested in small changes#Relaxed calculations of differences ratios:{rRelaxRatio}>
  <Use experimental heuristics:{rExperimental}>
  <#Enable this option to ignore sub_* names for the 'Same name' heuristic.#Ignore automatically generated names:{rIgnoreSubNames}>
  <#Enable this option to ignore all function names for the 'Same name' heuristic.#Ignore all function names:{rIgnoreAllNames}>
  <#Enable this option to ignore thunk functions, nullsubs, etc....#Ignore small functions:{rIgnoreSmallFunctions}>{cGroup1}>

  Project specific rules:
  <#Select the project specific Python script rules#Python script:{iProjectSpecificRules}>

  NOTE: Don't select IDA database files (.IDB, .I64) as only SQLite databases are considered.
"""
    args = {'iFileSave': Form.FileInput(save=True, swidth=40, hlp="SQLite database (*.sqlite)"),
            'iFileOpen': Form.FileInput(open=True, swidth=40, hlp="SQLite database (*.sqlite)"),
            'iMinEA':    Form.NumericInput(tp=Form.FT_HEX, swidth=22),
            'iMaxEA':    Form.NumericInput(tp=Form.FT_HEX, swidth=22),
            'cGroup1'  : Form.ChkGroupControl(("rUseDecompiler",
                                               "rExcludeLibraryThunk",
                                               "rUnreliable",
                                               "rNonIdaSubs",
                                               "rSlowHeuristics",
                                               "rRelaxRatio",
                                               "rExperimental",
                                               "rFuncSummariesOnly",
                                               "rIgnoreSubNames",
                                               "rIgnoreAllNames",
                                               "rIgnoreSmallFunctions")),
            'iProjectSpecificRules' : Form.FileInput(open=True, hlp="Python scripts (*.py)")}

    Form.__init__(self, s, args)

  def set_options(self, opts):
    if opts.file_out is not None:
      self.iFileSave.value = opts.file_out
    if opts.file_in is not None:
      self.iFileOpen.value = opts.file_in
    if opts.project_script is not None:
      self.iProjectSpecificRules.value = opts.project_script

    self.rUseDecompiler.checked = opts.use_decompiler
    self.rExcludeLibraryThunk.checked = opts.exclude_library_thunk
    self.rUnreliable.checked = opts.unreliable
    self.rSlowHeuristics.checked = opts.slow
    self.rRelaxRatio.checked = opts.relax
    self.rExperimental.checked = opts.experimental
    self.iMinEA.value = opts.min_ea
    self.iMaxEA.value = opts.max_ea
    self.rNonIdaSubs.checked = opts.ida_subs == False
    self.rIgnoreSubNames.checked = opts.ignore_sub_names
    self.rIgnoreAllNames.checked = opts.ignore_all_names
    self.rIgnoreSmallFunctions.checked = opts.ignore_small_functions
    self.rFuncSummariesOnly.checked = opts.func_summaries_only

  def get_options(self):
    opts = dict(
      file_out = self.iFileSave.value,
      file_in  = self.iFileOpen.value,
      use_decompiler = self.rUseDecompiler.checked,
      exclude_library_thunk = self.rExcludeLibraryThunk.checked,
      unreliable = self.rUnreliable.checked,
      slow = self.rSlowHeuristics.checked,
      relax = self.rRelaxRatio.checked,
      experimental = self.rExperimental.checked,
      min_ea = self.iMinEA.value,
      max_ea = self.iMaxEA.value,
      ida_subs = self.rNonIdaSubs.checked == False,
      ignore_sub_names = self.rIgnoreSubNames.checked,
      ignore_all_names = self.rIgnoreAllNames.checked,
      ignore_small_functions = self.rIgnoreSmallFunctions.checked,
      func_summaries_only = self.rFuncSummariesOnly.checked,
      project_script = self.iProjectSpecificRules.value
    )
    return BinDiffOptions(**opts)

#-------------------------------------------------------------------------------
class timeraction_t(object):
  def __init__(self, func, args, interval):
    self.func = func
    self.args = args
    self.interval = interval
    self.obj = idaapi.register_timer(self.interval, self)
    if self.obj is None:
      raise RuntimeError("Failed to register timer")

  def __call__(self):
    if self.args is not None:
      self.func(self.args)
    else:
      self.func()
    return -1

#-------------------------------------------------------------------------------
class uitimercallback_t(object):
  def __init__(self, g, interval):
    self.interval = interval
    self.obj = idaapi.register_timer(self.interval, self)
    if self.obj is None:
      raise RuntimeError("Failed to register timer")
    self.g = g

  def __call__(self):
    f = find_widget(self.g._title)
    activate_widget(f, 1)
    process_ui_action("GraphZoomFit", 0)
    return -1

#-------------------------------------------------------------------------------
class CDiffGraphViewer(GraphViewer):
  def __init__(self, title, g, colours):
    try:
      GraphViewer.__init__(self, title, False)
      self.graph = g[0]
      self.relations = g[1]
      self.nodes = {}
      self.colours = colours
    except:
      warning("CDiffGraphViewer: OnInit!!! " + str(sys.exc_info()[1]))

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
      print("GraphViewer Error:", sys.exc_info()[1])
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
      print("GraphViewer.OnGetText:", sys.exc_info()[1])
      return ("ERROR", 0x000000)

  def Show(self):
    return GraphViewer.Show(self)

#-------------------------------------------------------------------------------
class CIdaMenuHandlerShowChoosers(idaapi.action_handler_t):
  def __init__(self):
    idaapi.action_handler_t.__init__(self)

  def activate(self, ctx):
    show_choosers()
    return 1

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class CIdaMenuHandlerSaveResults(idaapi.action_handler_t):
  def __init__(self):
    idaapi.action_handler_t.__init__(self)

  def activate(self, ctx):
    save_results()
    return 1

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class CIdaMenuHandlerLoadResults(idaapi.action_handler_t):
  def __init__(self):
    idaapi.action_handler_t.__init__(self)

  def activate(self, ctx):
    load_results()
    return 1

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class CExternalDiffingDialog(Form):
  """Simple Form to test multilinetext and combo box controls"""
  def __init__(self):
      Form.__init__(self, r"""STARTITEM 0
BUTTON YES* Diff Pseudo-code
BUTTON NO Diff Assembler
External Diffing Tool
<#Hint1#Enter command line:{iStrCommand}>
""", {
      'iStrCommand': Form.StringInput(),
    })

#-------------------------------------------------------------------------------
class CIDABinDiff(diaphora.CBinDiff):
  def __init__(self, db_name):
    diaphora.CBinDiff.__init__(self, db_name, chooser=CIDAChooser)
    self.decompiler_available = True
    self.names = dict(Names())
    self.min_ea = get_inf_attr(INF_MIN_EA)
    self.max_ea = get_inf_attr(INF_MAX_EA)

    self.project_script = None
    self.hooks = None

  def load_hooks(self):
    if self.project_script is None or self.project_script == "":
      return True

    try:
      log("Loading project specific Python script %s" % self.project_script)
      module = imp.load_source("diaphora_hooks", self.project_script)
    except:
      print("Error loading project specific Python script: %s" % str(sys.exc_info()[1]))
      return False

    if module is None:
      # How can it be?
      return False

    keys = dir(module)
    if 'HOOKS' not in keys:
      log("Error: The project specific script doesn't export the HOOKS dictionary")
      return False

    hooks = module.HOOKS
    if 'DiaphoraHooks' not in hooks:
      log("Error: The project specific script exports the HOOK dictionary but it doesn't contain a 'DiaphoraHooks' entry.")
      return False

    hook_class = hooks["DiaphoraHooks"]
    self.hooks = hook_class(self)

    return True

  def refresh(self):
    idaapi.request_refresh(0xFFFFFFFF)

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

  def diff(self, db):
    res = diaphora.CBinDiff.diff(self, db)
    if res:
      # And, finally, show the list of best and partial matches and
      # register the hotkey for re-opening results
      self.show_choosers()
      self.register_menu()
    hide_wait_box()
    return res

  def get_last_crash_func(self):
    sql = "select address from functions order by id desc limit 1"
    cur = self.db_cursor()
    cur.execute(sql)

    row = cur.fetchone()
    if not row:
      return None

    address = int(row[0])
    cur.close()

    return address

  def recalculate_primes(self):
    sql = "select primes_value from functions"

    callgraph_primes = 1
    callgraph_all_primes = {}

    cur = self.db_cursor()
    cur.execute(sql)
    for row in cur.fetchall():
      ret = row[0]
      callgraph_primes *= decimal.Decimal(row[0])
      try:
        callgraph_all_primes[ret] += 1
      except KeyError:
        callgraph_all_primes[ret] = 1

    cur.close()
    return callgraph_primes, callgraph_all_primes

  def do_export(self, crashed_before = False):
    callgraph_primes = 1
    callgraph_all_primes = {}
    func_list = list(Functions(self.min_ea, self.max_ea))
    total_funcs = len(func_list)
    t = time.monotonic()

    if crashed_before:
      start_func = self.get_last_crash_func()
      if start_func is None:
        warning("Diaphora cannot resume the previous crashed session, the export process will start from scratch.")
        crashed_before = False
      else:
        callgraph_primes, callgraph_all_primes = self.recalculate_primes()

    self.db.commit()
    self.db.execute("PRAGMA synchronous = OFF")
    self.db.execute("PRAGMA journal_mode = MEMORY")
    self.db.execute("BEGIN transaction")
    i = 0
    for func in func_list:
      if user_cancelled():
        raise Exception("Canceled.")

      i += 1
      if (total_funcs >= 100) and i % (int(total_funcs/100)) == 0 or i == 1:
        line = "Exported %d function(s) out of %d total.\nElapsed %d:%02d:%02d second(s), remaining time ~%d:%02d:%02d"
        elapsed = time.monotonic() - t
        remaining = (elapsed / i) * (total_funcs - i)

        m, s = divmod(remaining, 60)
        h, m = divmod(m, 60)
        m_elapsed, s_elapsed = divmod(elapsed, 60)
        h_elapsed, m_elapsed = divmod(m_elapsed, 60)
        replace_wait_box(line % (i, total_funcs, h_elapsed, m_elapsed, s_elapsed, h, m, s))

      if crashed_before:
        rva = func - self.get_base_address()
        if rva != start_func:
          continue

        # When we get to the last function that was previously exported, switch
        # off the 'crash' flag and continue with the next row.
        crashed_before = False
        continue

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

      # Try to fix bug #30 and, also, try to speed up operations as
      # doing a commit every 10 functions, as before, is overkill.
      if total_funcs > 5000 and i % (total_funcs/10) == 0:
        self.db.commit()
        self.db.execute("PRAGMA synchronous = OFF")
        self.db.execute("PRAGMA journal_mode = MEMORY")
        self.db.execute("BEGIN transaction")

    md5sum = GetInputFileMD5()
    self.save_callgraph(str(callgraph_primes), json.dumps(callgraph_all_primes), md5sum)
    self.export_structures()
    self.export_til()

    replace_wait_box("Creating indexes...")
    self.create_indexes()

  def export(self):
    if self.project_script is not None:
      if not self.load_hooks():
        return False

    crashed_before = False
    crash_file = "%s-crash" % self.db_name
    if os.path.exists(crash_file):
      log("Resuming a previously crashed session...")
      crashed_before = True

    log("Creating crash file %s..." % crash_file)
    with open(crash_file, "wb") as f:
      f.close()

    try:
      show_wait_box("Exporting database")
      self.do_export(crashed_before)
    finally:
      hide_wait_box()

    self.db.commit()
    log("Removing crash file %s-crash..." % self.db_name)
    os.remove("%s-crash" % self.db_name)

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
      til = row["name"]
      if type(til) is bytes:
        til = til.decode("utf-8")

      try:
        add_default_til(til)
      except:
        log("Error loading til %s: %s" % (row["name"], str(sys.exc_info()[1])))
    cur.close()
    auto_wait()

  def import_definitions(self):
    cur = self.db_cursor()
    sql = "select type, name, value from diff.program_data where type in ('structure', 'struct', 'enum')"
    cur.execute(sql)
    rows = diaphora.result_iter(cur)

    new_rows = set()
    for row in rows:
      if row["name"] is None:
        continue

      the_name = row["name"].split(" ")[0]
      if get_struc_id(the_name) == BADADDR:
        type_name = "struct"
        if row["type"] == "enum":
          type_name = "enum"
        elif row["type"] == "union":
          type_name == "union"

        new_rows.add(row)
        line = "%s %s;" % (type_name, row["name"])
        try:
          ret = idc.parse_decls(line)
          if ret != 0:
            pass
        except:
          log("Error importing type: %s" % str(sys.exc_info()[1]))

    for _ in range(10):
      for row in new_rows:
        if row["name"] is None:
          continue

        the_name = row["name"].split(" ")[0]
        if get_struc_id(the_name) == BADADDR and get_struc_id(row["name"]) == BADADDR:
          definition = self.get_valid_definition(row["value"])
          ret = idc.parse_decls(definition) # Remove the "idc." to reproduce some strange behaviour
          if ret != 0:
            pass

    cur.close()
    auto_wait()

  def reinit(self, main_db, diff_db, create_choosers=True):
    log("Main database '%s'." % main_db)
    log("Diff database '%s'." % diff_db)

    self.__init__(main_db)
    self.attach_database(diff_db)

    if create_choosers:
      self.create_choosers()

  def import_definitions_only(self, filename):
    self.reinit(":memory:", filename)
    self.import_til()
    self.import_definitions()

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
      warning("Sorry, there is no assembly available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      html_diff = CHtmlDiff()
      asm1 = self.prettify_asm(row1["assembly"])
      asm2 = self.prettify_asm(row2["assembly"])
      buf1 = "%s proc near\n%s\n%s endp" % (row1["name"], asm1, row1["name"])
      buf2 = "%s proc near\n%s\n%s endp" % (row2["name"], asm2, row2["name"])
      
      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = False
      fmt.nobackground = True
      src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"), fmt, NasmLexer())

      title = "Diff assembler %s - %s" % (row1["name"], row2["name"])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

    cur.close()

  def import_one(self, item):
    ret = ask_yn(1, "AUTOHIDE DATABASE\nDo you want to import all the type libraries, structs and enumerations?")

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

    self.update_choosers()

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
      warning("Sorry, there is no assembly available for the selected function.")
    else:
      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = True
      asm = self.prettify_asm(row["assembly"])
      final_asm = "; %s\n%s proc near\n%s\n%s endp\n"
      final_asm = final_asm % (row["prototype"], row["name"], asm, row["name"])
      src = highlight(final_asm, NasmLexer(), fmt)
      title = "Assembly for %s" % row["name"]
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)
    cur.close()

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
    if row is None or row["prototype"] is None or row["pseudocode"] is None:
      warning("Sorry, there is no pseudo-code available for the selected function.")
    else:
      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = True
      func = "%s\n%s" % (row["prototype"], row["pseudocode"])
      src = highlight(func, CppLexer(), fmt)
      title = "Pseudo-code for %s" % row["name"]
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)
    cur.close()

  def show_pseudo_diff(self, item, html = True):
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
      warning("Sorry, there is no pseudo-code available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      html_diff = CHtmlDiff()
      proto1 = self.decompile_and_get(int(ea1))
      if proto1:
        buf1 = proto1 + "\n" + "\n".join(self.pseudo[int(ea1)])
      else:
        log("warning: cannot retrieve the current pseudo-code for the function, using the previously saved one...")
        buf1 = row1["prototype"] + "\n" + row1["pseudocode"]
      buf2 = row2["prototype"] + "\n" + row2["pseudocode"]

      if buf1 == buf2:
        warning("Both pseudo-codes are equal.")

      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = False
      fmt.nobackground = True
      if not html:
        uni_diff = difflib.unified_diff(buf2.split("\n"), buf1.split("\n"))
        tmp = []
        for line in uni_diff:
          tmp.append(line.strip("\n"))
        tmp = tmp[2:]
        buf = "\n".join(tmp)
        
        src = highlight(buf, DiffLexer(), fmt)
      else:
        src = html_diff.make_file(buf2.split("\n"), buf1.split("\n"), fmt, CppLexer())

      title = "Diff pseudo-code %s - %s" % (row2["name"], row1["name"])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

    cur.close()

  def diff_external(self, item):
    cmd_line = None
    f = CExternalDiffingDialog()
    f.Compile()
    cmd = reg_read_string("diaphora_external_command")
    if cmd == "" or cmd is None:
      cmd = "your_command $1 $2"
    f.iStrCommand.value = cmd
    ok = f.Execute()
    if ok == 0:
      cmd_line = f.iStrCommand.value
      diff_asm = True
    elif ok == 1:
      cmd_line = f.iStrCommand.value
      diff_asm = False

    f.Free()
    if cmd_line is None:
      return

    reg_write_string("diaphora_external_command", cmd_line)
    if diff_asm:
      ret = self.diff_external_asm(item, cmd_line)
    else:
      ret = self.diff_external_pseudo(item, cmd_line)
    print("External command returned", ret)

  def diff_external_asm(self, item, cmd_line):
    ret = None
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
      warning("Sorry, there is no assembly available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      asm1 = self.prettify_asm(row1["assembly"])
      asm2 = self.prettify_asm(row2["assembly"])
      buf1 = "%s proc near\n%s\n%s endp" % (row1["name"], asm1, row1["name"])
      buf2 = "%s proc near\n%s\n%s endp" % (row2["name"], asm2, row2["name"])

      filename1 = "main_%s.asm" % item[1]
      filename2 = "diff_%s.asm" % item[3]
      
      with open(filename1, "w") as f_source:
        with open(filename2, "w") as f_dest:
          f_source.writelines(buf1)
          f_dest.writelines(buf2)

      line = cmd_line.replace("$1", filename1)
      line = line.replace("$2", filename2)
      ret = os.system(line)

    cur.close()
    return ret

  def diff_external_pseudo(self, item, cmd_line):
    ret = None
    cur = self.db_cursor()
    sql = """select *
               from (
             select prototype, pseudocode, address, 1
               from functions
              where address = ?
                and pseudocode is not null
       union select prototype, pseudocode, address, 2
               from diff.functions
              where address = ?
                and pseudocode is not null)
              order by 4 asc"""
    ea1 = str(int(item[1], 16))
    ea2 = str(int(item[3], 16))
    cur.execute(sql, (ea1, ea2))
    rows = cur.fetchall()
    if len(rows) != 2:
      warning("Sorry, there is no pseudo-code available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]
      
      filename1 = "main_%s.cpp" % item[1]
      filename2 = "diff_%s.cpp" % item[3]
      
      with open(filename1, "w") as f_source:
        with open(filename2, "w") as f_dest:
          f_source.writelines("%s\n%s" % (row1["prototype"], row1["pseudocode"]))
          f_dest.writelines("%s\n%s" % (row2["prototype"],   row2["pseudocode"]))
      
      line = cmd_line.replace("$1", filename1)
      line = line.replace("$2", filename2)
      ret = os.system(line)

    cur.close()
    return ret

  def graph_diff(self, ea1, name1, ea2, name2):
    g1 = self.get_graph(str(ea1), True)
    g2 = self.get_graph(str(ea2))

    if g1 == ({}, {}) or g2 == ({}, {}):
      warning("Sorry, graph information is not available for one of the databases.")
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

  def import_instruction(self, ins_data1, ins_data2):
    ea1 = self.get_base_address() + int(ins_data1[0])
    ea2, cmt1, cmt2, name, mtype, mdis, mcmt, mitp = ins_data2
    # Set instruction level comments
    if cmt1 is not None and get_cmt(ea1, 0) is None:
      set_cmt(ea1, cmt1, 0)

    if cmt2 is not None and get_cmt(ea1, 1) is None:
      set_cmt(ea1, cmt2, 1)

    if mcmt is not None:
      cfunc = decompile(ea1)
      if cfunc is not None:
        tl = idaapi.treeloc_t()
        tl.ea = ea1
        tl.itp = mitp
        comment = mcmt
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()

    tmp_ea = None
    set_type = False
    data_refs = list(DataRefsFrom(ea1))
    if len(data_refs) > 0:
      # Global variables
      tmp_ea = data_refs[0]
      if tmp_ea in self.names:
        curr_name = get_ea_name(tmp_ea)
        if curr_name != name and self.is_auto_generated(curr_name):
          set_name(tmp_ea, name, SN_CHECK)
          set_type = False
      else:
        # If it's an object, we don't want to rename the offset, we want to
        # rename the true global variable.
        if is_off(get_full_flags(tmp_ea), OPND_ALL):
          tmp_ea = next(DataRefsFrom(tmp_ea), tmp_ea)

        set_name(tmp_ea, name, SN_CHECK)
        set_type = True
    else:
      # Functions
      code_refs = list(CodeRefsFrom(ea1, 0))
      if len(code_refs) == 0:
        code_refs = list(CodeRefsFrom(ea1, 1))

      if len(code_refs) > 0:
        curr_name = get_ea_name(code_refs[0])
        if curr_name != name and self.is_auto_generated(curr_name):
          set_name(code_refs[0], name, SN_CHECK)
          tmp_ea = code_refs[0]
          set_type = True

    if tmp_ea is not None and set_type:
      if mtype is not None and idc.get_type(tmp_ea) != mtype:
        if type(mtype) is bytes:
          mtype = mtype.decode("utf-8")
        SetType(tmp_ea, mtype)

  def row_is_importable(self, ea2, import_syms):
    ea = str(ea2)
    if not ea in import_syms:
      return False

    # Has cmt1
    if import_syms[ea][1] is not None:
      return True

    # Has cmt2
    if import_syms[ea][2] is not None:
      return True

    # Has a name
    if import_syms[ea][3] is not None:
      return True

    # Has pseudocode comment
    if import_syms[ea][6] is not None:
      return True

    return False

  def import_instruction_level(self, ea1, ea2, cur):
    cur = self.db_cursor()
    try:
      # Check first if we have any importable items
      sql = """ select ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.name name, ins.type type, ins.pseudocomment cmt, ins.pseudoitp itp
                  from diff.function_bblocks bb,
                       diff.functions f,
                       diff.bb_instructions bbi,
                       diff.instructions ins
                 where f.id = bb.function_id
                   and bbi.basic_block_id = bb.basic_block_id
                   and ins.id = bbi.instruction_id
                   and f.address = ?
                   and (ins.comment1 is not null
                     or ins.comment2 is not null
                     or ins.name is not null
                     or pseudocomment is not null) """
      cur.execute(sql, (str(ea2),))
      import_rows = cur.fetchall()
      if len(import_rows) > 0:
        import_syms = {}
        for row in import_rows:
          import_syms[row["ea"]] = [row["ea"], row["cmt1"], row["cmt2"], row["name"], row["type"], row["dis"], row["cmt"], row["itp"]]

        # Check in the current database
        sql = """ select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.name name, ins.type type, ins.pseudocomment cmt, ins.pseudoitp itp
                    from function_bblocks bb,
                         functions f,
                         bb_instructions bbi,
                         instructions ins
                   where f.id = bb.function_id
                     and bbi.basic_block_id = bb.basic_block_id
                     and ins.id = bbi.instruction_id
                     and f.address = ?"""
        cur.execute(sql, (str(ea1),))
        match_rows = cur.fetchall()
        if len(match_rows) > 0:
          matched_syms = {}
          for row in match_rows:
            matched_syms[row["ea"]] = [row["ea"], row["cmt1"], row["cmt2"], row["name"], row["type"], row["dis"], row["cmt"], row["itp"]]

          # We have 'something' to import, let's diff the assembly...
          sql = """select *
                     from (
                   select assembly, assembly_addrs, 1
                     from functions
                    where address = ?
                      and assembly is not null
             union select assembly, assembly_addrs, 2
                     from diff.functions
                    where address = ?
                      and assembly is not null)
                    order by 2 asc"""
          cur.execute(sql, (str(ea1), str(ea2)))
          diff_rows = cur.fetchall()
          if len(diff_rows) > 0:
            lines1 = diff_rows[0]["assembly"]
            lines2 = diff_rows[1]["assembly"]

            address1 = json.loads(diff_rows[0]["assembly_addrs"])
            address2 = json.loads(diff_rows[1]["assembly_addrs"])

            diff_list = difflib._mdiff(lines1.splitlines(1), lines2.splitlines(1))
            for x in diff_list:
              left, right, ignore = x
              left_line  = left[0]
              right_line = right[0]

              if right_line == "" or left_line == "":
                continue

              # At this point, we know which line number matches with
              # which another line number in both databases.
              ea1 = address1[int(left_line)-1]
              ea2 = address2[int(right_line)-1]
              changed = left[1].startswith('\x00-') and right[1].startswith('\x00+')
              is_importable = self.row_is_importable(ea2, import_syms)
              if changed or is_importable:
                ea1 = str(ea1)
                ea2 = str(ea2)
                if ea1 in matched_syms and ea2 in import_syms:
                  self.import_instruction(matched_syms[ea1], import_syms[ea2])
                if ea2 in matched_syms and ea1 in import_syms:
                  self.import_instruction(matched_syms[ea2], import_syms[ea1])
    finally:
      cur.close()

  def do_import_one(self, ea1, ea2, force = False):
    cur = self.db_cursor()
    sql = "select prototype, comment, mangled_function, function_flags from diff.functions where address = ?"
    cur.execute(sql, (str(ea2),))
    row = cur.fetchone()
    if row is not None:
      proto = row["prototype"]
      comment = row["comment"]
      name = row["mangled_function"]
      flags = row["function_flags"]

      ea1 = int(ea1)
      if not name.startswith("sub_") or force:
        if not set_name(ea1, name, SN_NOWARN|SN_NOCHECK):
          for i in range(10):
            if set_name(ea1, "%s_%d" % (name, i), SN_NOWARN|SN_NOCHECK):
              break

      if proto is not None and proto != "int()":
        SetType(ea1, proto)

      if comment is not None and comment != "":
        func = get_func(ea1)
        if func is not None:
          set_func_cmt(func, comment, 1)

      if flags is not None:
        set_func_attr(ea1, FUNCATTR_FLAGS, flags)

      self.import_instruction_level(ea1, ea2, cur)

    cur.close()

  def import_selected(self, items, selected, only_auto):
    # Import all the type libraries from the diff database
    self.import_til()
    # Import all the struct and enum definitions
    self.import_definitions()

    new_items = []
    for index in selected:
      item = items[index]
      name1 = item[2]
      if not only_auto or name1.startswith("sub_"):
        new_items.append(item)
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
      total = 0
      for ea in to_import:
        ea = str(ea)
        new_func = self.read_function(ea)
        self.delete_function(ea)
        self.save_function(new_func)
        total += 1
      self.db.commit()

      # Update the choosers after importing
      self.update_choosers()
    finally:
      hide_wait_box()

  def update_choosers(self):
    for chooser in [self.best_chooser, self.partial_chooser, self.unreliable_chooser]:
      for i, item in enumerate(chooser.items):
        ea = int(item[1], 16)
        name = item[2]
        func_name = get_func_name(ea)
        if func_name is not None and func_name != "" and func_name != name:
          chooser.items[i][2] = func_name
      chooser.Refresh()

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

  def import_all(self, items):
    try:
      self.do_import_all(items)
    except:
      log("import_all(): %s" % str(sys.exc_info()[1]))
      traceback.print_exc()

  def import_all_auto(self, items):
    try:
      self.do_import_all_auto(items)
    except:
      log("import_all(): %s" % str(sys.exc_info()[1]))
      traceback.print_exc()

  def do_decompile(self, f):
    if IDA_SDK_VERSION >= 730:
      return decompile(f, flags=DECOMP_NO_WAIT)
    return decompile(f)

  def decompile_and_get(self, ea):
    if not self.decompiler_available or is_spec_ea(ea):
      return False

    decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
    if decompiler_plugin is None:
      decompiler_plugin = "hexrays"
    if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
      self.decompiler_available = False
      return False

    f = get_func(ea)
    if f is None:
      return False

    cfunc = self.do_decompile(f)
    if cfunc is None:
      # Failed to decompile
      return False

    visitor = CAstVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)
    self.pseudo_hash[ea] = visitor.primes_hash

    cmts = idaapi.restore_user_cmts(cfunc.entry_ea)
    if cmts is not None:
      for tl, cmt in cmts.items():
        self.pseudo_comments[tl.ea - self.get_base_address()] = [str(cmt), tl.itp]

    sv = cfunc.get_pseudocode()
    self.pseudo[ea] = []
    first_line = None
    for sline in sv:
      line = tag_remove(sline.line)
      if line.startswith("//"):
        continue

      if first_line is None:
        first_line = line
      else:
        self.pseudo[ea].append(line)
    return first_line

  def guess_type(self, ea):
    t = guess_type(ea)
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

  def register_menu_action(self, action_name, action_desc, handler, hotkey = None):
    show_choosers_action = idaapi.action_desc_t(
      action_name,
      action_desc,
      handler,
      hotkey,
      None,
      -1)
    idaapi.register_action(show_choosers_action)
    idaapi.attach_action_to_menu(
        'Edit/Plugins/%s' % action_desc,
        action_name,
        idaapi.SETMENU_APP)

  def register_menu(self):
    global g_bindiff
    g_bindiff = self

    menu_items = [
      ['diaphora:show_results', 'Diaphora - Show results', CIdaMenuHandlerShowChoosers(), "F3"],
      ['diaphora:save_results', 'Diaphora - Save results', CIdaMenuHandlerSaveResults(), None],
      ['diaphora:load_results', 'Diaphora - Load results', CIdaMenuHandlerLoadResults(), None]
    ]
    for item in menu_items:
      action_name, action_desc, action_handler, hotkey = item
      self.register_menu_action(action_name, action_desc, action_handler, hotkey)

    warning("""AUTOHIDE REGISTRY\nIf you close one tab you can always re-open it by pressing F3
or selecting Edit -> Plugins -> Diaphora - Show results""")

  # Ripped out from REgoogle
  def constant_filter(self, value):
    """Filter for certain constants/immediate values. Not all values should be
    taken into account for searching. Especially not very small values that
    may just contain the stack frame size.

    @param value: constant value
    @type value: int
    @return: C{True} if value should be included in query. C{False} otherwise
    """
    # no small values
    if value < 0x1000:
      return False

    if value & 0xFFFFFF00 == 0xFFFFFF00 or value & 0xFFFF00 == 0xFFFF00 or \
       value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00 or \
       value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
      return False

    #no single bits sets - mostly defines / flags
    for i in range(64):
      if value == (1 << i):
        return False

    return True

  def is_constant(self, oper, ea):
    value = oper.value
    # make sure, its not a reference but really constant
    if value in DataRefsFrom(ea):
      return False

    return True

  def get_disasm(self, ea):
    mnem = print_insn_mnem(ea)
    op1  = print_operand(ea, 0)
    op2  = print_operand(ea, 1)
    line = "%s %s" % (mnem.ljust(8), op1)
    if op2 != "":
      line += ", %s" % op2
    return line

  def read_function(self, f, discard=False):
    name = get_func_name(int(f))
    true_name = name
    demangle_named_name = demangle_name(name, INF_SHORT_DN)
    if demangle_named_name == "":
      demangle_named_name = None

    if demangle_named_name is not None:
      name = demangle_named_name

    if self.hooks is not None:
      if 'before_export_function' in dir(self.hooks):
        ret = self.hooks.before_export_function(f, name)
        if not ret:
          return False

    f = int(f)
    func = get_func(f)
    if not func:
      log("Cannot get a function object for 0x%x" % f)
      return False

    flow = FlowChart(func)
    size = 0

    if not self.ida_subs:
      # Unnamed function, ignore it...
      if name.startswith("sub_") or name.startswith("j_") or name.startswith("unknown") or name.startswith("nullsub_"):
        return False

      # Already recognized runtime's function?
      flags = get_func_attr(f, FUNCATTR_FLAGS)
      if flags & FUNC_LIB or flags == -1:
        return False

    if self.exclude_library_thunk:
      # Skip library and thunk functions
      flags = get_func_attr(f, FUNCATTR_FLAGS)
      if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
        return False

    image_base = self.get_base_address()
    nodes = 0
    edges = 0
    instructions = 0
    mnems = []
    dones = {}
    names = set()
    bytes_hash = []
    bytes_sum = 0
    function_hash = []
    outdegree = 0
    indegree = len(list(CodeRefsTo(f, 1)))
    assembly = {}
    basic_blocks_data = {}
    bb_relations = {}
    bb_topo_num = {}
    bb_topological = {}
    switches = []
    bb_degree = {}
    bb_edges = []
    constants = []

    # The callees will be calculated later
    callees = list()
    # Calculate the callers
    callers = list()
    for caller in list(CodeRefsTo(f, 0)):
      caller_func = get_func(caller)
      if caller_func and caller_func.start_ea not in callers:
        callers.append(caller_func.start_ea)

    mnemonics_spp = 1
    cpu_ins_list = GetInstructionList()
    cpu_ins_list.sort()

    for block in flow:
      if block.end_ea == 0 or block.end_ea == BADADDR:
        print(("0x%08x: Skipping bad basic block" % f))
        continue

      nodes += 1
      instructions_data = []

      block_ea = block.start_ea - image_base
      idx = len(bb_topological)
      bb_topological[idx] = []
      bb_topo_num[block_ea] = idx

      for x in list(Heads(block.start_ea, block.end_ea)):
        mnem = print_insn_mnem(x)
        try:
          disasm = GetDisasm(x)
        except UnicodeDecodeError:
          # This is a workaround for a rare error getting the disassembly for a
          # line with some UTF-8 characters that Python fails to handle properly
          disasm = self.get_disasm(x)

        size += get_item_size(x)
        instructions += 1

        if mnem in cpu_ins_list:
          mnemonics_spp *= self.primes[cpu_ins_list.index(mnem)]

        try:
          assembly[block_ea].append([x - image_base, disasm])
        except KeyError:
          if nodes == 1:
            assembly[block_ea] = [[x - image_base, disasm]]
          else:
            assembly[block_ea] = [[x - image_base, "loc_%x:" % x], [x - image_base, disasm]]

        decoded_size, ins = diaphora_decode(x)
        if ins.ops[0].type in [o_mem, o_imm, o_far, o_near, o_displ]:
          decoded_size -= ins.ops[0].offb
        if ins.ops[1].type in [o_mem, o_imm, o_far, o_near, o_displ]:
          decoded_size -= ins.ops[1].offb
        if decoded_size <= 0:
          decoded_size = 1

        for oper in ins.ops:
          if oper.type == o_imm:
            if self.is_constant(oper, x) and self.constant_filter(oper.value):
              constants.append(oper.value)

          drefs = list(DataRefsFrom(x))
          if len(drefs) > 0:
            for dref in drefs:
              if get_func(dref) is None:
                str_constant = get_strlit_contents(dref, -1, -1)
                if str_constant is not None:
                  str_constant = str_constant.decode("utf-8", "backslashreplace")
                  if str_constant not in constants:
                    constants.append(str_constant)

        curr_bytes = get_bytes(x, decoded_size, False)
        if curr_bytes is None or len(curr_bytes) != decoded_size:
          log("Failed to read %d bytes at [%08x]" % (decoded_size, x))
          continue

        bytes_hash.append(curr_bytes)
        bytes_sum += sum(curr_bytes)

        function_hash.append(get_bytes(x, get_item_size(x), False))
        outdegree += len(list(CodeRefsFrom(x, 0)))
        mnems.append(mnem)
        op_value = get_operand_value(x, 1)
        if op_value == -1:
          op_value = get_operand_value(x, 0)

        tmp_name = None
        if op_value != BADADDR and op_value in self.names:
          tmp_name = self.names[op_value]
          demangle_named_name = demangle_name(tmp_name, INF_SHORT_DN)
          if demangle_named_name is not None:
            tmp_name = demangle_named_name
            pos = tmp_name.find("(")
            if pos > -1:
              tmp_name = tmp_name[:pos]

          if not tmp_name.startswith("sub_") and not tmp_name.startswith("nullsub_"):
            names.add(tmp_name)

        # Calculate the callees
        l = list(CodeRefsFrom(x, 0))
        for callee in l:
          callee_func = get_func(callee)
          if callee_func and callee_func.start_ea != func.start_ea:
            if callee_func.start_ea not in callees:
              callees.append(callee_func.start_ea)

        if len(l) == 0:
          l = DataRefsFrom(x)

        tmp_type = None
        for ref in l:
          if ref in self.names:
            tmp_name = self.names[ref]
            tmp_type = idc.get_type(ref)

        ins_cmt1 = GetCommentEx(x, 0)
        ins_cmt2 = GetCommentEx(x, 1)
        instructions_data.append([x - image_base, mnem, disasm, ins_cmt1, ins_cmt2, tmp_name, tmp_type])

        switch = get_switch_info(x)
        if switch:
          switch_cases = switch.get_jtable_size()
          results = calc_switch_cases(x, switch)

          if results is not None:
            # It seems that IDAPython for idaq64 has some bug when reading
            # switch's cases. Do not attempt to read them if the 'cur_case'
            # returned object is not iterable.
            can_iter = False
            switch_cases_values = set()
            for idx in range(len(results.cases)):
              cur_case = results.cases[idx]
              if not '__iter__' in dir(cur_case):
                break

              can_iter |= True
              for cidx in range(len(cur_case)):
                case_id = cur_case[cidx]
                switch_cases_values.add(case_id)

            if can_iter:
              switches.append([switch_cases, list(switch_cases_values)])

      basic_blocks_data[block_ea] = instructions_data
      bb_relations[block_ea] = []
      if block_ea not in bb_degree:
        # bb in degree, out degree
        bb_degree[block_ea] = [0, 0]

      for succ_block in block.succs():
        if succ_block.end_ea == 0:
          continue

        succ_base = succ_block.start_ea - image_base
        bb_relations[block_ea].append(succ_base)
        bb_degree[block_ea][1] += 1
        bb_edges.append((block_ea, succ_base))
        if succ_base not in bb_degree:
          bb_degree[succ_base] = [0, 0]
        bb_degree[succ_base][0] += 1

        edges += 1
        indegree += 1
        if succ_block.id not in dones:
          dones[succ_block] = 1

      for pred_block in block.preds():
        if pred_block.end_ea == 0:
          continue

        try:
          bb_relations[pred_block.start_ea - image_base].append(block.start_ea - image_base)
        except KeyError:
          bb_relations[pred_block.start_ea - image_base] = [block.start_ea - image_base]

        edges += 1
        outdegree += 1
        if pred_block.id not in dones:
          dones[pred_block] = 1

    for block in flow:
      if block.end_ea == 0:
        continue

      block_ea = block.start_ea - image_base
      for succ_block in block.succs():
        if succ_block.end_ea == 0:
          continue

        succ_base = succ_block.start_ea - image_base
        bb_topological[bb_topo_num[block_ea]].append(bb_topo_num[succ_base])

    strongly_connected_spp = 0

    try:
      strongly_connected = strongly_connected_components(bb_relations)
      bb_topological_sorted = robust_topological_sort(bb_topological)
      bb_topological = json.dumps(bb_topological_sorted)
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

    asm = []
    keys = list(assembly.keys())
    keys.sort()

    # Collect the ordered list of addresses, as shown in the assembly
    # viewer (when diffing). It will be extremely useful for importing
    # stuff later on.
    assembly_addrs = []

    # After sorting our the addresses of basic blocks, be sure that the
    # very first address is always the entry point, no matter at what
    # address it is.
    keys.remove(f - image_base)
    keys.insert(0, f - image_base)
    for key in keys:
      for line in assembly[key]:
        assembly_addrs.append(line[0])
        asm.append(line[1])
    asm = "\n".join(asm)

    cc = edges - nodes + 2
    proto = self.guess_type(f)
    proto2 = idc.get_type(f)
    try:
      prime = str(self.primes[cc])
    except:
      log("Cyclomatic complexity too big: 0x%x -> %d" % (f, cc))
      prime = 0

    comment = idc.get_func_cmt(f, 1)
    bytes_hash = md5(b"".join(bytes_hash)).hexdigest()
    function_hash = md5(b"".join(function_hash)).hexdigest()

    function_flags = get_func_attr(f, FUNCATTR_FLAGS)
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

    try:
      clean_assembly = self.get_cmp_asm_lines(asm)
    except:
      clean_assembly = ""
      print("Error getting assembly for 0x%x" % f)

    clean_pseudo = self.get_cmp_pseudo_lines(pseudo)

    md_index = 0
    if bb_topological:
      bb_topo_order = {}
      for i, scc in enumerate(bb_topological_sorted):
        for bb in scc:
          bb_topo_order[bb] = i
      tuples = []
      for src, dst in bb_edges:
        tuples.append((
            bb_topo_order[bb_topo_num[src]],
            bb_degree[src][0],
            bb_degree[src][1],
            bb_degree[dst][0],
            bb_degree[dst][1],))
      rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
      emb_tuples = (sum((z0, z1 * rt2, z2 * rt3, z3 * rt5, z4 * rt7))
              for z0, z1, z2, z3, z4 in tuples)
      md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
      md_index = str(md_index)

    seg_rva = x - get_segm_start(x)

    kgh = CKoretKaramitasHash()
    kgh_hash = kgh.calculate(f)

    rva = f - self.get_base_address()
    l = (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
             proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
             pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
             pseudo_hash2, pseudo_hash3, len(strongly_connected), loops, rva, bb_topological,
             strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches,
             function_hash, bytes_sum, md_index, constants, len(constants), seg_rva,
             assembly_addrs, kgh_hash, None,
             callers, callees,
             basic_blocks_data, bb_relations)

    if self.hooks is not None:
      if 'after_export_function' in dir(self.hooks):
        d = self.create_function_dictionary(l)
        d = self.hooks.after_export_function(d)
        l = self.get_function_from_dictionary(d)

    return l

  def get_function_from_dictionary(self, d):
    l = (
      d["name"],
      d["nodes"],
      d["edges"],
      d["indegree"],
      d["outdegree"],
      d["size"],
      d["instructions"],
      d["mnems"],
      d["names"],
      d["proto"],
      d["cc"],
      d["prime"],
      d["f"],
      d["comment"],
      d["true_name"],
      d["bytes_hash"],
      d["pseudo"],
      d["pseudo_lines"],
      d["pseudo_hash1"],
      d["pseudocode_primes"],
      d["function_flags"],
      d["asm"],
      d["proto2"],
      d["pseudo_hash2"],
      d["pseudo_hash3"],
      d["strongly_connected_size"],
      d["loops"],
      d["rva"],
      d["bb_topological"],
      d["strongly_connected_spp"],
      d["clean_assembly"],
      d["clean_pseudo"],
      d["mnemonics_spp"],
      d["switches"],
      d["function_hash"],
      d["bytes_sum"],
      d["md_index"],
      d["constants"],
      d["constants_size"],
      d["seg_rva"],
      d["assembly_addrs"],
      d["kgh_hash"],
      d["userdata"],
      d["callers"],
      d["callees"],
      d["basic_blocks_data"],
      d["bb_relations"])
    return l

  def create_function_dictionary(self, l):
    (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
    proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
    pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
    pseudo_hash2, pseudo_hash3, strongly_connected_size, loops, rva, bb_topological,
    strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches,
    function_hash, bytes_sum, md_index, constants, constants_size, seg_rva,
    assembly_addrs, kgh_hash, userdata, callers, callees, basic_blocks_data,
    bb_relations) = l
    d = dict(
          name = name,
          nodes = nodes,
          edges = edges,
          indegree = indegree,
          outdegree = outdegree,
          size = size,
          instructions = instructions,
          mnems = mnems,
          names = names,
          proto = proto,
          cc = cc,
          prime = prime,
          f = f,
          comment = comment,
          true_name = true_name,
          bytes_hash = bytes_hash,
          pseudo = pseudo,
          pseudo_lines = pseudo_lines,
          pseudo_hash1 = pseudo_hash1,
          pseudocode_primes = pseudocode_primes,
          function_flags = function_flags,
          asm = asm,
          proto2 = proto2,
          pseudo_hash2 = pseudo_hash2,
          pseudo_hash3 = pseudo_hash3,
          strongly_connected_size = strongly_connected_size,
          loops = loops,
          rva = rva,
          bb_topological = bb_topological,
          strongly_connected_spp = strongly_connected_spp,
          clean_assembly = clean_assembly,
          clean_pseudo = clean_pseudo,
          mnemonics_spp = mnemonics_spp,
          switches = switches,
          function_hash = function_hash,
          bytes_sum = bytes_sum,
          md_index = md_index,
          constants = constants,
          constants_size = constants_size,
          seg_rva = seg_rva,
          assembly_addrs = assembly_addrs,
          kgh_hash = kgh_hash,
          callers = callers,
          callees = callees,
          basic_blocks_data = basic_blocks_data,
          bb_relations = bb_relations,
          userdata = userdata)
    return d

  def get_base_address(self):
    return idaapi.get_imagebase()

  def save_callgraph(self, primes, all_primes, md5sum):
    cur = self.db_cursor()
    sql = "insert into main.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)"
    proc = idaapi.get_idp_name()
    if BADADDR == 0xFFFFFFFFFFFFFFFF:
      proc += "64"
    cur.execute(sql, (primes, all_primes, proc, md5sum))
    cur.close()

  def GetLocalType(self, ordinal, flags):
    ret = get_local_tinfo(ordinal)
    if ret is not None:
      (stype, fields) = ret
      if stype:
        name = idc.get_numbered_type_name(ordinal)
        try:
          return idc_print_type(stype, fields, name, flags)
        except:
          log("Error: %s" % str(sys.exc_info()[1]))
          return ""
    return ""

  def export_structures(self):
    # It seems that get_ordinal_qty, sometimes, can return negative
    # numbers, according to one beta-tester. My guess is that it's a bug
    # in IDA. However, as we cannot reproduce, at least handle this
    # condition.
    local_types = idc.get_ordinal_qty()
    if (local_types & 0x80000000) != 0:
      log("warning: get_ordinal_qty returned a negative number (0x%x)!" % local_types)
      return

    for i in range(local_types):
      name = idc.get_numbered_type_name(i+1)
      definition = self.GetLocalType(i+1, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI | PRTYPE_PRAGMA)
      if definition is None:
        continue

      type_name = "struct"
      if definition.startswith("enum"):
        type_name = "enum"
      elif definition.startswith("union"):
        type_name = "union"

      # For some reason, IDA my return types with the form "__int128 unsigned",
      # we want it the right way "unsigned __int128".
      if name and name.find(" ") > -1:
        names = name.split(" ")
        name = names[0]
        if names[1] == "unsigned":
          name = "unsigned %s" % name

      self.add_program_data(type_name, name, definition)

  def get_til_names(self):
    idb_path = get_idb_path()
    filename, ext = os.path.splitext(idb_path)
    til_path = "%s.til" % filename

    with open(til_path, "rb") as f:
      line = f.readline()
      pos = line.find(b"Local type definitions")
      if pos > -1:
        tmp = line[pos+len(b"Local type definitions")+1:]
        pos = tmp.find(b"\x00")
        if pos > -1:
          defs = tmp[:pos].split(b",")
          return defs
    return None

  def export_til(self):
    til_names = self.get_til_names()
    if til_names is not None:
      for til in til_names:
        self.add_program_data("til", til, None)


  def load_and_import_all_results(self, filename, main_db, diff_db):
    results_db = sqlite3.connect(filename, check_same_thread=False)
    results_db.text_factory = str
    results_db.row_factory = sqlite3.Row

    cur = results_db.cursor()
    try:
      sql = "select main_db, diff_db, version from config"
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) != 1:
        Warning("Malformed results database!")
        return False

      row = rows[0]
      version = row["version"]
      if version != diaphora.VERSION_VALUE:
        msg = "The version of the diff results is %s and current version is %s, there can be some incompatibilities."
        Warning(msg % (version, diaphora.VERSION_VALUE))

      self.reinit(main_db, diff_db)

      min_ratio = float(self.get_value_for("MINIMUM_IMPORT_RATIO", 0.5))
      log("Minimum import threshold %f" % min_ratio)

      sql = "select * from results"
      cur.execute(sql)
      for row in diaphora.result_iter(cur):
        if row["type"] == "best":
          choose = self.best_chooser
        elif row["type"] == "partial":
          choose = self.partial_chooser
        else:
          choose = self.unreliable_chooser

        ea1 = int(row["address"], 16)
        name1 = row["name"]
        ea2 = int(row["address2"], 16)
        name2 = row["name2"]
        desc = row["description"]
        ratio = float(row["ratio"])

        if ratio < min_ratio:
          log("Match %s-%s is excluded" % (name1, name2))
          continue

        bb1 = int(row["bb1"])
        bb2 = int(row["bb2"])

        choose.add_item(diaphora.CChooser.Item(ea1, name1, ea2, name2, desc, ratio, bb1, bb2))

      sql = "select * from unmatched"
      cur.execute(sql)
      for row in diaphora.result_iter(cur):
        if row["type"] == "primary":
          choose = self.unmatched_primary
        else:
          choose = self.unmatched_second
        choose.add_item(diaphora.CChooser.Item(int(row["address"], 16), row["name"]))

      self.import_all_auto(self.best_chooser.items)
      self.import_all_auto(self.partial_chooser.items)

      return True
    finally:
      cur.close()
      results_db.close()

    return False

  def load_results(self, filename):
    results_db = sqlite3.connect(filename, check_same_thread=False)
    results_db.text_factory = str
    results_db.row_factory = sqlite3.Row

    cur = results_db.cursor()
    try:
      sql = "select main_db, diff_db, version from config"
      cur.execute(sql)
      rows = cur.fetchall()
      if len(rows) != 1:
        warning("Malformed results database!")
        msg("Malformed results database!")
        return False

      row = rows[0]
      version = row["version"]
      if version != diaphora.VERSION_VALUE:
        line = "The version of the diff results is %s and current version is %s, there can be some incompatibilities."
        warning(line % (version, diaphora.VERSION_VALUE))
        msg(line)

      main_db = row["main_db"]
      diff_db = row["diff_db"]
      if not os.path.exists(main_db):
        log("Primary database %s not found." % main_db)
        main_db = ask_file(0, main_db, "Select the primary database path")
        if main_db is None:
          return False

      if not os.path.exists(diff_db):
        diff_db = ask_file(0, main_db, "Select the secondary database path")
        if diff_db is None:
          return False

      self.reinit(main_db, diff_db)

      sql = "select * from results"
      cur.execute(sql)
      for row in diaphora.result_iter(cur):
        if row["type"] == "best":
          choose = self.best_chooser
        elif row["type"] == "partial":
          choose = self.partial_chooser
        else:
          choose = self.unreliable_chooser

        ea1 = int(row["address"], 16)
        name1 = row["name"]
        ea2 = int(row["address2"], 16)
        name2 = row["name2"]
        desc = row["description"]
        ratio = float(row["ratio"])
        bb1 = int(row["bb1"])
        bb2 = int(row["bb2"])

        choose.add_item(diaphora.CChooser.Item(ea1, name1, ea2, name2, desc, ratio, bb1, bb2))

      sql = "select * from unmatched"
      cur.execute(sql)
      for row in diaphora.result_iter(cur):
        if row["type"] == "primary":
          choose = self.unmatched_primary
        else:
          choose = self.unmatched_second
        choose.add_item(diaphora.CChooser.Item(int(row["address"], 16), row["name"]))

      log("Showing diff results.")
      self.show_choosers()
      return True
    finally:
      cur.close()
      results_db.close()

    return False

  def re_diff(self):
    self.best_chooser.Close()
    self.partial_chooser.Close()
    if self.unreliable_chooser is not None:
      self.unreliable_chooser.Close()
    if self.unmatched_primary is not None:
      self.unmatched_primary.Close()
    if self.unmatched_second is not None:
      self.unmatched_second.Close()

    _diff_or_export(use_ui=True, file_in=self.last_diff_db,
                                 project_script = self.project_script)

  def equal_db(self):
    are_equal = diaphora.CBinDiff.equal_db(self)
    if are_equal:
      if ask_yn(0, "HIDECANCEL\nThe databases seems to be 100% equal. Do you want to continue anyway?") != 1:
        self.do_continue = False
    return are_equal

#-------------------------------------------------------------------------------
def _diff_or_export(use_ui, **options):
  global g_bindiff

  total_functions = len(list(Functions()))
  if get_idb_path() == "" or total_functions == 0:
    warning("No IDA database opened or no function in the database.\nPlease open an IDA database and create some functions before running this script.")
    return

  opts = BinDiffOptions(**options)

  if use_ui:
    x = CBinDiffExporterSetup()
    x.Compile()
    x.set_options(opts)

    if not x.Execute():
      return

    opts = x.get_options()

  if opts.file_out == opts.file_in:
    warning("Both databases are the same file!")
    return
  elif opts.file_out == "" or len(opts.file_out) < 5:
    warning("No output database selected or invalid filename. Please select a database file.")
    return
  elif is_ida_file(opts.file_in) or is_ida_file(opts.file_out):
    warning("One of the selected databases is an IDA file. Please select only database files")
    return

  export = True
  if os.path.exists(opts.file_out):
    crash_file = "%s-crash" % opts.file_out
    resume_crashed = False
    crashed_before = False
    if os.path.exists(crash_file):
      crashed_before = True
      ret = ask_yn(1, "The previous export session crashed. Do you want to resume the previous crashed session?")
      if ret == -1:
        log("Cancelled")
        return
      elif ret == 1:
        resume_crashed = True

    if not resume_crashed and not crashed_before:
      ret = ask_yn(0, "Export database already exists. Do you want to overwrite it?")
      if ret == -1:
        log("Cancelled")
        return

      if ret == 0:
        export = False

    if export:
      if g_bindiff is not None:
        g_bindiff = None

      if not resume_crashed:
        remove_file(opts.file_out)
        log("Database %s removed" % repr(opts.file_out))
        if os.path.exists(crash_file):
          os.remove(crash_file)

  t0 = time.monotonic()
  try:
    bd = CIDABinDiff(opts.file_out)
    bd.use_decompiler_always = opts.use_decompiler
    bd.exclude_library_thunk = opts.exclude_library_thunk
    bd.unreliable = opts.unreliable
    bd.slow_heuristics = opts.slow
    bd.relaxed_ratio = opts.relax
    bd.experimental = opts.experimental
    bd.min_ea = opts.min_ea
    bd.max_ea = opts.max_ea
    bd.ida_subs = opts.ida_subs
    bd.ignore_sub_names = opts.ignore_sub_names
    bd.ignore_all_names = opts.ignore_all_names
    bd.ignore_small_functions = opts.ignore_small_functions
    bd.function_summaries_only = opts.func_summaries_only
    bd.max_processed_rows = diaphora.MAX_PROCESSED_ROWS * max(total_functions / 20000, 1)
    bd.timeout = diaphora.TIMEOUT_LIMIT * max(total_functions / 20000, 1)
    bd.project_script = opts.project_script

    if export:
      exported = False
      if os.getenv("DIAPHORA_PROFILE") is not None:
        log("*** Profiling export ***")
        import cProfile
        profiler = cProfile.Profile()
        profiler.runcall(bd.export)
        exported = True
        profiler.print_stats(sort="time")
      else:
        try:
          bd.export()
          exported = True
        except KeyboardInterrupt:
          log("Aborted by user, removing crash file %s-crash..." % opts.file_out)
          os.remove("%s-crash" % opts.file_out)

      if exported:
        log("Database exported. Took {} seconds.".format(time.monotonic() - t0))
        hide_wait_box()

    if opts.file_in != "":
      if os.getenv("DIAPHORA_PROFILE") is not None:
        log("*** Profiling diff ***")
        import cProfile
        profiler = cProfile.Profile()
        profiler.runcall(bd.diff, opts.file_in)
        profiler.print_stats(sort="time")
      else:
        bd.diff(opts.file_in)
  except:
    print(("Error: %s" % sys.exc_info()[1]))
    traceback.print_exc()

  return bd

#-------------------------------------------------------------------------------
class BinDiffOptions:
  def __init__(self, **kwargs):
    total_functions = len(list(Functions()))
    sqlite_db = os.path.splitext(get_idb_path())[0] + ".sqlite"
    self.file_out = kwargs.get('file_out', sqlite_db)
    self.file_in  = kwargs.get('file_in', '')
    self.use_decompiler = kwargs.get('use_decompiler', True)
    self.exclude_library_thunk = kwargs.get('exclude_library_thunk', True)

    self.relax = kwargs.get('relax')
    if self.relax:
      warning(MSG_RELAXED_RATIO_ENABLED)

    self.unreliable = kwargs.get('unreliable', False)
    self.slow = kwargs.get('slow', False)
    self.experimental = kwargs.get('experimental', False)
    self.min_ea = kwargs.get('min_ea', get_inf_attr(INF_MIN_EA))
    self.max_ea = kwargs.get('max_ea', get_inf_attr(INF_MAX_EA))
    self.ida_subs = kwargs.get('ida_subs', True)
    self.ignore_sub_names = kwargs.get('ignore_sub_names', True)
    self.ignore_all_names = kwargs.get('ignore_all_names', False)
    self.ignore_small_functions = kwargs.get('ignore_small_functions', False)

    # Enable, by default, exporting only function summaries for huge dbs.
    self.func_summaries_only = kwargs.get('func_summaries_only', total_functions > 100000)

    # Python script to run for both the export and diffing process
    self.project_script = kwargs.get('project_script')

#-------------------------------------------------------------------------------
class CHtmlDiff:
  """A replacement for difflib.HtmlDiff that tries to enforce a max width

  The main challenge is to do this given QTextBrowser's limitations. In
  particular, QTextBrowser only implements a minimum of CSS.
  """

  _html_template = """
  <html>
  <head>
  <style>%(style)s</style>
  </head>
  <body>
  <table class="diff_tab" cellspacing=0>
  %(rows)s
  </table>
  </body>
  </html>
  """

  _style = """
  table.diff_tab {
    font-family: Courier, monospace;
    table-layout: fixed;
    width: 100%;
  }
  table td {
    white-space: nowrap;
    overflow: hidden;
  }

  .diff_add {
    background-color: #aaffaa;
  }
  .diff_chg {
    background-color: #ffff77;
  }
  .diff_sub {
    background-color: #ffaaaa;
  }
  .diff_lineno {
    text-align: right;
    background-color: #e0e0e0;
  }
  """

  _row_template = """
  <tr>
      <td class="diff_lineno" width="auto">%s</td>
      <td class="diff_play" nowrap width="45%%">%s</td>
      <td class="diff_lineno" width="auto">%s</td>
      <td class="diff_play" nowrap width="45%%">%s</td>
  </tr>
  """

  _rexp_too_much_space = re.compile("^\t[.\\w]+ {8}")

  def make_file(self, lhs, rhs, fmt, lex):
    rows = []
    for left, right, changed in difflib._mdiff(lhs, rhs):
        lno, ltxt = left
        rno, rtxt = right

        if not changed:
          ltxt = highlight(ltxt, lex, fmt)
          rtxt = highlight(rtxt, lex, fmt)
        else:
          ltxt = self._stop_wasting_space(ltxt)
          rtxt = self._stop_wasting_space(rtxt)

          ltxt = ltxt.replace(" ", "&nbsp;")
          rtxt = rtxt.replace(" ", "&nbsp;")
          ltxt = ltxt.replace("<", "&lt;")
          ltxt = ltxt.replace(">", "&gt;")
          rtxt = rtxt.replace("<", "&lt;")
          rtxt = rtxt.replace(">", "&gt;")

        row = self._row_template % (str(lno), ltxt, str(rno), rtxt)
        rows.append(row)

    all_the_rows = "\n".join(rows)
    all_the_rows = all_the_rows.replace(
          "\x00+", '<span class="diff_add">').replace(
          "\x00-", '<span class="diff_sub">').replace(
          "\x00^", '<span class="diff_chg">').replace(
          "\x01", '</span>').replace(
          "\t", 4 * "&nbsp;")

    res = self._html_template % {"style": self._style, "rows": all_the_rows}
    return res

  def _stop_wasting_space(self, s):
    """I never understood why you'd want to have 13 spaces between instruction and args'
    """
    m = self._rexp_too_much_space.search(s)
    if m:
      mlen = len(m.group(0))
      return s[:mlen-4] + s[mlen:]
    else:
      return s

#-------------------------------------------------------------------------------
try:
  class CAstVisitorInherits(ctree_visitor_t): pass
except:
  class CAstVisitorInherits: pass

#-------------------------------------------------------------------------------
class CAstVisitor(CAstVisitorInherits):
  def __init__(self, cfunc):
    self.primes = primes(4096)
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

#-------------------------------------------------------------------------------
def is_ida_file(filename):
  filename = filename.lower()
  return filename.endswith(".idb") or filename.endswith(".i64") or \
         filename.endswith(".til") or filename.endswith(".id0") or \
         filename.endswith(".id1") or filename.endswith(".nam")

#-------------------------------------------------------------------------------
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
    with sqlite3.connect(filename, check_same_thread=False) as db:
      cur = db.cursor()
      try:
        funcs = ["functions", "program", "program_data", "version",
               "instructions", "basic_blocks", "bb_relations",
               "bb_instructions", "function_bblocks"]
        for func in funcs:
          db.execute("drop table if exists %s" % func)
      finally:
        cur.close()

#-------------------------------------------------------------------------------
def main():
  global g_bindiff
  if os.getenv("DIAPHORA_AUTO") is not None:
    file_out = os.getenv("DIAPHORA_EXPORT_FILE")
    if file_out is None:
      raise Exception("No export file specified!")

    use_decompiler = os.getenv("DIAPHORA_USE_DECOMPILER")
    if use_decompiler is None:
      use_decompiler = False

    auto_wait()

    if os.path.exists(file_out):
      if g_bindiff is not None:
        g_bindiff = None

      remove_file(file_out)
      log("Database %s removed" % repr(file_out))

    bd = CIDABinDiff(file_out)
    project_script = os.getenv("DIAPHORA_PROJECT_SCRIPT")
    if project_script is not None:
      bd.project_script = project_script
    bd.use_decompiler_always = use_decompiler

    bd.exclude_library_thunk = bd.get_value_for("exclude_library_thunk", bd.exclude_library_thunk)
    bd.ida_subs = bd.get_value_for("ida_subs", bd.ida_subs)
    bd.ignore_sub_names = bd.get_value_for("ignore_sub_names", bd.ignore_sub_names)
    bd.function_summaries_only = bd.get_value_for("function_summaries_only", bd.function_summaries_only)
    bd.min_ea = int(bd.get_value_for("from_address", "0"), 16)

    to_ea = bd.get_value_for("to_address", None)
    if to_ea is not None:
      bd.max_ea = int(to_ea, 16)

    try:
      bd.export()
    except KeyboardInterrupt:
      log("Aborted by user, removing crash file %s-crash..." % file_out)
      os.remove("%s-crash" % file_out)

    idaapi.qexit(0)
  else:
    _diff_or_export(True)

if __name__ == "__main__":
  main()

