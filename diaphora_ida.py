"""
Diaphora, a diffing plugin for IDA
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
import sys
import time
import json
import decimal
import difflib
import sqlite3
import datetime
import traceback

from hashlib import md5
from typing import Iterable, Set, Tuple

# pylint: disable=wildcard-import
# pylint: disable=unused-wildcard-import
from idc import *
from idaapi import *
from idautils import *
# pylint: enable=unused-wildcard-import
# pylint: enable=wildcard-import

import idaapi

idaapi.require("diaphora")

try:
  import ida_hexrays as hr

  HAS_HEXRAYS = True
except ImportError:
  HAS_HEXRAYS = False

sys.path.append(os.path.join(os.path.dirname(__file__), "codecut"))
from codecut import lfa

from pygments import highlight
from pygments.lexers import NasmLexer, CppLexer, DiffLexer
from pygments.formatters import HtmlFormatter

import diaphora_config as config

from others.tarjan_sort import strongly_connected_components, robust_topological_sort

from jkutils.factor import primesbelow
from jkutils.graph_hashes import CKoretKaramitasHash

try:
  from jkutils.IDAMagicStrings import get_source_strings

  HAS_GET_SOURCE_STRINGS = True
except ImportError:
  print(f"Error loading IDAMagicStrings.py: {str(sys.exc_info()[1])}")
  HAS_GET_SOURCE_STRINGS = False

# pylint: disable-next=wrong-import-order
from PyQt5 import QtWidgets

#-------------------------------------------------------------------------------
# Chooser items indices. They do differ from the CChooser.item items that are
# handled in diaphora.py.
import diaphora

CHOOSER_ITEM_MAIN_EA = diaphora.ITEM_MAIN_EA + 1
CHOOSER_ITEM_MAIN_NAME = diaphora.ITEM_MAIN_NAME + 1
CHOOSER_ITEM_DIFF_EA = diaphora.ITEM_DIFF_EA + 1
CHOOSER_ITEM_DIFF_NAME = diaphora.ITEM_DIFF_NAME + 1
CHOOSER_ITEM_RATIO = diaphora.ITEM_RATIO

# Constants unexported in IDA Python
PRTYPE_SEMI = 0x0008

# Messages
MSG_RELAXED_RATIO_ENABLED = """AUTOHIDE DATABASE\n
Relaxed ratio calculations can be enabled. It will ignore many small
modifications to functions and will match more functions with higher ratios.
Enable this option if you're only interested in the new functionality. Disable
it for patch diffing if you're interested in small modifications (like buffer
sizes).

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
# Python linter specific things to disable (temporarily, I guess...)
#
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=protected-access

#-------------------------------------------------------------------------------
def log(message):
  """
  Print a message
  """
  print(f"[Diaphora: {time.asctime()}] {message}")


#-------------------------------------------------------------------------------
def log_refresh(message, show=False, do_log=True):
  """
  Print a message and refresh the UI.
  """
  if show:
    show_wait_box(message)
  else:
    replace_wait_box(message)

  if user_cancelled():
    raise Exception("Cancelled")

  if do_log:
    log(message)


#-------------------------------------------------------------------------------
def debug_refresh(message):
  """
  Print a debugging message if debugging is enabled.
  """
  if os.getenv("DIAPHORA_DEBUG"):
    log(message)


#-------------------------------------------------------------------------------
diaphora.log = log
diaphora.log_refresh = log_refresh

#-------------------------------------------------------------------------------
# pylint: disable=global-variable-not-assigned
g_bindiff = None


def show_choosers():
  """
  Show the non empty choosers.
  """
  if g_bindiff is not None:
    g_bindiff.show_choosers(False)


#-------------------------------------------------------------------------------
def save_results():
  """
  Show the dialogue to save the diffing results.
  """
  if g_bindiff is not None:
    filename = ask_file(1, "*.diaphora", "Select the file to store diffing results")
    if filename is not None:
      g_bindiff.save_results(filename)


# pylint: enable=global-variable-not-assigned


#-------------------------------------------------------------------------------
def load_and_import_all_results(filename, main_db, diff_db):
  """
  Load the diffing results and import all matches.
  """
  tmp_diff = CIDABinDiff(":memory:")

  if os.path.exists(filename) and os.path.exists(main_db) and os.path.exists(diff_db):
    tmp_diff.load_and_import_all_results(filename, main_db, diff_db)

  idaapi.qexit(0)


#-------------------------------------------------------------------------------
def load_results():
  """
  Load previously saved diffing results.
  """
  tmp_diff = CIDABinDiff(":memory:")
  filename = ask_file(0, "*.diaphora", "Select the file to load diffing results")
  if filename is not None:
    tmp_diff.load_results(filename)


#-------------------------------------------------------------------------------
def import_definitions():
  """
  Import *only* the definitions (struct, enums and unions).
  """
  tmp_diff = CIDABinDiff(":memory:")
  message = "Select the file to import structures, unions and enumerations from"
  filename = ask_file(0, "*.sqlite", message)
  if filename is not None:
    message = "HIDECANCEL\nDo you really want to import all structures, unions and enumerations?"
    if ask_yn(1, message) == 1:
      tmp_diff.import_definitions_only(filename)


#-------------------------------------------------------------------------------
def diaphora_decode(ea):
  """
  Wrapper for IDA's decode_insn
  """
  ins = idaapi.insn_t()
  decoded_size = idaapi.decode_insn(ins, ea)
  return decoded_size, ins


#-------------------------------------------------------------------------------
# pylint: disable=redefined-outer-name
# pylint: disable=arguments-renamed
# pylint: disable=attribute-defined-outside-init
# pylint: disable=c-extension-no-member
class CHtmlViewer(PluginForm):
  """
  Class used to graphically show the differences.
  """

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
    self.layout.addWidget(self.browser)
    self.parent.setLayout(self.layout)

  def Show(self, text, title):
    self.text = text
    return PluginForm.Show(self, title)


# pylint: enable=c-extension-no-member
# pylint: enable=attribute-defined-outside-init
# pylint: enable=arguments-renamed
# pylint: enable=redefined-outer-name


#-------------------------------------------------------------------------------
class CBasicChooser(Choose):
  def __init__(self, title):
    Choose.__init__(
      self,
      title,
      [["Id", 10 | Choose.CHCOL_PLAIN], ["Name", 30 | Choose.CHCOL_PLAIN]],
    )
    self.items = []

  def OnGetSize(self):
    return len(self.items)

  def OnGetLine(self, n):
    return self.items[n]


#-------------------------------------------------------------------------------
# Hex-Rays finally removed AddCommand(). Now, instead of a 1 line call, we need
# 2 classes...
class command_handler_t(ida_kernwin.action_handler_t):
  def __init__(self, obj, cmd_id, num_args=2):
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


# pylint: disable=super-init-not-called
# pylint: disable=arguments-differ
class CDiaphoraChooser(diaphora.CChooser, Choose):
  def __init__(self, title, bindiff, show_commands=True):
    diaphora.CChooser.__init__(self, title, bindiff, show_commands)
    self.actions = []

  def AddCommand(self, menu_name, shortcut=None):
    if menu_name is not None:
      tmp = menu_name.replace(" ", "")
      action_name = f"Diaphora:{tmp}"
    else:
      action_name = None
    self.actions.append([len(self.actions), action_name, menu_name, shortcut])
    return len(self.actions) - 1

  def OnPopup(self, widget, popup_handle):
    for num, action_name, menu_name, shortcut in self.actions:
      if menu_name is None:
        ida_kernwin.attach_action_to_popup(widget, popup_handle, None)
      else:
        handler = command_handler_t(self, num, 2)
        desc = ida_kernwin.action_desc_t(
          action_name, menu_name, handler, shortcut
        )
        ida_kernwin.attach_dynamic_action_to_popup(widget, popup_handle, desc)


# pylint: enable=arguments-differ
# pylint: enable=super-init-not-called


#-------------------------------------------------------------------------------
class CIDAChooser(CDiaphoraChooser):
  """
  Wrapper class for IDA choosers
  """

  # pylint: disable=non-parent-init-called
  def __init__(self, title, bindiff, show_commands=True):
    CDiaphoraChooser.__init__(self, title, bindiff, show_commands)
    if title.startswith("Unmatched in"):
      Choose.__init__(
        self,
        title,
        [["Line", 8], ["Address", 10], ["Name", 20]],
        Choose.CH_MULTI,
      )
    else:
      columns = [
        ["Line", 8],
        ["Address", 10],
        ["Name", 20],
        ["Address 2", 10],
        ["Name 2", 20],
        ["Ratio", 8],
        ["BBlocks 1", 5],
        ["BBlocks 2", 5],
        ["Description", 30],
      ]
      Choose.__init__(self, title, columns, Choose.CH_MULTI)

  # pylint: enable=non-parent-init-called

  def OnSelectLine(self, sel):
    item = self.items[sel[0]]
    if self.primary:
      jump_ea = int(item[CHOOSER_ITEM_MAIN_EA], 16)
      # Only jump for valid addresses
      if is_mapped(jump_ea):
        jumpto(jump_ea)
    else:
      self.bindiff.show_asm(self.items[sel[0]], self.primary)

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    return len(self.items)

  def OnDeleteLine(self, sel):
    for n in sorted(sel, reverse=True):
      if n >= 0:

        def get_item(n, index):
          try:
            return self.items[n][index]
          except IndexError:
            return None

        name1 = get_item(n, CHOOSER_ITEM_MAIN_NAME)
        name2 = get_item(n, CHOOSER_ITEM_DIFF_NAME)

        del self.items[n]

        if name1 in self.bindiff.matched_primary:
          del self.bindiff.matched_primary[name1]
        if name2 in self.bindiff.matched_secondary:
          del self.bindiff.matched_secondary[name2]

    return [Choose.ALL_CHANGED] + sel

  def show(self, force=False):
    """
    Sort items, add menu items and show the chooser.
    """
    if self.show_commands:
      self.items = sorted(
        self.items,
        key=lambda x: decimal.Decimal(x[CHOOSER_ITEM_RATIO]),
        reverse=True,
      )

    t = self.Show()
    if t < 0:
      return False

    # pylint: disable=attribute-defined-outside-init

    if self.show_commands and (self.cmd_diff_asm is None or force):
      # create aditional actions handlers
      self.cmd_rediff = self.AddCommand("Diff again")
      self.cmd_save_results = self.AddCommand("Save results")
      self.cmd_add_manual_match = self.AddCommand("Add manual match")
      self.AddCommand(None)
      self.cmd_diff_asm = self.AddCommand("Diff assembly")
      self.cmd_diff_microcode = self.AddCommand("Diff microcode")
      self.cmd_diff_c = self.AddCommand("Diff pseudo-code")
      self.cmd_diff_graph = self.AddCommand("Diff assembly in a graph")
      self.cmd_diff_graph_microcode = self.AddCommand("Diff microcode in a graph")
      self.cmd_diff_external = self.AddCommand("Diff using an external tool")
      self.cmd_diff_c_patch = self.AddCommand("Show pseudo-code patch")
      self.cmd_view_callgraph_context = self.AddCommand(
        "Show callers and callees graph"
      )
      self.AddCommand(None)
      self.cmd_import_selected = self.AddCommand("Import selected", "Ctrl+Alt+i")
      self.cmd_import_selected_auto = self.AddCommand("Import selected sub_*")
      self.cmd_import_all = self.AddCommand("Import *all* functions")
      self.cmd_import_all_funcs = self.AddCommand(
        "Import *all* data for sub_* functions"
      )
      self.AddCommand(None)
      self.cmd_highlight_functions = self.AddCommand("Highlight matches")
      self.cmd_unhighlight_functions = self.AddCommand("Unhighlight matches")
    elif not self.show_commands and (self.cmd_show_asm is None or force):
      self.cmd_show_asm = self.AddCommand("Show assembly")
      self.cmd_show_pseudo = self.AddCommand("Show pseudo-code")

    # pylint: enable=attribute-defined-outside-init

    return True

  def OnCommand(self, n, cmd_id):
    """
    Aditional right-click-menu commands handles.
    """
    if cmd_id == self.cmd_show_asm:
      self.bindiff.show_asm(self.items[n], self.primary)
    elif cmd_id == self.cmd_show_pseudo:
      self.bindiff.show_pseudo(self.items[n], self.primary)
    elif cmd_id == self.cmd_import_all:
      text = "HIDECANCEL\n"
      text += "Do you want to import all functions, comments, prototypes and definitions?"
      if ask_yn(1, text) == 1:
        self.bindiff.import_all(self.items)
    elif cmd_id == self.cmd_import_all_funcs:
      if (
        ask_yn(
          1,
          "HIDECANCEL\nDo you really want to import all IDA named matched functions, comments, prototypes and definitions?",
        )
        == 1
      ):
        self.bindiff.import_all_auto(self.items)
    elif (
      cmd_id == self.cmd_import_selected
      or cmd_id == self.cmd_import_selected_auto
    ):
      if len(self.selected_items) <= 1:
        self.bindiff.import_one(self.items[n])
      else:
        if (
          ask_yn(
            1,
            "HIDECANCEL\nDo you really want to import all selected IDA named matched functions, comments, prototypes and definitions?",
          )
          == 1
        ):
          self.bindiff.import_selected(
            self.items,
            self.selected_items,
            cmd_id == self.cmd_import_selected_auto,
          )
    elif cmd_id == self.cmd_diff_c:
      self.bindiff.show_pseudo_diff(self.items[n])
    elif cmd_id == self.cmd_diff_c_patch:
      self.bindiff.show_pseudo_diff(self.items[n], html=False)
    elif cmd_id == self.cmd_diff_asm:
      self.bindiff.show_asm_diff(self.items[n])
    elif cmd_id == self.cmd_diff_microcode:
      self.bindiff.show_microcode_diff(self.items[n])
    elif cmd_id == self.cmd_highlight_functions:
      if (
        ask_yn(
          1,
          "HIDECANCEL\nDo you want to change the background color of each matched function?",
        )
        == 1
      ):
        color = self.get_color()
        for item in self.items:
          ea = int(item[CHOOSER_ITEM_MAIN_EA], 16)
          if not set_color(ea, CIC_FUNC, color):
            # pylint: disable-next=consider-using-f-string
            print("Error setting color for %x" % ea)
        self.Refresh()
    elif cmd_id == self.cmd_unhighlight_functions:
      for item in self.items:
        ea = int(item[CHOOSER_ITEM_MAIN_EA], 16)
        if not set_color(ea, CIC_FUNC, 0xFFFFFF):
          # pylint: disable-next=consider-using-f-string
          print("Error setting color for %x" % ea)
      self.Refresh()
    elif cmd_id == self.cmd_diff_graph:
      item = self.items[n]
      ea1 = int(item[CHOOSER_ITEM_MAIN_EA], 16)
      name1 = item[CHOOSER_ITEM_MAIN_NAME]
      ea2 = int(item[CHOOSER_ITEM_DIFF_EA], 16)
      name2 = item[CHOOSER_ITEM_DIFF_NAME]
      # pylint: disable-next=consider-using-f-string
      log("Diff graph for 0x%x - 0x%x" % (ea1, ea2))
      self.bindiff.graph_diff(ea1, name1, ea2, name2)
    elif cmd_id == self.cmd_diff_graph_microcode:
      item = self.items[n]
      ea1 = int(item[CHOOSER_ITEM_MAIN_EA], 16)
      name1 = item[CHOOSER_ITEM_MAIN_NAME]
      ea2 = int(item[CHOOSER_ITEM_DIFF_EA], 16)
      name2 = item[CHOOSER_ITEM_DIFF_NAME]
      # pylint: disable-next=consider-using-f-string
      log("Diff microcode graph for 0x%x - 0x%x" % (ea1, ea2))
      self.bindiff.graph_diff_microcode(ea1, name1, ea2, name2)
    elif cmd_id == self.cmd_view_callgraph_context:
      item = self.items[n]
      ea1 = int(item[CHOOSER_ITEM_MAIN_EA], 16)
      name1 = item[CHOOSER_ITEM_MAIN_NAME]
      ea2 = int(item[CHOOSER_ITEM_DIFF_EA], 16)
      name2 = item[CHOOSER_ITEM_DIFF_NAME]
      # pylint: disable-next=consider-using-f-string
      log("Showing call graph context for 0x%x - 0x%x" % (ea1, ea2))
      self.bindiff.show_callgraph_context(name1, name2)
    elif cmd_id == self.cmd_save_results:
      filename = ask_file(
        1, "*.diaphora", "Select the file to store diffing results"
      )
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
    """
    Return the functions rows for the diff database
    """
    cur = self.bindiff.db_cursor()
    try:
      cur.execute("select cast(id as text), name from diff.functions order by id")
      rows = list(cur.fetchall())
      rows = list(map(list, rows))
    finally:
      cur.close()

    return rows

  def add_manual_match_internal(self, name1, name2):
    """
    Internal function, add a manual match directly to the partial chooser.
    """
    main_row = self.bindiff.get_function_row(name1)
    diff_row = self.bindiff.get_function_row(name2, "diff")
    ratio = self.bindiff.compare_function_rows(main_row, diff_row)

    ea1 = main_row["address"]
    name1 = main_row["name"]
    ea2 = diff_row["address"]
    name2 = diff_row["name"]
    desc = "Manual match"
    bb1 = main_row["nodes"]
    bb2 = diff_row["nodes"]
    self.bindiff.partial_chooser.add_item(
      diaphora.CChooser.Item(ea1, name1, ea2, name2, desc, ratio, bb1, bb2)
    )
    self.bindiff.matched_primary[name1] = {"name": name2, "ratio": ratio}
    self.bindiff.matched_secondary[name2] = {"name": name1, "ratio": ratio}
    self.bindiff.partial_chooser.Refresh()

  def add_manual_match(self):
    """
    Menu item handler for adding a manual match.
    """
    f = choose_func("Select a function from the current database...", 0)
    if f is not None:
      diff_chooser = CBasicChooser(
        "Select a function from the external database..."
      )
      diff_funcs = self.get_diff_functions()
      diff_chooser.items = diff_funcs
      ret = diff_chooser.Show(modal=True)
      if ret > -1:
        name1 = get_func_name(f.start_ea)
        name2 = diff_funcs[ret][1]

        if (
          name1 in self.bindiff.matched_primary
          or name2 in self.bindiff.matched_secondary
        ):
          line = (
            f"Either the local function {repr(name1)} or the foreign function {repr(name2)} are already matched.\n"
            + "Please remove the previously assigned match before adding a manual match."
          )
          warning(line)
        else:
          log(f"Adding manual match between {name1} and {name2}")
          self.add_manual_match_internal(name1, name2)

  def OnSelectionChange(self, sel):
    self.selected_items = sel

  def seems_false_positive(self, item):
    """
    Check if it looks like a false positive because the names are different.
    """
    name1 = item[CHOOSER_ITEM_MAIN_NAME]
    name2 = item[CHOOSER_ITEM_DIFF_NAME]

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
      ratio = float(item[CHOOSER_ITEM_RATIO])
      if self.seems_false_positive(item):
        return [LITTLE_ORANGE, 0]
      else:
        red = int(164 * (1 - ratio))
        green = int(128 * ratio)
        blue = int(255 * (1 - ratio))
        # pylint: disable-next=consider-using-f-string
        color = int("0x%02x%02x%02x" % (blue, green, red), 16)
      return [color, 0]
    return [0xFFFFFF, 0]


#-------------------------------------------------------------------------------
# pylint: disable=no-member
class CBinDiffExporterSetup(Form):
  """
  IDA class to build the export dialogue.
  """

  def __init__(self):
    s = r"""Diaphora
  Please select the path to the SQLite database to save the current IDA database and the path of the SQLite database to diff against.
  If no SQLite diff database is selected, it will just export the current IDA database to SQLite format. Leave the 2nd field empty if you are exporting the first database.

  SQLite databases:
  <#Select a file to export the current IDA database to SQLite format#Export IDA database to SQLite  :{iFileSave}>
  <#Select the SQLite database to diff against             #SQLite database to diff against:{iFileOpen}>

  Export filter limits:
  <#Minimum address to find functions to export#From address:{iMinEA}>
  <#Maximum address to find functions to export#To address  :{iMaxEA}>

  Export options:
  <Use the decompiler if available:{rUseDecompiler}>
  <#Enable this option to disable exporting microcode#Export microcode instructions and basic blocks:{rExportMicrocode}>
  <Do not export library and thunk functions:{rExcludeLibraryThunk}>
  <#Enable if you want neither sub_* functions nor library functions to be exported#Export only non-IDA generated functions:{rNonIdaSubs}>
  <#Export only function summaries, not all instructions. Showing differences in a graph between functions will not be available.#Do not export instructions and basic blocks:{rFuncSummariesOnly}>
  <#Enable this option to ignore thunk functions, nullsubs, etc....#Ignore small functions:{rIgnoreSmallFunctions}>{cGroupExport}>|

  Diffing options:
  <Use probably unreliable methods:{rUnreliable}>
  <Recommended to disable with databases with more than 5.000 functions#Use slow heuristics:{rSlowHeuristics}>
  <#Enable this option if you aren't interested in small changes#Relaxed calculations of differences ratios:{rRelaxRatio}>
  <Use speed ups:{rExperimental}##Use tricks to speed ups some of the most common diffing tasks>
  <#Enable this option to ignore sub_* names for the 'Same name' heuristic.#Ignore automatically generated names:{rIgnoreSubNames}>
  <#Enable this option to ignore all function names for the 'Same name' heuristic.#Ignore all function names:{rIgnoreAllNames}>{cGroup1}>

  Project specific rules:
  <#Select the project specific Python script rules#Python script:{iProjectSpecificRules}>

  NOTE: Don't select IDA database files (.IDB, .I64) as only SQLite databases are considered.
"""
    args = {
      "iFileSave": Form.FileInput(save=True, hlp="SQLite database (*.sqlite)"),
      "iFileOpen": Form.FileInput(open=True, hlp="SQLite database (*.sqlite)"),
      "iMinEA": Form.NumericInput(tp=Form.FT_HEX, swidth=22),
      "iMaxEA": Form.NumericInput(tp=Form.FT_HEX, swidth=22),
      "cGroupExport": Form.ChkGroupControl(
        (
          "rUseDecompiler",
          "rExcludeLibraryThunk",
          "rIgnoreSmallFunctions",
          "rExportMicrocode",
          "rNonIdaSubs",
          "rFuncSummariesOnly",
        )
      ),
      "cGroup1": Form.ChkGroupControl(
        (
          "rUnreliable",
          "rSlowHeuristics",
          "rRelaxRatio",
          "rExperimental",
          "rIgnoreSubNames",
          "rIgnoreAllNames",
        )
      ),
      "iProjectSpecificRules": Form.FileInput(
        open=True, hlp="Python scripts (*.py)"
      ),
    }

    Form.__init__(self, s, args)

  def set_options(self, opts):
    """
    Set the configuration options from opts.
    """
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
    self.rNonIdaSubs.checked = not opts.ida_subs
    self.rIgnoreSubNames.checked = opts.ignore_sub_names
    self.rIgnoreAllNames.checked = opts.ignore_all_names
    self.rIgnoreSmallFunctions.checked = opts.ignore_small_functions
    self.rFuncSummariesOnly.checked = opts.func_summaries_only
    self.rExportMicrocode.checked = opts.export_microcode

  def get_options(self):
    """
    Get a dictionary with the configuration options.
    """
    opts = dict(
      file_out=self.iFileSave.value,
      file_in=self.iFileOpen.value,
      use_decompiler=self.rUseDecompiler.checked,
      exclude_library_thunk=self.rExcludeLibraryThunk.checked,
      unreliable=self.rUnreliable.checked,
      slow=self.rSlowHeuristics.checked,
      relax=self.rRelaxRatio.checked,
      experimental=self.rExperimental.checked,
      min_ea=self.iMinEA.value,
      max_ea=self.iMaxEA.value,
      ida_subs=self.rNonIdaSubs.checked is False,
      ignore_sub_names=self.rIgnoreSubNames.checked,
      ignore_all_names=self.rIgnoreAllNames.checked,
      ignore_small_functions=self.rIgnoreSmallFunctions.checked,
      func_summaries_only=self.rFuncSummariesOnly.checked,
      project_script=self.iProjectSpecificRules.value,
      export_microcode=self.rExportMicrocode.checked,
    )
    return BinDiffOptions(**opts)


# pylint: enable=no-member


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
  """
  Class used to show graphs.
  """

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
        if key not in self.nodes:
          self.nodes[key] = self.AddNode([key, [[0, 0, ""]]])
        parent_node = self.nodes[key]
        for child in self.relations[key]:
          if child not in self.nodes:
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
class CCallGraphViewer(GraphViewer):
  def __init__(self, title, callers, callees, target):
    GraphViewer.__init__(self, title, False)
    self.target = target
    self.callers = callers
    self.callees = callees

    self.root = None
    self.nodes = {}
    self.node_types = {
      "target": config.CALLGRAPH_COLOR_TARGET,
      "callee": config.CALLGRAPH_COLOR_CALLEE,
      "caller": config.CALLGRAPH_COLOR_CALLER,
    }

  def OnRefresh(self):
    self.Clear()
    self.root = self.AddNode(self.target)
    self.nodes[self.root] = [self.target, "target"]

    for caller in self.callers:
      name = caller["name1"]
      node = self.AddNode(name)
      self.AddEdge(node, self.root)
      self.nodes[node] = [name, "caller"]

    for callee in self.callees:
      name = callee["name1"]
      node = self.AddNode(name)
      self.AddEdge(self.root, node)
      self.nodes[node] = [name, "callee"]

    return True

  def OnGetText(self, node_id):
    node = self.nodes[node_id]
    name, node_type = node
    colour = self.node_types[node_type]
    return name, colour

  def OnHint(self, node_id):
    node = self.nodes[node_id]
    _, node_type = node
    return node_type

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
  def __init__(self):
    self.iStrCommand = None
    Form.__init__(
      self,
      r"""STARTITEM 0
BUTTON YES* Diff Pseudo-code
BUTTON NO Diff Assembler
External Diffing Tool
<#Hint1#Enter command line:{iStrCommand}>
""",
      {
        "iStrCommand": Form.StringInput(),
      },
    )


#-------------------------------------------------------------------------------
class CPrinter_t(hr.vd_printer_t):
  """Converts microcode output to an array of strings."""

  def __init__(self, *args):
    hr.vd_printer_t.__init__(self)
    self.mc = []

  def get_mc(self):
    return self.mc

  # pylint: disable-next=arguments-differ
  # pylint: disable-next=unexpected-keyword-arg
  def _print(self, _, line):
    self.mc.append(line)
    return 1

#-------------------------------------------------------------------------------
class CIDABinDiff(diaphora.CBinDiff):
  """
  The main binary diffing class.
  """

  def __init__(self, db_name):
    diaphora.CBinDiff.__init__(self, db_name, chooser=CIDAChooser)
    self.decompiler_available = config.EXPORTING_USE_DECOMPILER
    self.names = dict(Names())
    self.min_ea = get_inf_attr(INF_MIN_EA)
    self.max_ea = get_inf_attr(INF_MAX_EA)

    self.microcode_ins_list = self.get_microcode_instructions()

    self.project_script = None
    self.hooks = None

  def refresh(self):
    idaapi.request_refresh(0xFFFFFFFF)

  def show_choosers(self, force=False):
    """
    Show all non empty choosers.
    """
    CHOOSERS = [
      self.best_chooser,
      self.partial_chooser,
      self.multimatch_chooser,
      self.unreliable_chooser,
      self.unmatched_primary,
      self.unmatched_second,
    ]

    for chooser in CHOOSERS:
      if chooser is not None and len(chooser.items) > 0:
        chooser.show(force)

  def diff(self, db):
    if user_cancelled():
      return None

    res = diaphora.CBinDiff.diff(self, db)
    if res:
      # And, finally, show the list of best and partial matches and
      # register the hotkey for re-opening results
      self.show_choosers()
      self.register_menu()
    hide_wait_box()
    return res

  def init_primes(self) -> Tuple[int, int]:
    """
    Recalculate the primes assigned to a function.
    """
    callgraph_primes = 1
    callgraph_all_primes = {}

    for _, prime, _ in self._funcs_cache.values():
      callgraph_primes *= prime
      try:
        callgraph_all_primes[prime] += 1
      except KeyError:
        callgraph_all_primes[prime] = 1

    return callgraph_primes, callgraph_all_primes

  def restore_crashed_export(self):
    """
    Restore self._funcs_cache before resuming crashed export
    """
    sql = "select address, rowid, primes_value, pseudocode_primes from functions"

    cur = self.db_cursor()
    try:
      cur.execute(sql)
      for row in cur.fetchall():
        self._funcs_cache[int(row[0])] = [
          row[1],
          int(row[2]),
          row[3] and int(row[3]),
        ]
    finally:
      cur.close()

  def filter_functions(self, functions: Set[int]) -> Iterable[int]:
    # filter functions to export
    # Useful for parallel fork
    return (functions - self._funcs_cache.keys())

  def do_export(self, crashed_before=False):
    """
    Internal use, export the database.
    """
    # pylint: disable-next=consider-using-f-string
    log("Exporting range 0x%08x - 0x%08x" % (self.min_ea, self.max_ea))
    func_list = set(Functions(self.min_ea, self.max_ea))
    total_funcs = len(func_list)
    log_step = (total_funcs + 127) // 128  # log every `log_step` functions
    self._funcs_cache = {}
    t = time.monotonic()

    if crashed_before:
      self.restore_crashed_export()
      if not self._funcs_cache:
        warning(
          "Diaphora cannot resume the previous crashed session, the export process will start from scratch."
        )
        crashed_before = False

    callgraph_primes, callgraph_all_primes = self.init_primes()

    self.db.commit()
    self.db.execute("PRAGMA synchronous = OFF")
    self.db.execute("PRAGMA journal_mode = MEMORY")
    self.db.execute("BEGIN transaction")

    i = len(self._funcs_cache.keys() & func_list)
    for func in self.filter_functions(func_list):
      if user_cancelled():
        raise Exception("Canceled.")

      i += 1
      if (i-1) % log_step == 0:
        line = "Exported %d function(s) out of %d total.\nElapsed %d:%02d:%02d second(s), remaining time ~%d:%02d:%02d"
        elapsed = time.monotonic() - t
        remaining = (elapsed / i) * (total_funcs - i)

        m, s = divmod(remaining, 60)
        h, m = divmod(m, 60)
        m_elapsed, s_elapsed = divmod(elapsed, 60)
        h_elapsed, m_elapsed = divmod(m_elapsed, 60)
        message = line % (i, total_funcs, h_elapsed, m_elapsed, s_elapsed, h, m, s)
        replace_wait_box(message)

      self.microcode_ins_list = self.get_microcode_instructions()
      props = self.read_function(func)
      if props is False:
        continue

      ret = props[11]
      callgraph_primes *= decimal.Decimal(ret)
      try:
        callgraph_all_primes[ret] += 1
      except KeyError:
        callgraph_all_primes[ret] = 1
      self.save_function(props)

      # Try to fix bug #30 and, also, try to speed up operations as doing a
      # commit every 10 functions, as before, is overkill.
      if (
        total_funcs > config.EXPORTING_FUNCTIONS_TO_COMMIT
        and i % (total_funcs / 10) == 0
      ):
        self.db.commit()
        self.db.execute("PRAGMA synchronous = OFF")
        self.db.execute("PRAGMA journal_mode = MEMORY")
        self.db.execute("BEGIN transaction")

    md5sum = GetInputFileMD5()
    self.save_callgraph(
      str(callgraph_primes), json.dumps(callgraph_all_primes), md5sum
    )
    self.export_structures()
    try:
      self.export_til()
    except:
      log(f"Error reading type libraries: {str(sys.exc_info()[1])}")
    self.save_compilation_units()

    log_refresh("Creating indices...")
    self.create_indices()

  def export(self):
    """
    Export the current database. Call script hooks if there is any.
    """
    if self.project_script is not None:
      if not self.load_hooks():
        return False

    crashed_before = False
    crash_file = f"{self.db_name}-crash"
    if os.path.exists(crash_file):
      log("Resuming a previously crashed session...")
      crashed_before = True

    log(f"Creating crash file {crash_file}...")
    with open(crash_file, "wb") as f:
      f.close()

    try:
      show_wait_box("Exporting database")
      try:
        self.do_export(crashed_before)
      except:
        log(f"Error: {str(sys.exc_info()[1])}")
        traceback.print_exc()
        if self.hooks is not None:
          if "on_export_crash" in dir(self.hooks):
            ret = self.hooks.on_export_crash()
            if not ret:
              raise
    finally:
      hide_wait_box()

    self.db.commit()
    log(f"Removing crash file {self.db_name}-crash...")
    os.remove(f"{self.db_name}-crash")

    cur = self.db_cursor()
    try:
      cur.execute("analyze")
    finally:
      cur.close()

    self.db_close()

  def import_til(self):
    """
    Import IDA's Type Libraries.
    """
    log("Importing type libraries...")
    cur = self.db_cursor()
    try:
      sql = "select name from diff.program_data where type = 'til'"
      cur.execute(sql)
      for row in cur.fetchall():
        til = row["name"]
        if isinstance(til, bytes):
          til = til.decode("utf-8")

        try:
          add_default_til(til)
        except:
          log(f'Error loading TIL {row["name"]}: {str(sys.exc_info()[1])}')
    finally:
      cur.close()

    auto_wait()

  def import_definitions(self):
    """
    Import structs, enums and unions
    """
    cur = self.db_cursor()
    try:
      sql = "select type, name, value from diff.program_data where type in ('structure', 'struct', 'enum', 'union')"
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
            type_name = "union"

          new_rows.add(row)
          line = f"{type_name} {row['name']};"
          try:
            ret = idc.parse_decls(line)
            if ret != 0:
              pass
          except:
            log(f"Error importing type: {str(sys.exc_info()[1])}")

      for _ in range(10):
        for row in new_rows:
          if row["name"] is None:
            continue

          the_name = row["name"].split(" ")[0]
          if (
            get_struc_id(the_name) == BADADDR
            and get_struc_id(row["name"]) == BADADDR
          ):
            definition = self.get_valid_definition(row["value"])
            ret = idc.parse_decls(
              definition
            )  # Remove the "idc." to reproduce some strange behaviour
            if ret != 0:
              pass
    finally:
      cur.close()

    auto_wait()

  def reinit(self, main_db, diff_db, create_choosers=True):
    """
    Reinitialize databases.
    """
    log(f"Main database '{main_db}'.")
    log(f"Diff database '{diff_db}'.")

    self.__init__(main_db)
    self.attach_database(diff_db)
    self.last_diff_db = diff_db

    if create_choosers:
      self.create_choosers()

  def import_definitions_only(self, filename):
    """
    Import only the definitions (TIL and structs/enums/unions).
    """
    self.reinit(":memory:", filename)
    self.import_til()
    self.import_definitions()

  def generate_asm_diff_internal(self, ea1, ea2, field, title_fmt, error_func=log):
    """
    Internal use, generate a HTML table with the assembly differences.
    """
    cur = self.db_cursor()
    try:
      sql = f"""select *
         from (
         select prototype, {field}, name, 1
         from functions
        where address = ?
          and {field} is not null
     union select prototype, {field}, name, 2
         from diff.functions
        where address = ?
          and {field} is not null)
        order by 4 asc"""
      ea1 = str(int(ea1, 16))
      ea2 = str(int(ea2, 16))
      cur.execute(sql, (ea1, ea2))
      rows = cur.fetchall()
      res = None
      if len(rows) != 2:
        message = f"Sorry, there is no {field} available for either the first or the second database."
        error_func(message)
      else:
        row1 = rows[0]
        row2 = rows[1]

        html_diff = CHtmlDiff()
        asm1 = self.prettify_asm(row1[field])
        asm2 = self.prettify_asm(row2[field])
        buf1 = f'{row1["name"]} proc near\n{asm1}\n{row1["name"]} endp'
        buf2 = f'{row2["name"]} proc near\n{asm2}\n{row2["name"]} endp'

        fmt = HtmlFormatter()
        fmt.noclasses = True
        fmt.linenos = False
        fmt.nobackground = True
        src = html_diff.make_file(
          buf1.split("\n"), buf2.split("\n"), fmt, NasmLexer()
        )

        title = title_fmt % (row1["name"], row2["name"])
        res = (src, title)
    finally:
      cur.close()

    return res

  def generate_asm_diff(self, ea1, ea2, error_func=log):
    return self.generate_asm_diff_internal(
      ea1, ea2, "assembly", "Diff assembly %s - %s", error_func
    )

  def generate_microcode_diff(self, ea1, ea2, error_func=log):
    return self.generate_asm_diff_internal(
      ea1, ea2, "microcode", "Diff microcode %s - %s", error_func
    )

  def show_asm_diff(self, item):
    res = self.generate_asm_diff(item[1], item[3], error_func=warning)
    if res:
      (src, title) = res
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

  def show_microcode_diff(self, item):
    res = self.generate_microcode_diff(item[1], item[3], error_func=warning)
    if res:
      (src, title) = res
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

  def save_asm_diff(self, ea1, ea2, filename):
    res = self.generate_asm_diff(ea1, ea2)
    if res:
      (src, _) = res
      with open(filename, "w", encoding="utf8") as f:
        f.write(src)

  def import_one(self, item):
    ret = ask_yn(
      1,
      "AUTOHIDE DATABASE\nDo you want to import all the type libraries, structs and enumerations?",
    )

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
    try:
      if primary:
        db = "main"
      else:
        db = "diff"
      ea = str(int(item[1], 16))
      sql = "select prototype, assembly, name from %s.functions where address = ?"
      sql = sql % db
      cur.execute(sql, (ea,))
      row = cur.fetchone()
      if row is None:
        warning(
          "Sorry, there is no assembly available for the selected function."
        )
      else:
        fmt = HtmlFormatter()
        fmt.noclasses = True
        fmt.linenos = True
        asm = self.prettify_asm(row["assembly"])
        final_asm = f'; {row["prototype"]}\n{row["name"]} proc near\n{asm}\n{row["name"]} endp\n'
        src = highlight(final_asm, NasmLexer(), fmt)
        title = f'Assembly for {row["name"]}'
        cdiffer = CHtmlViewer()
        cdiffer.Show(src, title)
    finally:
      cur.close()

  def show_pseudo(self, item, primary):
    cur = self.db_cursor()
    try:
      if primary:
        db = "main"
      else:
        db = "diff"
      ea = str(int(item[1], 16))
      sql = (
        "select prototype, pseudocode, name from %s.functions where address = ?"
      )
      sql = sql % db
      cur.execute(sql, (str(ea),))
      row = cur.fetchone()
      if row is None or row["prototype"] is None or row["pseudocode"] is None:
        warning(
          "Sorry, there is no pseudo-code available for the selected function."
        )
      else:
        fmt = HtmlFormatter()
        fmt.noclasses = True
        fmt.linenos = True
        func = f'{row["prototype"]}\n{row["pseudocode"]}'
        src = highlight(func, CppLexer(), fmt)
        title = f'Pseudo-code for {row["name"]}'
        cdiffer = CHtmlViewer()
        cdiffer.Show(src, title)
    finally:
      cur.close()

  def generate_pseudo_diff(self, ea1, ea2, html=True, error_func=log):
    cur = self.db_cursor()
    try:
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
      ea1 = str(int(ea1, 16))
      ea2 = str(int(ea2, 16))
      cur.execute(sql, (ea1, ea2))
      rows = cur.fetchall()
      res = None
      if len(rows) != 2:
        error_func(
          "Sorry, there is no pseudo-code available for either the first or the second database."
        )
      else:
        row1 = rows[0]
        row2 = rows[1]

        html_diff = CHtmlDiff()
        proto1 = self.decompile_and_get(int(ea1))
        if proto1:
          buf1 = proto1 + "\n" + "\n".join(self.pseudo[int(ea1)])
        else:
          log(
            "warning: cannot retrieve the current pseudo-code for the function, using the previously saved one..."
          )
          buf1 = row1["prototype"] + "\n" + row1["pseudocode"]
        buf2 = row2["prototype"] + "\n" + row2["pseudocode"]

        if buf1 == buf2:
          error_func("Both pseudo-codes are equal.")

        fmt = HtmlFormatter()
        fmt.noclasses = True
        fmt.linenos = False
        fmt.nobackground = True
        if not html:
          uni_diff = difflib.unified_diff(buf1.split("\n"), buf2.split("\n"))
          tmp = []
          for line in uni_diff:
            tmp.append(line.strip("\n"))
          tmp = tmp[2:]
          buf = "\n".join(tmp)

          src = highlight(buf, DiffLexer(), fmt)
        else:
          src = html_diff.make_file(
            buf1.split("\n"), buf2.split("\n"), fmt, CppLexer()
          )

        title = f'Diff pseudo-code {row1["name"]} - {row2["name"]}'
        res = (src, title)
    finally:
      cur.close()
    return res

  def show_pseudo_diff(self, item, html=True):
    res = self.generate_pseudo_diff(item[1], item[3], html=html, error_func=warning)
    if res:
      (src, title) = res
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

  def save_pseudo_diff(self, ea1, ea2, filename):
    res = self.generate_pseudo_diff(ea1, ea2, html=True)
    if res:
      (src, _) = res
      with open(filename, "w", encoding="utf8") as f:
        f.write(src)

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
    try:
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
        warning(
          "Sorry, there is no assembly available for either the first or the second database."
        )
      else:
        row1 = rows[0]
        row2 = rows[1]

        asm1 = self.prettify_asm(row1["assembly"])
        asm2 = self.prettify_asm(row2["assembly"])
        buf1 = f'{row1["name"]} proc near\n{asm1}\n{row1["name"]} endp'
        buf2 = f'{row2["name"]} proc near\n{asm2}\n{row2["name"]} endp'

        filename1 = f"main_{item[1]}.asm"
        filename2 = f"diff_{item[3]}.asm"

        with open(filename1, "w", encoding="utf8") as f_source:
          with open(filename2, "w", encoding="utf8") as f_dest:
            f_source.writelines(buf1)
            f_dest.writelines(buf2)

        line = cmd_line.replace("$1", filename1)
        line = line.replace("$2", filename2)
        ret = os.system(line)
    finally:
      cur.close()

    return ret

  def diff_external_pseudo(self, item, cmd_line):
    ret = None
    cur = self.db_cursor()
    try:
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
        warning(
          "Sorry, there is no pseudo-code available for either the first or the second database."
        )
      else:
        row1 = rows[0]
        row2 = rows[1]

        filename1 = f"main_{item[1]}.cpp"
        filename2 = f"diff_{item[3]}.cpp"

        with open(filename1, "w", encoding="utf8") as f_source:
          with open(filename2, "w", encoding="utf8") as f_dest:
            f_source.writelines(f'{row1["prototype"]}\n{row1["pseudocode"]}')
            f_dest.writelines(f'{row2["prototype"]}\n{row2["pseudocode"]}')

        line = cmd_line.replace("$1", filename1)
        line = line.replace("$2", filename2)
        ret = os.system(line)
    finally:
      cur.close()
    return ret

  def graph_diff(self, ea1, name1, ea2, name2):
    g1 = self.get_graph(str(ea1), True)
    g2 = self.get_graph(str(ea2))

    if g1 == ({}, {}) or g2 == ({}, {}):
      warning(
        "Sorry, graph information is not available for one of the databases."
      )
      return False

    colours = self.compare_graphs(g1, g2)

    title1 = f"Graph for {name1} (primary)"
    title2 = f"Graph for {name2} (secondary)"
    graph1 = CDiffGraphViewer(title1, g1, colours[0])
    graph2 = CDiffGraphViewer(title2, g2, colours[1])
    graph1.Show()
    graph2.Show()

    set_dock_pos(title2, title1, DP_RIGHT)
    uitimercallback_t(graph1, 100)
    uitimercallback_t(graph2, 100)

  def graph_diff_microcode(self, ea1, name1, ea2, name2):
    g1 = self.get_graph(str(ea1), True, "microcode")
    g2 = self.get_graph(str(ea2), False, "microcode")

    if g1 == ({}, {}) or g2 == ({}, {}):
      warning(
        "Sorry, graph information is not available for one of the databases."
      )
      return False

    colours = self.compare_graphs(g1, g2)

    title1 = f"Microcode graph for {name1} (primary)"
    title2 = f"Microcode graph for {name2} (secondary)"
    graph1 = CDiffGraphViewer(title1, g1, colours[0])
    graph2 = CDiffGraphViewer(title2, g2, colours[1])
    graph1.Show()
    graph2.Show()

    set_dock_pos(title2, title1, DP_RIGHT)
    uitimercallback_t(graph1, 100)
    uitimercallback_t(graph2, 100)

  def get_calls_graph(self, name, mtype, db):
    """
    Get the call graph for the given function.
    """
    cur = self.db_cursor()
    rows = []
    try:
      sql = f"""select cg.type type, f2.address ea1, f2.name name1,
             f1.address ea2, f1.name name2
          from {db}.callgraph cg,
             {db}.functions f1,
             {db}.functions f2
         where f1.name = ?
           and cg.func_id = f1.id
           and cg.type = ?
           and f2.address = cg.address """
      cur.execute(sql, (name, mtype))
      rows = cur.fetchall()
    finally:
      cur.close()

    return rows

  def build_calls_graph(self, title, callers, callees, name):
    """
    Build the CCallGraphViewer objects.
    """
    g = CCallGraphViewer(title, callers, callees, name)
    return g

  def show_callgraph_context(self, name1, name2):
    """
    Show the callers and the callees for the given functions.
    """
    main_callers = self.get_calls_graph(name1, "caller", "main")
    main_callees = self.get_calls_graph(name1, "callee", "main")
    diff_callers = self.get_calls_graph(name2, "caller", "diff")
    diff_callees = self.get_calls_graph(name2, "callee", "diff")

    base_title = "Call graph context for {name}"
    title1 = base_title.format(name=name1)
    title2 = base_title.format(name=name2)
    g1 = self.build_calls_graph(title1, main_callers, main_callees, name1)
    g2 = self.build_calls_graph(title2, diff_callers, diff_callees, name2)
    g1.Show()
    g2.Show()

    set_dock_pos(title2, title1, DP_RIGHT)
    uitimercallback_t(g1, 100)
    uitimercallback_t(g2, 100)

  def import_instruction(self, ins_data1, ins_data2):
    """
    Try to import an instruction.
    """
    ea1 = self.get_base_address() + int(ins_data1[0])
    _, cmt1, cmt2, operand_names, name, mtype, _, mcmt, mitp = ins_data2
    if operand_names is None:
      operand_names = []

    # Set instruction level comments
    if cmt1 is not None and get_cmt(ea1, 0) is None:
      set_cmt(ea1, cmt1, 0)

    if cmt2 is not None and get_cmt(ea1, 1) is None:
      set_cmt(ea1, cmt2, 1)

    for operand_name in operand_names:
      index, name = operand_name
      if name:
        ida_bytes.set_forced_operand(ea1, index, name)

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
    the_type = False
    data_refs = list(DataRefsFrom(ea1))
    if len(data_refs) > 0:
      # Global variables
      tmp_ea = data_refs[0]
      if tmp_ea in self.names:
        curr_name = get_ea_name(tmp_ea)
        if curr_name != name and self.is_auto_generated(curr_name):
          set_name(tmp_ea, name, SN_CHECK)
          the_type = False
      else:
        # If it's an object, we don't want to rename the offset, we want to
        # rename the true global variable.
        if is_off(get_full_flags(tmp_ea), OPND_ALL):
          tmp_ea = next(DataRefsFrom(tmp_ea), tmp_ea)

        set_name(tmp_ea, name, SN_CHECK)
        the_type = True
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
          the_type = True

    if tmp_ea is not None and the_type:
      if mtype is not None and idc.get_type(tmp_ea) != mtype:
        if isinstance(mtype, bytes):
          mtype = mtype.decode("utf-8")
        SetType(tmp_ea, mtype)

  def row_is_importable(self, ea2, import_syms):
    """
    Check if the given row is importable.
    """
    ea = str(ea2)
    if ea not in import_syms:
      return False

    operand_names = import_syms[ea][3]

    # Has cmt1
    if import_syms[ea][1] is not None:
      return True

    # Has cmt2
    if import_syms[ea][2] is not None:
      return True

    # Has operand names
    operand_names = import_syms[ea][3]
    if operand_names is not None:
      for operand_name in operand_names:
        if operand_name[1] != "":
          return True

    # Has a name
    if import_syms[ea][4] is not None:
      return True

    # Has pseudocode comment
    if import_syms[ea][6] is not None:
      return True

    return False

  def do_import_instruction_level_item(self, diff_rows, import_syms, matched_syms):
    """
    Internal use, import everything that can be imported at assembly instruction
    level.
    """
    lines1 = diff_rows[0]["assembly"]
    lines2 = diff_rows[1]["assembly"]

    address1 = json.loads(diff_rows[0]["assembly_addrs"])
    address2 = json.loads(diff_rows[1]["assembly_addrs"])

    diff_list = difflib._mdiff(lines1.splitlines(1), lines2.splitlines(1))
    for x in diff_list:
      left, right, _ = x
      left_line = left[0]
      right_line = right[0]

      if right_line == "" or left_line == "":
        continue

      # At this point, we know which line number matches with
      # which another line number in both databases.
      ea1 = address1[int(left_line) - 1]
      ea2 = address2[int(right_line) - 1]
      changed = left[1].startswith("\x00-") and right[1].startswith("\x00+")
      is_importable = self.row_is_importable(ea2, import_syms)
      if changed or is_importable:
        ea1 = str(ea1)
        ea2 = str(ea2)
        if ea1 in matched_syms and ea2 in import_syms:
          self.import_instruction(matched_syms[ea1], import_syms[ea2])
        if ea2 in matched_syms and ea1 in import_syms:
          self.import_instruction(matched_syms[ea2], import_syms[ea1])

  def import_instruction_level(self, ea1, ea2, cur):
    cur = self.db_cursor()
    try:
      # Check first if we have any importable items
      sql = """ select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.operand_names operand_names, ins.name name, ins.type type, ins.pseudocomment cmt, ins.pseudoitp itp
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
           or ins.operand_names is not null
           or ins.name is not null
           or pseudocomment is not null) """
      cur.execute(sql, (str(ea2),))
      import_rows = cur.fetchall()
      if len(import_rows) > 0:
        import_syms = {}
        for row in import_rows:
          operand_names = row["operand_names"]
          if operand_names is not None:
            operand_names = json.loads(operand_names)
          import_syms[row["ea"]] = [
            row["ea"],
            row["cmt1"],
            row["cmt2"],
            operand_names,
            row["name"],
            row["type"],
            row["dis"],
            row["cmt"],
            row["itp"],
          ]

        # Check in the current database
        sql = """ select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.operand_names operand_names, ins.name name, ins.type type, ins.pseudocomment cmt, ins.pseudoitp itp
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
            operand_names = row["operand_names"]
            if operand_names is not None:
              operand_names = json.loads(operand_names)
            matched_syms[row["ea"]] = [
              row["ea"],
              row["cmt1"],
              row["cmt2"],
              operand_names,
              row["name"],
              row["type"],
              row["dis"],
              row["cmt"],
              row["itp"],
            ]

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
            try:
              self.do_import_instruction_level_item(
                diff_rows, import_syms, matched_syms
              )
            except:
              log(f"Error importing item: {str(sys.exc_info()[1])}")
              traceback.print_exc()
    finally:
      cur.close()

  def do_import_one(self, ea1, ea2, force=False):
    cur = self.db_cursor()
    try:
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
          if not set_name(ea1, name, SN_NOWARN | SN_NOCHECK):
            for i in range(10):
              if set_name(ea1, f"{name}_{i}", SN_NOWARN | SN_NOCHECK):
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
    finally:
      cur.close()

  def import_selected(self, items, selected, only_auto):
    log_refresh("Importing selected row(s)...")

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

      self.db.execute("analyze")
      self.db.commit()

      # Update the choosers after importing
      self.update_choosers()
    finally:
      hide_wait_box()

  def update_choosers(self):
    for chooser in [
      self.best_chooser,
      self.partial_chooser,
      self.unreliable_chooser,
    ]:
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
      log(f"import_all(): {str(sys.exc_info()[1])}")
      traceback.print_exc()

  def import_all_auto(self, items):
    try:
      self.do_import_all_auto(items)
    except:
      log(f"import_all(): {str(sys.exc_info()[1])}")
      traceback.print_exc()

  def do_decompile(self, f):
    # pylint: disable-next=unexpected-keyword-arg
    return decompile(f, flags=DECOMP_NO_WAIT)

  def get_plain_microcode_line(self, color_line):
    """
    Remove colors, trailing spaces and the basic block numbers from a microcode
    line.
    """
    plain_line = ida_lines.tag_remove(color_line)
    plain_line = plain_line.strip(" ")

    mnem = None
    tokens = plain_line.split(" ")
    for _, x in enumerate(tokens[1:]):
      if not x.isdigit():
        mnem = x
        pos = plain_line.find(x)
        plain_line = plain_line[pos:]
        break
    return plain_line, mnem

  def get_microcode_bblocks(self, mba):
    mba.build_graph()
    total = mba.qty
    bblocks = {}
    for i in range(total):
      if i == 0:
        continue

      block = mba.get_mblock(i)
      if block.type == hr.BLT_STOP:
        continue

      vp = hr.qstring_printer_t(None, True)
      block._print(vp)
      src = vp.s
      lines = src.splitlines()

      new_lines = []
      for line in lines:
        color_line = line.strip("\n").strip(" ")
        pos = color_line.find(";")
        line_ea = None
        comments = None
        if pos > -1:
          comments = color_line[pos + 1:].strip(" ")
          line_ea = int(comments.split(" ")[0], 16)
          color_line = color_line[:pos]
        plain_line, mnem = self.get_plain_microcode_line(color_line)
        new_lines.append(
          {
            "address": line_ea,
            "line": plain_line,
            "mnemonic": mnem,
            "color_line": color_line,
            "comments": comments,
          }
        )

      bblocks[i] = {"start": block.start, "end": block.end, "lines": new_lines}

    bb_relations = {}
    for i in range(total):
      if i == 0 or i not in bblocks:
        continue

      block = mba.get_mblock(i)
      for succ in block.succset:
        try:
          bb_relations[i].append(succ)
        except KeyError:
          bb_relations[i] = [succ]

    return bblocks, bb_relations

  def get_microcode(self, f, ea):
    if not self.decompiler_available or not self.export_microcode:
      return [], []

    mbr = hr.mba_ranges_t(f)
    hf = hr.hexrays_failure_t()
    ml = hr.mlist_t()
    vp = CPrinter_t()
    mba = hr.gen_microcode(mbr, hf, ml, hr.DECOMP_WARNINGS, hr.MMAT_GENERATED)
    if mba is None:
      return [], []

    mba._print(vp)
    bblocks = []
    bb_relations = []
    bblocks, bb_relations = self.get_microcode_bblocks(mba)

    self.microcode[ea] = []
    for line in vp.mc:
      line = ida_lines.tag_remove(line).strip("\n")
      pos = line.find(";")
      if pos > -1:
        line = line[:pos]

      tokens = re.split(r"\W+", line)
      tokens = list(filter(None, tokens))
      if len(tokens) > 2:
        self.microcode[ea].append(line.strip(" "))
    return bblocks, bb_relations

  def decompile_and_get(self, ea):
    if not self.decompiler_available or is_spec_ea(ea):
      return False

    # Workaround for a bug in IDA that might trigger the following error:
    #
    # max non-trivial tinfo_t count has been reached
    #
    if os.getenv("DIAPHORA_WORKAROUND_MAX_TINFO_T") is not None:
      idaapi.clear_cached_cfuncs()

    decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
    if decompiler_plugin is None:
      decompiler_plugin = "hexrays"
    if not init_hexrays_plugin() and not (
      load_plugin(decompiler_plugin) and init_hexrays_plugin()
    ):
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
        self.pseudo_comments[tl.ea - self.get_base_address()] = [
          str(cmt),
          tl.itp,
        ]

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

    self.microcode[ea] = []
    self.get_microcode(f, ea)
    return first_line

  def guess_type(self, ea):
    t = guess_type(ea)
    if not self.use_decompiler:
      return t
    else:
      try:
        ret = self.decompile_and_get(ea)
        if ret:
          t = ret
      except:
        # pylint: disable-next=consider-using-f-string
        log("Cannot decompile 0x%x: %s" % (ea, str(sys.exc_info()[1])))
    return t

  def register_menu_action(self, action_name, action_desc, handler, hotkey=None):
    show_choosers_action = idaapi.action_desc_t(
      action_name, action_desc, handler, hotkey, None, -1
    )
    idaapi.register_action(show_choosers_action)
    idaapi.attach_action_to_menu(
      f"Edit/Plugins/{action_desc}", action_name, idaapi.SETMENU_APP
    )

  def register_menu(self):
    # pylint: disable-next=global-statement
    global g_bindiff
    g_bindiff = self

    menu_items = [
      [
        "diaphora:show_results",
        "Diaphora - Show results",
        CIdaMenuHandlerShowChoosers(),
        "F3",
      ],
      [
        "diaphora:save_results",
        "Diaphora - Save results",
        CIdaMenuHandlerSaveResults(),
        None,
      ],
      [
        "diaphora:load_results",
        "Diaphora - Load results",
        CIdaMenuHandlerLoadResults(),
        None,
      ],
    ]
    for item in menu_items:
      action_name, action_desc, action_handler, hotkey = item
      self.register_menu_action(action_name, action_desc, action_handler, hotkey)

    warning(
      """AUTOHIDE REGISTRY\nIf you close one tab you can always re-open it by pressing F3
or selecting Edit -> Plugins -> Diaphora - Show results"""
    )

  # Ripped out from REgoogle (which is dead since long ago...)
  def constant_filter(self, value):
    """Filter for certain constants/immediate values. Not all values should be
    taken into account for searching. Especially not very small values that may
    just contain the stack frame size.
    """
    # no small values
    if value < 0x1000:
      return False

    if (
      value & 0xFFFFFF00 == 0xFFFFFF00
      or value & 0xFFFF00 == 0xFFFF00
      or value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00
      or value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00
    ):
      return False

    # no single bits sets - mostly defines / flags
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
    op1 = print_operand(ea, 0)
    op2 = print_operand(ea, 1)
    line = f"{mnem.ljust(8)} {op1}"
    if op2 != "":
      line += f", {op2}"
    return line

  def get_function_names(self, f):
    name = get_func_name(int(f))
    true_name = name
    demangle_named_name = demangle_name(name, INF_SHORT_DN)
    if demangle_named_name == "":
      demangle_named_name = None

    if demangle_named_name is not None:
      name = demangle_named_name

    return name, true_name, demangle_named_name

  def extract_function_callers(self, f):
    # Calculate the callers *but* considering data references to functions from
    # functions as code references.
    callers = list()
    refs = list(CodeRefsTo(f, 0))
    refs.extend(DataRefsTo(f))
    for caller in refs:
      caller_func = get_func(caller)
      if caller_func and caller_func.start_ea not in callers:
        callers.append(caller_func.start_ea)
    return callers

  def extract_function_constants(self, ins, x, constants):
    for operand in ins.ops:
      if operand.type == o_imm:
        if self.is_constant(operand, x) and self.constant_filter(operand.value):
          constants.append(operand.value)
      elif operand.type == o_displ:
        if self.constant_filter(operand.addr):
          constants.append(operand.addr)

      drefs = DataRefsFrom(x)
      for dref in drefs:
        if get_func(dref) is None:
          str_constant = get_strlit_contents(dref, -1, -1)
          if str_constant is not None:
            str_constant = str_constant.decode("utf-8", "backslashreplace")
            if str_constant not in constants:
              constants.append(str_constant)
    return constants

  def extract_function_switches(self, x, switches):
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
        for cur_case in results.cases:
          if "__iter__" not in dir(cur_case):
            break

          can_iter |= True
          for case_id in cur_case:
            switch_cases_values.add(case_id)

        if can_iter:
          switches.append([switch_cases, list(switch_cases_values)])

    return switches

  def extract_function_mdindex(
    self, bb_topological, bb_topological_sorted, bb_edges, bb_topo_num, bb_degree
  ):
    md_index = 0
    if bb_topological:
      bb_topo_order = {}
      for i, scc in enumerate(bb_topological_sorted):
        for bb in scc:
          bb_topo_order[bb] = i
      tuples = []
      for src, dst in bb_edges:
        tuples.append(
          (
            bb_topo_order[bb_topo_num[src]],
            bb_degree[src][0],
            bb_degree[src][1],
            bb_degree[dst][0],
            bb_degree[dst][1],
          )
        )
      rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
      emb_tuples = (
        sum((z0, z1 * rt2, z2 * rt3, z3 * rt5, z4 * rt7))
        for z0, z1, z2, z3, z4 in tuples
      )
      md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
      md_index = str(md_index)
    return md_index

  def extract_function_pseudocode_features(self, f):
    pseudo = None
    pseudo_hash1 = None
    pseudo_hash2 = None
    pseudo_hash3 = None
    pseudo_lines = 0
    pseudocode_primes = None
    if f in self.pseudo:
      pseudo = "\n".join(self.pseudo[f])
      pseudo_lines = len(self.pseudo[f])
      pseudo_hash1, pseudo_hash2, pseudo_hash3 = self.kfh.hash_bytes(
        pseudo
      ).split(";")
      if pseudo_hash1 == "":
        pseudo_hash1 = None
      if pseudo_hash2 == "":
        pseudo_hash2 = None
      if pseudo_hash3 == "":
        pseudo_hash3 = None
      pseudocode_primes = str(self.pseudo_hash[f])
    return (
      pseudo,
      pseudo_lines,
      pseudo_hash1,
      pseudocode_primes,
      pseudo_hash2,
      pseudo_hash3,
    )

  def extract_function_assembly_features(self, assembly, f, image_base):
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
    base = f - image_base
    keys.remove(base)
    keys.insert(0, base)
    for key in keys:
      for line in assembly[key]:
        assembly_addrs.append(line[0])
        asm.append(line[1])
    asm = "\n".join(asm)
    return asm, assembly_addrs

  def get_decoded_instruction(self, x):
    decoded_size, ins = diaphora_decode(x)
    if ins.ops[0].type in [o_mem, o_imm, o_far, o_near, o_displ]:
      decoded_size -= ins.ops[0].offb
    if ins.ops[1].type in [o_mem, o_imm, o_far, o_near, o_displ]:
      decoded_size -= ins.ops[1].offb
    if decoded_size <= 0:
      decoded_size = 1

    return ins, decoded_size

  def extract_function_topological_information(self, bb_relations, bb_topological):
    loops = 0
    strongly_connected = None
    strongly_connected_spp = 0
    bb_topological_sorted = None
    try:
      strongly_connected = strongly_connected_components(bb_relations)
      bb_topological_sorted = robust_topological_sort(bb_topological)
      bb_topological = json.dumps(bb_topological_sorted)
      strongly_connected_spp = 1
      for item in strongly_connected:
        val = len(item)
        if val > 1:
          strongly_connected_spp *= self.primes[val]
    except RecursionError:
      # XXX: FIXME: The original implementation that we're using is recursive
      # and can fail. We really need to create our own non recursive version.
      strongly_connected = []
      bb_topological = None
    except:
      traceback.print_exc()
      raise

    loops = 0
    for sc in strongly_connected:
      if len(sc) > 1:
        loops += 1
      else:
        if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
          loops += 1

    return (
      bb_topological,
      bb_topological_sorted,
      strongly_connected,
      loops,
      strongly_connected_spp,
    )

  def extract_line_mnem_disasm(self, x):
    mnem = print_insn_mnem(x)
    try:
      disasm = GetDisasm(x)
    except UnicodeDecodeError:
      # This is a workaround for a rare error getting the disassembly for a
      # line with some UTF-8 characters that Python fails to handle properly
      disasm = self.get_disasm(x)

    return mnem, disasm

  def extract_microcode(self, f):
    micro = None
    micro_spp = 1
    clean_micro = None
    mnemonics = set()
    if self.export_microcode and f in self.microcode:
      micro = "\n".join(self.microcode[f])
      ret = []
      for line in self.microcode[f]:
        tokens = line.split(" ")
        for x in tokens[1:]:
          if not x.isdigit():
            mnem = x
            mnemonics.add(mnem)
            pos = mnem.find(".")
            if pos > -1:
              mnem = mnem[:pos]
            break

        line = line[line.find(mnem):]
        ret.append(line)
        if mnem in self.microcode_ins_list:
          micro_spp *= self.primes[self.microcode_ins_list.index(mnem)]
        else:
          log(
            f"Warning: Mnemonic {repr(mnem)} not found in the list of microcode instructions!"
          )
      clean_micro = self.get_cmp_asm_lines("\n".join(ret))
    return micro, clean_micro, micro_spp

  def get_microcode_instructions(self):
    if HAS_HEXRAYS:
      instructions = []
      for x in dir(hr):
        if x.startswith("m_"):
          mnem = x[2:]
          if mnem not in instructions:
            instructions.append(x[2:])

      instructions.sort()
      return instructions
    return []

  def read_function(self, ea):
    """
    Extract anything and everything we (might) need from a function.

    This is a horribly big (read: huge) function that, from time to time, I try
    to make a bit smaller. Feel free to do the same...
    """
    name, true_name, demangle_named_name = self.get_function_names(ea)

    # Call hooks immediately after we have a proper function name
    if self.hooks is not None:
      if "before_export_function" in dir(self.hooks):
        ret = self.hooks.before_export_function(ea, name)
        if not ret:
          return False

    f = int(ea)
    func = get_func(f)
    if not func:
      # pylint: disable-next=consider-using-f-string
      log("Cannot get a function object for 0x%x" % f)
      return False

    flow = FlowChart(func)
    size = 0

    if not self.ida_subs:
      # Unnamed function, ignore it...
      if (
        name.startswith("sub_")
        or name.startswith("j_")
        or name.startswith("unknown")
        or name.startswith("nullsub_")
      ):
        debug_refresh(f"Skipping function {repr(name)}")
        return False

      # Already recognized runtime's function?
      flags = get_func_attr(f, FUNCATTR_FLAGS)
      if flags & FUNC_LIB or flags == -1:
        debug_refresh(f"Skipping library function {repr(name)}")
        return False

    if self.exclude_library_thunk:
      # Skip library and thunk functions
      flags = get_func_attr(f, FUNCATTR_FLAGS)
      if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
        debug_refresh(f"Skipping thunk function {repr(name)}")
        return False

      if name.startswith("nullsub_"):
        debug_refresh(f"Skipping nullsub function {repr(name)}")
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
    callers = self.extract_function_callers(f)

    mnemonics_spp = 1
    cpu_ins_list = GetInstructionList()
    cpu_ins_list.sort()

    current_head = BADADDR
    for block in flow:
      if block.end_ea == 0 or block.end_ea == BADADDR:
        # pylint: disable-next=consider-using-f-string
        print(("0x%08x: Skipping bad basic block" % f))
        continue

      nodes += 1
      instructions_data = []

      block_ea = block.start_ea - image_base
      idx = len(bb_topological)
      bb_topological[idx] = []
      bb_topo_num[block_ea] = idx

      for current_head in list(Heads(block.start_ea, block.end_ea)):
        mnem, disasm = self.extract_line_mnem_disasm(current_head)
        size += get_item_size(current_head)
        instructions += 1

        if mnem in cpu_ins_list:
          mnemonics_spp *= self.primes[cpu_ins_list.index(mnem)]

        try:
          assembly[block_ea].append([current_head - image_base, disasm])
        except KeyError:
          if nodes == 1:
            assembly[block_ea] = [[current_head - image_base, disasm]]
          else:
            assembly[block_ea] = [
              # pylint: disable-next=consider-using-f-string
              [current_head - image_base, "loc_%x:" % current_head],
              [current_head - image_base, disasm],
            ]

        ins, decoded_size = self.get_decoded_instruction(current_head)
        constants = self.extract_function_constants(ins, current_head, constants)

        curr_bytes = get_bytes(current_head, decoded_size, False)
        if curr_bytes is None or len(curr_bytes) != decoded_size:
          # pylint: disable-next=consider-using-f-string
          log("Failed to read %d bytes at [%08x]" % (decoded_size, current_head))
          continue

        bytes_hash.append(curr_bytes)
        bytes_sum += sum(curr_bytes)

        function_hash.append(get_bytes(current_head, get_item_size(current_head), False))
        outdegree += len(list(CodeRefsFrom(current_head, 0)))
        mnems.append(mnem)
        op_value = get_operand_value(current_head, 1)
        if op_value == -1:
          op_value = get_operand_value(current_head, 0)

        tmp_name = None
        if op_value != BADADDR and op_value in self.names:
          tmp_name = self.names[op_value]
          demangle_named_name = demangle_name(tmp_name, INF_SHORT_DN)
          if demangle_named_name is not None:
            tmp_name = demangle_named_name
            pos = tmp_name.find("(")
            if pos > -1:
              tmp_name = tmp_name[:pos]

          if not tmp_name.startswith("sub_") and not tmp_name.startswith(
            "nullsub_"
          ):
            names.add(tmp_name)

        # Calculate the callees
        refs = list(CodeRefsFrom(current_head, 0))
        for callee in refs:
          callee_func = get_func(callee)
          if callee_func and callee_func.start_ea != func.start_ea:
            if callee_func.start_ea not in callees:
              callees.append(callee_func.start_ea)

        if len(refs) == 0:
          refs = DataRefsFrom(current_head)

        tmp_type = None
        for ref in refs:
          if ref in self.names:
            tmp_name = self.names[ref]
            tmp_type = idc.get_type(ref)

        ins_cmt1 = GetCommentEx(current_head, 0)
        ins_cmt2 = GetCommentEx(current_head, 1)

        operands_names = []
        # save operands_names
        for index, _ in enumerate(ins.ops):
          if ida_bytes.is_forced_operand(ins.ip, index):
            operand_name = (
              ida_bytes.get_forced_operand(ins.ip, index)
              if ida_bytes.is_forced_operand(ins.ip, index)
              else ""
            )
            operands_names.append([index, operand_name])

        instructions_data.append(
          [
            current_head - image_base,
            mnem,
            disasm,
            ins_cmt1,
            ins_cmt2,
            operands_names,
            tmp_name,
            tmp_type,
          ]
        )

        switches = self.extract_function_switches(current_head, switches)

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
          bb_relations[pred_block.start_ea - image_base].append(
            block.start_ea - image_base
          )
        except KeyError:
          bb_relations[pred_block.start_ea - image_base] = [
            block.start_ea - image_base
          ]

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

    topological_data = self.extract_function_topological_information(
      bb_relations, bb_topological
    )
    (
      bb_topological,
      bb_topological_sorted,
      strongly_connected,
      loops,
      strongly_connected_spp,
    ) = topological_data

    asm, assembly_addrs = self.extract_function_assembly_features(
      assembly, f, image_base
    )
    try:
      clean_assembly = self.get_cmp_asm_lines(asm)
    except:
      clean_assembly = ""
      # pylint: disable-next=consider-using-f-string
      print("Error getting assembly for 0x%x" % f)

    cc = edges - nodes + 2
    proto = self.guess_type(f)
    proto2 = idc.get_type(f)
    try:
      prime = str(self.primes[cc])
    except:
      # pylint: disable-next=consider-using-f-string
      log("Cyclomatic complexity too big: 0x%x -> %d" % (f, cc))
      prime = 0

    comment = idc.get_func_cmt(f, 1)
    bytes_hash = md5(b"".join(bytes_hash)).hexdigest()
    function_hash = md5(b"".join(function_hash)).hexdigest()

    function_flags = get_func_attr(f, FUNCATTR_FLAGS)
    (
      pseudo,
      pseudo_lines,
      pseudo_hash1,
      pseudocode_primes,
      pseudo_hash2,
      pseudo_hash3,
    ) = self.extract_function_pseudocode_features(f)
    microcode, clean_microcode, microcode_spp = self.extract_microcode(f)
    microcode_bblocks, microcode_bbrelations = self.get_microcode(func, ea)
    clean_pseudo = self.get_cmp_pseudo_lines(pseudo)

    md_index = self.extract_function_mdindex(
      bb_topological, bb_topological_sorted, bb_edges, bb_topo_num, bb_degree
    )
    seg_rva = current_head - get_segm_start(current_head)

    kgh = CKoretKaramitasHash()
    kgh_hash = kgh.calculate(f)

    rva = f - self.get_base_address()

    # It's better to have names sorted
    names = list(names)
    names.sort()

    props_list = (
      name,
      nodes,
      edges,
      indegree,
      outdegree,
      size,
      instructions,
      mnems,
      names,
      proto,
      cc,
      prime,
      f,
      comment,
      true_name,
      bytes_hash,
      pseudo,
      pseudo_lines,
      pseudo_hash1,
      pseudocode_primes,
      function_flags,
      asm,
      proto2,
      pseudo_hash2,
      pseudo_hash3,
      len(strongly_connected),
      loops,
      rva,
      bb_topological,
      strongly_connected_spp,
      clean_assembly,
      clean_pseudo,
      mnemonics_spp,
      switches,
      function_hash,
      bytes_sum,
      md_index,
      constants,
      len(constants),
      seg_rva,
      assembly_addrs,
      kgh_hash,
      None,
      None,
      microcode,
      clean_microcode,
      microcode_spp,
      microcode_bblocks,
      microcode_bbrelations,
      callers,
      callees,
      basic_blocks_data,
      bb_relations,
    )

    if self.hooks is not None:
      if "after_export_function" in dir(self.hooks):
        d = self.create_function_dictionary(props_list)
        d = self.hooks.after_export_function(d)
        props_list = self.get_function_from_dictionary(d)

    return props_list

  def get_base_address(self):
    return idaapi.get_imagebase()

  def get_modules_using_lfa(self):
    # First, try to guess modules areas
    _, lfa_modules = lfa.analyze()

    # Next, using IDAMagicStrings, try to guess file names using some heuristics
    func_modules = {}
    if HAS_GET_SOURCE_STRINGS:
      d, _ = get_source_strings()

      # First, put names found with IDAMagicStrings to anonymous modules found
      # with LFA
      for source_file in d:
        for _, func_name, mod_name in d[source_file]:
          func_ea = idc.get_name_ea_simple(func_name)
          if func_ea not in func_modules:
            # print("0x%08x:%s -> %s" % (func_ea, func_name, mod_name))
            func_modules[func_ea] = mod_name
            for module in lfa_modules:
              if func_ea >= module.start and func_ea <= module.end:
                if module.name == "":
                  module.name = mod_name

      #
      # Next sub-step: find the limits of modules with the same name that appear
      # multiple times and update the end address to the last found one.
      #
      new_modules = []
      named_modules = {}
      for module in lfa_modules:
        if module.name != "":
          if module.name not in named_modules:
            named_modules[module.name] = {
              "start": module.start,
              "end": module.end,
            }
          else:
            named_modules[module.name]["end"] = module.end

      areas = []
      for name, module in named_modules.items():
        new_modules.append(
          {"name": name, "start": module["start"], "end": module["end"]}
        )
        areas.append([module["start"], module["end"]])

      #
      # Next step: find all the modules, discard anonymous modules that fall in
      # the area (start and end addres) of named modules and return a list with
      # the proper modules, both anonymous and otherwise.
      #
      for module in lfa_modules:
        if module.name != "":
          continue

        found = False
        for start, end in areas:
          if module.start >= start and module.end <= end:
            found = True
            break

        if not found:
          d = {"name": module.name, "start": module.start, "end": module.end}
          new_modules.append(d)

    for module in new_modules:
      local_primes = 1
      pseudo_primes = 1
      total_funcs = 0
      for func in Functions(module["start"], module["end"]):
        if func in self._funcs_cache:
          total_funcs += 1
          _, primes_value, pseudocode_primes = self._funcs_cache[func]
          if pseudocode_primes is not None:
            pseudo_primes *= int(pseudocode_primes)
          if primes_value is not None:
            local_primes *= int(primes_value)

      module["total"] = str(total_funcs)
      module["primes"] = str(local_primes)
      module["pseudo_primes"] = str(pseudo_primes)

    return new_modules

  def save_compilation_units(self):
    log("Finding compilation units...")
    lfa_modules = self.get_modules_using_lfa()

    sql1 = """insert into compilation_units (name, start_ea, end_ea)
                  values (?, ?, ?)"""
    sql2 = """insert or ignore into compilation_unit_functions(
                    cu_id, func_id)
                  values (?, ?)"""
    sql3 = """ update compilation_units
          set primes_value = ?,
            pseudocode_primes = ?,
            functions = ?
        where id = ? """
    sql4 = """ update functions set source_file = ? where id = ? """
    cur = self.db_cursor()
    try:
      dones = set()
      for module in lfa_modules:
        module_name = None
        if module["name"] != "":
          module_name = module["name"]

        vals = (module["name"], str(module["start"]), str(module["end"]))
        cur.execute(sql1, vals)
        cu_id = cur.lastrowid

        for func in Functions(module["start"], module["end"]):
          # Some functions (like thunk ones) might be ignored when exporting
          if func in self._funcs_cache:
            func_id, _, _ = self._funcs_cache[func]
            if func_id not in dones:
              dones.add(func_id)
              cur.execute(sql2, (cu_id, func_id))
              cur.execute(sql4, (module_name, func_id))

        cur.execute(
          sql3,
          [module["primes"], module["pseudo_primes"], module["total"], cu_id],
        )
        if cur.rowcount == 0:
          raise Exception(
            "Unable to UPDATE the primes for a compilation unit!"
          )
    except:
      print(f"ERROR saving compilation unit: {str(sys.exc_info()[1])}")
      raise
    finally:
      cur.close()

  def save_callgraph(self, primes, all_primes, md5sum):
    cur = self.db_cursor()
    try:
      sql = "insert into main.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)"
      proc = idaapi.get_idp_name()
      if BADADDR == 0xFFFFFFFFFFFFFFFF:
        proc += "64"
      cur.execute(sql, (primes, all_primes, proc, md5sum))
    finally:
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
          log(f"Error: {str(sys.exc_info()[1])}")
          return ""
    return ""

  def export_structures(self):
    # It seems that get_ordinal_qty, sometimes, can return negative
    # numbers, according to one beta-tester. My guess is that it's a bug
    # in IDA. However, as we cannot reproduce, at least handle this
    # condition.
    local_types = idc.get_ordinal_qty()
    if (local_types & 0x80000000) != 0:
      # pylint: disable-next=consider-using-f-string
      message = "warning: get_ordinal_qty returned a negative number (0x%x)!" % local_types
      log(message)
      return

    for i in range(local_types):
      name = idc.get_numbered_type_name(i + 1)
      definition = self.GetLocalType(
        i + 1, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI | PRTYPE_PRAGMA
      )
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
          name = f"unsigned {name}"

      self.add_program_data(type_name, name, definition)

  def get_til_names(self):
    idb_path = get_idb_path()
    filename, _ = os.path.splitext(idb_path)
    til_path = f"{filename}.til"

    with open(til_path, "rb") as f:
      line = f.readline()
      pos = line.find(b"Local type definitions")
      if pos > -1:
        tmp = line[pos + len(b"Local type definitions") + 1:]
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
    results_db = diaphora.sqlite3_connect(filename)

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
        message = f"The version of the diff results is {version} and current version is {diaphora.VERSION_VALUE}, there can be some incompatibilities."
        Warning(message)

      self.reinit(main_db, diff_db)

      min_ratio = float(self.get_value_for("MINIMUM_IMPORT_RATIO", 0.5))
      log(f"Minimum import threshold {min_ratio}")

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
          log(f"Match {name1}-{name2} is excluded")
          continue

        bb1 = int(row["bb1"])
        bb2 = int(row["bb2"])

        choose.add_item(
          diaphora.CChooser.Item(
            ea1, name1, ea2, name2, desc, ratio, bb1, bb2
          )
        )

      sql = "select * from unmatched"
      cur.execute(sql)
      for row in diaphora.result_iter(cur):
        if row["type"] == "primary":
          choose = self.unmatched_primary
        else:
          choose = self.unmatched_second
        choose.add_item(
          diaphora.CChooser.Item(int(row["address"], 16), row["name"])
        )

      self.import_all_auto(self.best_chooser.items)
      self.import_all_auto(self.partial_chooser.items)

      return True
    finally:
      cur.close()
      results_db.close()

    return False

  def load_results(self, filename):
    results_db = diaphora.sqlite3_connect(filename)

    ret = False
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
        log(f"Primary database {main_db} not found.")
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
        elif row["type"] == "multimatch":
          choose = self.multimatch_chooser
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

        choose.add_item(
          diaphora.CChooser.Item(
            ea1, name1, ea2, name2, desc, ratio, bb1, bb2
          )
        )

      sql = "select * from unmatched"
      cur.execute(sql)
      for row in diaphora.result_iter(cur):
        if row["type"] == "primary":
          choose = self.unmatched_primary
        else:
          choose = self.unmatched_second
        choose.add_item(
          diaphora.CChooser.Item(int(row["address"], 16), row["name"])
        )

      log("Showing diff results.")
      self.show_choosers()
      ret = True
    finally:
      cur.close()
      results_db.close()

    return ret

  def re_diff(self):
    self.best_chooser.Close()
    self.partial_chooser.Close()
    self.multimatch_chooser.Close()
    if self.unreliable_chooser is not None:
      self.unreliable_chooser.Close()
    if self.unmatched_primary is not None:
      self.unmatched_primary.Close()
    if self.unmatched_second is not None:
      self.unmatched_second.Close()

    _diff_or_export(
      use_ui=True, file_in=self.last_diff_db, project_script=self.project_script
    )

  def equal_db(self):
    are_equal = diaphora.CBinDiff.equal_db(self)
    if are_equal:
      if (
        ask_yn(
          0,
          "HIDECANCEL\nThe databases seems to be 100% equal. Do you want to continue anyway?",
        )
        != 1
      ):
        self.do_continue = False
    return are_equal


#-------------------------------------------------------------------------------
def _diff_or_export(use_ui, **options):
  # pylint: disable-next=global-statement
  global g_bindiff
  total_functions = len(list(Functions()))
  if get_idb_path() == "" or total_functions == 0:
    warning(
      "No IDA database opened or no function in the database.\nPlease open an IDA database and create some functions before running this script."
    )
    return None

  opts = BinDiffOptions(**options)

  if use_ui:
    x = CBinDiffExporterSetup()
    x.Compile()
    x.set_options(opts)

    if not x.Execute():
      return None

    opts = x.get_options()

  if opts.file_out == opts.file_in:
    warning("Both databases are the same file!")
    return None
  elif opts.file_out == "" or len(opts.file_out) < 5:
    warning(
      "No output database selected or invalid filename. Please select a database file."
    )
    return None
  elif is_ida_file(opts.file_in) or is_ida_file(opts.file_out):
    warning(
      "One of the selected databases is an IDA file. Please select only database files."
    )
    return None

  export = True
  if os.path.exists(opts.file_out):
    crash_file = f"{opts.file_out}-crash"
    resume_crashed = False
    crashed_before = False
    if os.path.exists(crash_file):
      crashed_before = True
      ret = ask_yn(
        1,
        "The previous export session crashed. Do you want to resume the previous crashed session?",
      )
      if ret == -1:
        log("Cancelled")
        return None
      elif ret == 1:
        resume_crashed = True

    if not resume_crashed and not crashed_before:
      ret = ask_yn(
        0, "Export database already exists. Do you want to overwrite it?"
      )
      if ret == -1:
        log("Cancelled")
        return None

      if ret == 0:
        export = False

    if export:
      if g_bindiff is not None:
        g_bindiff = None

      if not resume_crashed:
        remove_file(opts.file_out)
        log(f"Database {repr(opts.file_out)} removed")
        if os.path.exists(crash_file):
          os.remove(crash_file)

  t0 = time.monotonic()
  try:
    bd = CIDABinDiff(opts.file_out)
    bd.use_decompiler = opts.use_decompiler
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
    bd.export_microcode = opts.export_microcode
    bd.sql_max_processed_rows = config.SQL_MAX_PROCESSED_ROWS
    bd.timeout = config.SQL_TIMEOUT_LIMIT * max(total_functions / 20000, 1)
    bd.project_script = opts.project_script

    if export:
      exported = False
      if os.getenv("DIAPHORA_PROFILE") is not None:
        log("*** Profiling export ***")
        # pylint: disable-next=import-outside-toplevel
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
          log(f"Aborted by user, removing crash file {opts.file_out}-crash...")
          os.remove(f"{opts.file_out}-crash")

      if exported:
        final_t = time.monotonic() - t0
        # pylint: disable-next=consider-using-f-string
        log(f"Database exported, time taken: {datetime.timedelta(seconds=final_t)}.")
        hide_wait_box()

    if opts.file_in != "":
      if os.getenv("DIAPHORA_PROFILE") is not None:
        log("*** Profiling diff ***")
        # pylint: disable-next=import-outside-toplevel
        import cProfile

        profiler = cProfile.Profile()
        profiler.runcall(bd.diff, opts.file_in)
        profiler.print_stats(sort="time")
      else:
        bd.diff(opts.file_in)
  except:
    print((f"Error: {sys.exc_info()[1]}"))
    traceback.print_exc()
  finally:
    hide_wait_box()

  return bd


#-------------------------------------------------------------------------------
def _generate_html(db1, diff_db, ea1, ea2, html_asm, html_pseudo):
  bd = CIDABinDiff(db1)
  bd.db = diaphora.sqlite3_connect(db1)
  bd.load_results(diff_db)
  bd.save_pseudo_diff(ea1, ea2, html_pseudo)
  bd.save_asm_diff(ea1, ea2, html_asm)


#-------------------------------------------------------------------------------
class BinDiffOptions:
  def __init__(self, **kwargs):
    total_functions = len(list(Functions()))
    sqlite_db = os.path.splitext(get_idb_path())[0] + ".sqlite"
    self.file_out = kwargs.get("file_out", sqlite_db)
    self.file_in = kwargs.get("file_in", "")
    self.use_decompiler = kwargs.get(
      "use_decompiler", config.EXPORTING_USE_DECOMPILER
    )
    self.exclude_library_thunk = kwargs.get(
      "exclude_library_thunk", config.EXPORTING_EXCLUDE_LIBRARY_THUNK
    )

    self.relax = kwargs.get("relax")
    if self.relax:
      warning(MSG_RELAXED_RATIO_ENABLED)

    self.unreliable = kwargs.get("unreliable", config.DIFFING_ENABLE_UNRELIABLE)
    self.slow = kwargs.get(
      "slow", total_functions <= config.MIN_FUNCTIONS_TO_DISABLE_SLOW
    )
    self.experimental = kwargs.get(
      "experimental", config.DIFFING_ENABLE_EXPERIMENTAL
    )
    self.min_ea = kwargs.get("min_ea", get_inf_attr(INF_MIN_EA))
    self.max_ea = kwargs.get("max_ea", get_inf_attr(INF_MAX_EA))
    self.ida_subs = kwargs.get("ida_subs", config.EXPORTING_ONLY_NON_IDA_SUBS)
    self.ignore_sub_names = kwargs.get(
      "ignore_sub_names", config.DIFFING_IGNORE_SUB_FUNCTION_NAMES
    )
    self.ignore_all_names = kwargs.get(
      "ignore_all_names", config.DIFFING_IGNORE_ALL_FUNCTION_NAMES
    )
    self.ignore_small_functions = kwargs.get(
      "ignore_small_functions", config.DIFFING_IGNORE_SMALL_FUNCTIONS
    )

    # Enable, by default, exporting only function summaries for huge dbs.
    too_big_db = total_functions > config.MIN_FUNCTIONS_TO_CONSIDER_HUGE
    self.func_summaries_only = kwargs.get("func_summaries_only", too_big_db)
    if too_big_db:
      warning(MSG_FUNCTION_SUMMARIES_ONLY)

    # Python script to run for both the export and diffing process
    self.project_script = kwargs.get("project_script")

    # Microcode slows down the export process and might cause false positives
    # with big to huge databases, disable it by default for 'big' databases
    medium_db = total_functions <= config.MIN_FUNCTIONS_TO_CONSIDER_MEDIUM
    self.export_microcode = kwargs.get("export_microcode", medium_db)


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

  _style = (
    """
  table.diff_tab {
  font-family: Courier, monospace;
  table-layout: fixed;
  width: 100%;
  }

  .diff_add {
  background-color: """
    + config.DIFF_COLOR_ADDED
    + """;
  }
  .diff_chg {
  background-color: """
    + config.DIFF_COLOR_CHANGED
    + """;
  }
  .diff_sub {
  background-color: """
    + config.DIFF_COLOR_SUBTRACTED
    + """;
  }
  .diff_lineno {
  text-align: right;
  background-color: """
    + config.DIFF_COLOR_LINE_NO
    + """;
  }
  """
  )

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
    all_the_rows = (
      all_the_rows.replace("\x00+", '<span class="diff_add">')
      .replace("\x00-", '<span class="diff_sub">')
      .replace("\x00^", '<span class="diff_chg">')
      .replace("\x01", "</span>")
      .replace("\t", 4 * "&nbsp;")
    )

    res = self._html_template % {"style": self._style, "rows": all_the_rows}
    return res

  def _stop_wasting_space(self, s):
    """I never understood why you'd want to have 13 spaces between instruction and args'"""
    m = self._rexp_too_much_space.search(s)
    if m:
      mlen = len(m.group(0))
      return s[: mlen - 4] + s[mlen:]
    else:
      return s


#-------------------------------------------------------------------------------
try:

  class CAstVisitorInherits(ctree_visitor_t):
    pass

except:

  class CAstVisitorInherits:
    pass


#-------------------------------------------------------------------------------
# pylint: disable=super-init-not-called
# pylint: disable=non-parent-init-called
# pylint: disable=arguments-differ
class CAstVisitor(CAstVisitorInherits):
  def __init__(self, cfunc):
    self.primes = primesbelow(4096)
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

# pylint: enable=arguments-differ
# pylint: enable=non-parent-init-called
# pylint: enable=super-init-not-called

#-------------------------------------------------------------------------------
def is_ida_file(filename):
  filename = filename.lower()
  return (
    filename.endswith(".idb")
    or filename.endswith(".i64")
    or filename.endswith(".til")
    or filename.endswith(".id0")
    or filename.endswith(".id1")
    or filename.endswith(".nam")
  )


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
        funcs = [
          "functions",
          "program",
          "program_data",
          "version",
          "instructions",
          "basic_blocks",
          "bb_relations",
          "bb_instructions",
          "function_bblocks",
          "compilation_units",
          "compilation_unit_functions",
        ]
        for func in funcs:
          db.execute(f"drop table if exists {func}")
      finally:
        cur.close()


#-------------------------------------------------------------------------------
def main():
  # pylint: disable-next=global-statement
  global g_bindiff

  # EXPORT
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
      log(f"Database {repr(file_out)} removed")

    bd = CIDABinDiff(file_out)
    project_script = os.getenv("DIAPHORA_PROJECT_SCRIPT")
    if project_script is not None:
      bd.project_script = project_script
    bd.use_decompiler = use_decompiler

    bd.exclude_library_thunk = bd.get_value_for(
      "exclude_library_thunk", bd.exclude_library_thunk
    )
    bd.ida_subs = bd.get_value_for("ida_subs", bd.ida_subs)
    bd.ignore_sub_names = bd.get_value_for("ignore_sub_names", bd.ignore_sub_names)
    bd.function_summaries_only = bd.get_value_for(
      "function_summaries_only", bd.function_summaries_only
    )
    bd.min_ea = int(bd.get_value_for("from_address", "0"), 16)
    bd.export_microcode = bd.get_value_for(
      "self.export_microcode", bd.export_microcode
    )

    _to_ea = bd.get_value_for("to_address", None)
    if _to_ea is not None:
      bd.max_ea = int(_to_ea, 16)

    try:
      bd.export()
    except KeyboardInterrupt:
      log(f"Aborted by user, removing crash file {file_out}-crash...")
      os.remove(f"{file_out}-crash")

    idaapi.qexit(0)

  # DIFF-SHOW
  elif os.getenv("DIAPHORA_AUTO_HTML") is not None:
    debug_refresh("Handling DIAPHORA_AUTO_HTML")
    debug_refresh(f'DIAPHORA_AUTO_HTML={os.getenv("DIAPHORA_AUTO_HTML")}')
    debug_refresh(f'DIAPHORA_DB1={os.getenv("DIAPHORA_DB1")}')
    debug_refresh(f'DIAPHORA_DB2={os.getenv("DIAPHORA_DB2")}')
    debug_refresh(f'DIAPHORA_DIFF={os.getenv("DIAPHORA_DIFF")}')
    debug_refresh(f'DIAPHORA_EA1={os.getenv("DIAPHORA_EA1")}')
    debug_refresh(f'DIAPHORA_EA2={os.getenv("DIAPHORA_EA2")}')
    debug_refresh(f'DIAPHORA_HTML_ASM={os.getenv("DIAPHORA_HTML_ASM")}')
    debug_refresh(f'DIAPHORA_HTML_PSEUDO={os.getenv("DIAPHORA_HTML_PSEUDO")}')
    db1 = os.getenv("DIAPHORA_DB1")
    if db1 is None:
      raise Exception("No database file specified!")
    diff_db = os.getenv("DIAPHORA_DIFF")
    if diff_db is None:
      raise Exception("No diff database file for diff specified!")
    ea1 = os.getenv("DIAPHORA_EA1")
    if ea1 is None:
      raise Exception("No address 1 specified!")
    ea2 = os.getenv("DIAPHORA_EA2")
    if ea2 is None:
      raise Exception("No address 2 specified!")
    html_asm = os.getenv("DIAPHORA_HTML_ASM")
    if html_asm is None:
      raise Exception("No html output file for asm specified!")
    html_pseudo = os.getenv("DIAPHORA_HTML_PSEUDO")
    if html_pseudo is None:
      raise Exception("No html output file for pseudo specified!")
    _generate_html(db1, diff_db, ea1, ea2, html_asm, html_pseudo)
    idaapi.qexit(0)
  else:
    _diff_or_export(True)


if __name__ == "__main__":
  main()
