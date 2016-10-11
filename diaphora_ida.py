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
import sys
import time
import json
import decimal
import difflib
import sqlite3
import traceback
from hashlib import md5

import diaphora

from pygments import highlight
from pygments.lexers import NasmLexer, CppLexer
from pygments.formatters import HtmlFormatter

from others.tarjan_sort import strongly_connected_components, robust_topological_sort

from jkutils.factor import primesbelow as primes

import idaapi
from idc import *
from idaapi import *
from idautils import *

try:
  if IDA_SDK_VERSION < 690:
    # In versions prior to IDA 6.9 PySide is used...
    from PySide import QtGui
    QtWidgets = QtGui
    is_pyqt5 = False
  else:
    # ...while in IDA 6.9, they switched to PyQt5
    from PyQt5 import QtCore, QtGui, QtWidgets
    is_pyqt5 = True
except ImportError:
  pass

#-----------------------------------------------------------------------
# Constants unexported in IDA Python
PRTYPE_SEMI = 0x0008

# Messages
MSG_RELAXED_RATIO_ENABLED = """AUTOHIDE DATABASE\n<b>Relaxed ratio calculations</b> will be enabled. It will ignore many small
modifications to functions and will match more functions with higher ratios. Enable this option if you're only interested in the
new functionality. Disable it for patch diffing if you're interested in small modifications (like buffer sizes).
<br><br>
This is automatically done for diffing big databases (more than 20,000 functions in the database).<br><br>
You can disable it by un-checking the 'Relaxed calculations of differences ratios' option."""

MSG_FUNCTION_SUMMARIES_ONLY = """AUTOHIDE DATABASE\n<b>Do not export basic blocks or instructions</b> will be enabled.<br>
It will not export the information relative to basic blocks or<br>
instructions and 'Diff assembly in a graph' will not be available.
<br><br>
This is automatically done for exporting huge databases with<br>
more than 100,000 functions.<br><br>
You can disable it by un-checking the 'Do not export basic blocks<br>
or instructions' option."""

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
# TODO: FIX hack
diaphora.log = log
diaphora.log_refresh = log_refresh

#-----------------------------------------------------------------------
g_bindiff = None
def show_choosers():
  global g_bindiff
  if g_bindiff is not None:
    g_bindiff.show_choosers(True)

#-----------------------------------------------------------------------
def save_results():
  global g_bindiff
  if g_bindiff is not None:
    filename = AskFile(1, "*.diaphora", "Select the file to store diffing results")
    if filename is not None:
      g_bindiff.save_results(filename)

#-----------------------------------------------------------------------
def load_results():
  tmp_diff = CIDABinDiff(":memory:")
  filename = AskFile(0, "*.diaphora", "Select the file to load diffing results")
  if filename is not None:
    tmp_diff.load_results(filename)

#-----------------------------------------------------------------------
def import_definitions():
  tmp_diff = diaphora.CBinDiff(":memory:")
  filename = AskFile(0, "*.sqlite", "Select the file to import structures, unions and enumerations from")
  if filename is not None:
    if askyn_c(1, "HIDECANCEL\nDo you really want to import all structures, unions and enumerations?") == 1:
      tmp_diff.import_definitions_only(filename)

#-----------------------------------------------------------------------
class CHtmlViewer(PluginForm):
  def OnCreate(self, form):
    if is_pyqt5:
      self.parent = self.FormToPyQtWidget(form)
    else:
      self.parent = self.FormToPySideWidget(form)
    self.PopulateForm()

    self.browser = None
    self.layout = None
    return 1

  def PopulateForm(self):
    self.layout = QtWidgets.QVBoxLayout()
    self.browser = QtWidgets.QTextBrowser()
    self.browser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
    self.browser.setHtml(self.text)
    self.browser.setReadOnly(True)
    self.browser.setFontWeight(12)
    self.layout.addWidget(self.browser)
    self.parent.setLayout(self.layout)

  def Show(self, text, title):
    self.text = text
    return PluginForm.Show(self, title)

#-----------------------------------------------------------------------
class CIDAChooser(diaphora.CChooser, Choose2):

  def __init__(self, title, bindiff, show_commands=True):
    diaphora.CChooser.__init__(self, title, bindiff, show_commands)
    if title.startswith("Unmatched in"):
      Choose2.__init__(self, title, [ ["Line", 8], ["Address", 8], ["Name", 20] ], Choose2.CH_MULTI)
    else:
      Choose2.__init__(self, title, [ ["Line", 8], ["Address", 8], ["Name", 20], ["Address 2", 8], ["Name 2", 20],
                                      ["Ratio", 5], ["BBlocks 1", 5], ["BBlocks 2", 5], ["Description", 30] ], Choose2.CH_MULTI)

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
    except:
      pass
    return True

  def OnRefresh(self, n):
    return n

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
      self.cmd_save_results = self.AddCommand("Save diffing results")
    elif not self.show_commands and (self.cmd_show_asm is None or force):
      self.cmd_show_asm = self.AddCommand("Show assembly")
      self.cmd_show_pseudo = self.AddCommand("Show pseudo-code")

    return True

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
    elif cmd_id == self.cmd_save_results:
      filename = AskFile(1, "*.diaphora", "Select the file to store diffing results")
      if filename is not None:
        self.bindiff.save_results(filename)

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

  NOTE: Don't select IDA database files (.IDB, .I64) as only SQLite databases are considered.
"""
    args = {'iFileSave': Form.FileInput(save=True, swidth=40),
            'iFileOpen': Form.FileInput(open=True, swidth=40),
            'iMinEA': Form.NumericInput(tp=Form.FT_HEX, swidth=22),
            'iMaxEA': Form.NumericInput(tp=Form.FT_HEX, swidth=22),
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
                                               "rIgnoreSmallFunctions"))}
    Form.__init__(self, s, args)

  def set_options(self, opts):
    if opts.file_out is not None:
      self.iFileSave.value = opts.file_out
    if opts.file_in is not None:
      self.iFileOpen.value = opts.file_in

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
      func_summaries_only = self.rFuncSummariesOnly.checked
    )
    return BinDiffOptions(**opts)

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
class CIDABinDiff(diaphora.CBinDiff):
  def __init__(self, db_name):
    diaphora.CBinDiff.__init__(self, db_name, chooser=CIDAChooser)
    self.names = dict(Names())
    self.min_ea = MinEA()
    self.max_ea = MaxEA()

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
    # And, finally, show the list of best and partial matches and
    # register the hotkey for re-opening results
    self.show_choosers()
    self.register_menu()
    hide_wait_box()
    return res

  def do_export(self):
    i = 0
    callgraph_primes = 1
    callgraph_all_primes = {}
    func_list = list(Functions(self.min_ea, self.max_ea))
    total_funcs = len(func_list)
    t = time.time()

    self.db.execute("PRAGMA synchronous = OFF")
    self.db.execute("BEGIN transaction")
    for func in func_list:
      i += 1
      if (total_funcs > 100) and i % (total_funcs/100) == 0 or i == 1:
        line = "Exported %d function(s) out of %d total.\nElapsed %d:%02d:%02d second(s), remaining time ~%d:%02d:%02d"
        elapsed = time.time() - t
        remaining = (elapsed / i) * (total_funcs - i)

        m, s = divmod(remaining, 60)
        h, m = divmod(m, 60)
        m_elapsed, s_elapsed = divmod(elapsed, 60)
        h_elapsed, m_elapsed = divmod(m_elapsed, 60)

        replace_wait_box(line % (i, total_funcs, h_elapsed, m_elapsed, s_elapsed, h, m, s))

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
      if total_funcs > 1000 and i % (total_funcs/1000) == 0:
        self.db.commit()
        self.db.execute("PRAGMA synchronous = OFF")
        self.db.execute("BEGIN transaction")

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
      LoadTil(row["name"])
    cur.close()
    Wait()

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
      if GetStrucIdByName(the_name) == BADADDR:
        type_name = "struct"
        if row["type"] == "enum":
          type_name = "enum"
        elif row["type"] == "union":
          type_name == "union"

        new_rows.add(row)
        ret = ParseTypes("%s %s;" % (type_name, row["name"]))
        if ret != 0:
          pass

    for i in xrange(10):
      for row in new_rows:
        if row["name"] is None:
          continue

        the_name = row["name"].split(" ")[0]
        if GetStrucIdByName(the_name) == BADADDR and GetStrucIdByName(row["name"]) == BADADDR:
          definition = self.get_valid_definition(row["value"])
          ret = ParseTypes(definition)
          if ret != 0:
            pass

    cur.close()
    Wait()

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
      Warning("Sorry, there is no assembly available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      html_diff = CHtmlDiff()
      asm1 = self.prettify_asm(row1["assembly"])
      asm2 = self.prettify_asm(row2["assembly"])
      buf1 = "%s proc near\n%s\n%s endp" % (row1["name"], asm1, row1["name"])
      buf2 = "%s proc near\n%s\n%s endp" % (row2["name"], asm2, row2["name"])
      src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))

      title = "Diff assembler %s - %s" % (row1["name"], row2["name"])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

    cur.close()

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
      Warning("Sorry, there is no pseudo-code available for the selected function.")
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

      html_diff = CHtmlDiff()
      buf1 = row1["prototype"] + "\n" + row1["pseudocode"]
      buf2 = row2["prototype"] + "\n" + row2["pseudocode"]
      src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))

      title = "Diff pseudo-code %s - %s" % (row1["name"], row2["name"])
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

    cur.close()

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

  def import_instruction(self, ins_data1, ins_data2):
    ea1 = self.get_base_address() + int(ins_data1[0])
    ea2, cmt1, cmt2, name, mtype = ins_data2
    # Set instruction level comments
    if cmt1 is not None and get_cmt(ea1, 0) is None:
      set_cmt(ea1, cmt1, 0)

    if cmt2 is not None and get_cmt(ea1, 1) is None:
      set_cmt(ea1, cmt1, 1)

    tmp_ea = None
    set_type = False
    data_refs = list(DataRefsFrom(ea1))
    if len(data_refs) > 0:
      # Global variables
      tmp_ea = data_refs[0]
      if tmp_ea in self.names:
        curr_name = GetTrueName(tmp_ea)
        if curr_name != name and self.is_auto_generated(curr_name):
          MakeName(tmp_ea, name)
          set_type = False
      else:
        MakeName(tmp_ea, name)
        set_type = True
    else:
      # Functions
      code_refs = list(CodeRefsFrom(ea1, 0))
      if len(code_refs) == 0:
        code_refs = list(CodeRefsFrom(ea1, 1))

      if len(code_refs) > 0:
        curr_name = GetTrueName(code_refs[0])
        if curr_name != name and self.is_auto_generated(curr_name):
          MakeName(code_refs[0], name)
          tmp_ea = code_refs[0]
          set_type = True

    if tmp_ea is not None and set_type:
      if mtype is not None and GetType(tmp_ea) != mtype:
        SetType(tmp_ea, mtype)

  def import_instruction_level(self, ea1, ea2, cur):
    cur = self.db_cursor()
    try:
      # Check first if we have any importable items
      sql = """ select ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.name name, ins.type type
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
                     or ins.name is not null) """
      cur.execute(sql, (ea2,))
      import_rows = cur.fetchall()
      if len(import_rows) > 0:
        import_syms = {}
        for row in import_rows:
          import_syms[row["dis"]] = [row["ea"], row["cmt1"], row["cmt2"], row["name"], row["type"]]

        # Check in the current database
        sql = """ select ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.name name, ins.type type
                    from function_bblocks bb,
                         functions f,
                         bb_instructions bbi,
                         instructions ins
                   where f.id = bb.function_id
                     and bbi.basic_block_id = bb.basic_block_id
                     and ins.id = bbi.instruction_id
                     and f.address = ?"""
        cur.execute(sql, (ea1,))
        match_rows = cur.fetchall()
        if len(match_rows) > 0:
          matched_syms = {}
          for row in match_rows:
            matched_syms[row["dis"]] = [row["ea"], row["cmt1"], row["cmt2"], row["name"], row["type"]]

          # We have 'something' to import, let's diff the assembly...
          sql = """select *
                     from (
                   select assembly, 1
                     from functions
                    where address = ?
                      and assembly is not null
             union select assembly, 2
                     from diff.functions
                    where address = ?
                      and assembly is not null)
                    order by 2 asc"""
          cur.execute(sql, (ea1, ea2))
          diff_rows = cur.fetchall()
          if len(diff_rows) > 0:
            lines1 = diff_rows[0]["assembly"]
            lines2 = diff_rows[1]["assembly"]

            matches = {}
            to_line = None
            change_line = None
            diff_list = difflib.ndiff(lines1.splitlines(1), lines2.splitlines(1))
            for x in diff_list:
              if x[0] == '-':
                change_line = x[1:].strip(" ").strip("\r").strip("\n")
              elif x[0] == '+':
                to_line = x[1:].strip(" ").strip("\r").strip("\n")
              elif change_line is not None:
                change_line = None

              if to_line is not None and change_line is not None:
                matches[change_line] = to_line
                if change_line in matched_syms and to_line in import_syms:
                  self.import_instruction(matched_syms[change_line], import_syms[to_line])
                change_line = to_line = None
    finally:
      cur.close()

  def do_import_one(self, ea1, ea2, force = False):
    cur = self.db_cursor()
    sql = "select prototype, comment, mangled_function, function_flags from diff.functions where address = ?"
    cur.execute(sql, (ea2,))
    row = cur.fetchone()
    if row is not None:
      proto = row["prototype"]
      comment = row["comment"]
      name = row["mangled_function"]
      flags = row["function_flags"]

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

      self.import_instruction_level(ea1, ea2, cur)

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
      total = 0
      for ea in to_import:
        ea = str(ea)
        new_func = self.read_function(ea)
        self.delete_function(ea)
        self.save_function(new_func)
        total += 1
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

  def decompile_and_get(self, ea):
    if not init_hexrays_plugin() and not (load_plugin("hexrays") and init_hexrays_plugin()):
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

  def register_menu(self):
    global g_bindiff
    g_bindiff = self

    idaapi.add_menu_item("Edit/Plugins/", "Diaphora - Show results", "F3", 0, show_choosers, ())
    idaapi.add_menu_item("Edit/Plugins/", "Diaphora - Save results", None, 0, save_results, ())
    idaapi.add_menu_item("Edit/Plugins/", "Diaphora - Load results", None, 0, load_results, ())
    Warning("""AUTOHIDE REGISTRY\nIf you close one tab you can always re-open it by pressing F3
or selecting Edit -> Plugins -> Diaphora - Show results""")

  def read_function(self, f, discard=False):
    name = GetFunctionName(int(f))
    true_name = name
    demangled_name = Demangle(name, INF_SHORT_DN)
    if demangled_name is not None:
      name = demangled_name

    f = int(f)
    func = get_func(f)
    if not func:
      log("Cannot get a function object for 0x%x" % f)
      return False

    flow = FlowChart(func)
    size = 0

    if not self.ida_subs:
      # Unnamed function, ignore it...
      if name.startswith("sub_") or name.startswith("j_") or name.startswith("unknown"):
        return False

      # Already recognized runtime's function?
      flags = GetFunctionFlags(f)
      if flags & FUNC_LIB or flags == -1:
        return False

    if self.exclude_library_thunk:
      # Skip library and thunk functions
      flags = GetFunctionFlags(f)
      if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
        return False

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

    mnemonics_spp = 1
    cpu_ins_list = GetInstructionList()
    cpu_ins_list.sort()

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
        size += ItemSize(x)
        instructions += 1

        if mnem in cpu_ins_list:
          mnemonics_spp += self.primes[cpu_ins_list.index(mnem)]

        try:
          assembly[block_ea].append(disasm)
        except KeyError:
          if nodes == 1:
            assembly[block_ea] = [disasm]
          else:
            assembly[block_ea] = ["loc_%x:" % x, disasm]


        decoded_size = idaapi.decode_insn(x)
        if idaapi.cmd.Operands[0].type in [o_mem, o_imm, o_far, o_near, o_displ]:
          decoded_size -= idaapi.cmd.Operands[0].offb
        if idaapi.cmd.Operands[1].type in [o_mem, o_imm, o_far, o_near, o_displ]:
          decoded_size -= idaapi.cmd.Operands[1].offb
        if decoded_size <= 0:
          decoded_size = 1

        curr_bytes = GetManyBytes(x, decoded_size)
        if curr_bytes is None or len(curr_bytes) != decoded_size:
            log("Failed to read %d bytes at [%08x]" % (decoded_size, x))
            continue

        bytes_hash.append(curr_bytes)
        bytes_sum += sum(map(ord, curr_bytes))

        function_hash.append(GetManyBytes(x, ItemSize(x)))
        outdegree += len(list(CodeRefsFrom(x, 0)))
        mnems.append(mnem)
        op_value = GetOperandValue(x, 1)
        if op_value == -1:
          op_value = GetOperandValue(x, 0)

        tmp_name = None
        if op_value != BADADDR and op_value in self.names:
          tmp_name = self.names[op_value]
          demangled_name = Demangle(tmp_name, INF_SHORT_DN)
          if demangled_name is not None:
            tmp_name = demangled_name
          if not tmp_name.startswith("sub_"):
            names.add(tmp_name)

        l = list(CodeRefsFrom(x, 0))
        if len(l) == 0:
          l = DataRefsFrom(x)

        tmp_type = None
        for ref in l:
          if ref in self.names:
            tmp_name = self.names[ref]
            tmp_type = GetType(ref)

        ins_cmt1 = GetCommentEx(x, 0)
        ins_cmt2 = GetCommentEx(x, 1)
        instructions_data.append([x - image_base, mnem, disasm, ins_cmt1, ins_cmt2, tmp_name, tmp_type])

        switch = get_switch_info_ex(x)
        if switch:
          switch_cases = switch.get_jtable_size()
          results = calc_switch_cases(x, switch)

          # It seems that IDAPython for idaq64 has some bug when reading
          # switch's cases. Do not attempt to read them if the 'cur_case'
          # returned object is not iterable.
          can_iter = False
          switch_cases_values = set()
          for idx in xrange(len(results.cases)):
            cur_case = results.cases[idx]
            if not '__iter__' in dir(cur_case):
              break

            can_iter |= True
            for cidx in xrange(len(cur_case)):
              case_id = cur_case[cidx]
              switch_cases_values.add(case_id)

          if can_iter:
            switches.append([switch_cases, list(switch_cases_values)])

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

    asm = []
    keys = assembly.keys()
    keys.sort()

    # After sorting our the addresses of basic blocks, be sure that the
    # very first address is always the entry point, no matter at what
    # address it is.
    keys.remove(f - image_base)
    keys.insert(0, f - image_base)
    for key in keys:
      asm.extend(assembly[key])
    asm = "\n".join(asm)

    cc = edges - nodes + 2
    proto = self.guess_type(f)
    proto2 = GetType(f)
    try:
      prime = str(self.primes[cc])
    except:
      log("Cyclomatic complexity too big: 0x%x -> %d" % (f, cc))
      prime = 0

    comment = GetFunctionCmt(f, 1)
    bytes_hash = md5("".join(bytes_hash)).hexdigest()
    function_hash = md5("".join(function_hash)).hexdigest()

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

    clean_assembly = self.get_cmp_asm_lines(asm)
    clean_pseudo = self.get_cmp_pseudo_lines(pseudo)

    rva = f - self.get_base_address()
    return (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
             proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
             pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
             pseudo_hash2, pseudo_hash3, len(strongly_connected), loops, rva, bb_topological,
             strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches,
             function_hash, bytes_sum,
             basic_blocks_data, bb_relations)

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
    ret = GetLocalTinfo(ordinal)
    if ret is not None:
      (stype, fields) = ret
      if stype:
        name = GetLocalTypeName(ordinal)
        return idc_print_type(stype, fields, name, flags)
    return ""

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
      name = GetLocalTypeName(i+1)
      definition = self.GetLocalType(i+1, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI | PRTYPE_PRAGMA)
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

  def load_results(self, filename):
    results_db = sqlite3.connect(filename)
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

      main_db = row["main_db"]
      diff_db = row["diff_db"]
      if not os.path.exists(main_db):
        log("Primary database %s not found." % main_db)
        main_db = AskFile(0, main_db, "Select the primary database path")
        if main_db is None:
          return False

      if not os.path.exists(diff_db):
        diff_db = AskFile(0, main_db, "Select the secondary database path")
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

    ret = askyn_c(1, "Do you want to show only the new matches?")
    if ret == -1:
      return
    elif ret == 0:
      self.matched1 = set()
      self.matched2 = set()

    self.diff(self.last_diff_db)

  def equal_db(self):
    are_equal = diaphora.CBinDiff.equal_db(self)
    if are_equal:
      if askyn_c(0, "HIDECANCEL\nThe databases seems to be 100% equal. Do you want to continue anyway?") != 1:
        self.do_continue = False
    return are_equal

#-----------------------------------------------------------------------
def _diff_or_export(use_ui, **options):
  global g_bindiff

  total_functions = len(list(Functions()))
  if GetIdbPath() == "" or total_functions == 0:
    Warning("No IDA database opened or no function in the database.\nPlease open an IDA database and create some functions before running this script.")
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
    Warning("Both databases are the same file!")
    return
  elif opts.file_out == "" or len(opts.file_out) < 5:
    Warning("No output database selected or invalid filename. Please select a database file.")
    return
  elif is_ida_file(opts.file_in) or is_ida_file(opts.file_out):
    Warning("One of the selected databases is an IDA file. Please select only database files")
    return

  export = True
  if os.path.exists(opts.file_out):
    ret = askyn_c(0, "Export database already exists. Do you want to overwrite it?")
    if ret == -1:
      log("Cancelled")
      return

    if ret == 0:
      export = False

    if export:
      if g_bindiff is not None:
        g_bindiff = None
      remove_file(opts.file_out)
      log("Database %s removed" % repr(opts.file_out))

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
    print("Error: %s" % sys.exc_info()[1])
    traceback.print_exc()

  return bd

#-----------------------------------------------------------------------
class BinDiffOptions:
  def __init__(self, **kwargs):
    total_functions = len(list(Functions()))
    sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
    self.file_out = kwargs.get('file_out', sqlite_db)
    self.file_in  = kwargs.get('file_in', '')
    self.use_decompiler = kwargs.get('use_decompiler', True)
    self.exclude_library_thunk = kwargs.get('exclude_library_thunk', True)
    self.unreliable = kwargs.get('unreliable', True)
    self.slow = kwargs.get('slow', True)
    # Enable, by default, relaxed calculations on difference ratios for
    # 'big' databases (>20k functions)
    self.relax = kwargs.get('relax', total_functions > 20000)
    if self.relax:
      Warning(MSG_RELAXED_RATIO_ENABLED)
    self.experimental = kwargs.get('experimental', False)
    self.min_ea = kwargs.get('min_ea', MinEA())
    self.max_ea = kwargs.get('max_ea', MaxEA())
    self.ida_subs = kwargs.get('ida_subs', True)
    self.ignore_sub_names = kwargs.get('ignore_sub_names', True)
    self.ignore_all_names = kwargs.get('ignore_all_names', False)
    self.ignore_small_functions = kwargs.get('ignore_small_functions', False)
    # Enable, by default, exporting only function summaries for huge dbs.
    self.func_summaries_only = kwargs.get('func_summaries_only', total_functions > 100000)

#-----------------------------------------------------------------------
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

  def make_file(self, lhs, rhs):
    rows = []
    for left, right, changed in difflib._mdiff(lhs, rhs):
        lno, ltxt = left
        rno, rtxt = right
        ltxt = self._stop_wasting_space(ltxt)
        rtxt = self._stop_wasting_space(rtxt)
        ltxt = self._trunc(ltxt, changed).replace(" ", "&nbsp;")
        rtxt = self._trunc(rtxt, changed).replace(" ", "&nbsp;")
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

  def _trunc(self, s, changed, max_col=120):
    if not changed:
        return s[:max_col]

    # Don't count markup towards the length.
    outlen = 0
    push = 0
    for i, ch in enumerate(s):
        if ch == "\x00": # Followed by an additional byte that should also not count
            outlen -= 1
            push = True
        elif ch == "\x01":
            push = False
        else:
            outlen += 1
        if outlen == max_col:
            break

    res = s[:i + 1]
    if push:
        res += "\x01"

    return res

#-----------------------------------------------------------------------
class CAstVisitor(ctree_visitor_t):
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

#-----------------------------------------------------------------------
def is_ida_file(filename):
  filename = filename.lower()
  return filename.endswith(".idb") or filename.endswith(".i64") or \
         filename.endswith(".til") or filename.endswith(".id0") or \
         filename.endswith(".id1") or filename.endswith(".nam")

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
def main():
  if os.getenv("DIAPHORA_AUTO") is not None:
    file_out = os.getenv("DIAPHORA_EXPORT_FILE")
    if file_out is None:
      raise Exception("No export file specified!")

    use_decompiler = os.getenv("DIAPHORA_USE_DECOMPILER")
    if use_decompiler is None:
      use_decompiler = False

    idaapi.autoWait()

    if os.path.exists(file_out):
      if g_bindiff is not None:
        g_bindiff = None

      remove_file(file_out)
      log("Database %s removed" % repr(file_out))

    bd = CIDABinDiff(file_out)
    bd.use_decompiler_always = use_decompiler
    bd.export()

    idaapi.qexit(0)
  else:
    _diff_or_export(True)

if __name__ == "__main__":
  main()
