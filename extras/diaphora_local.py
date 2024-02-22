#!/usr/bin/python3

"""
Diaphora, a binary diffing tool
Copyright (c) 2015-2024, Joxean Koret

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

import re
import os
import sys
import time
import difflib

import idc
import idaapi
import idautils

from PyQt5 import QtWidgets
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import NasmLexer, CppLexer, DiffLexer

#-------------------------------------------------------------------------------
DIFF_COLOR_ADDED      = "#aaffaa"
DIFF_COLOR_CHANGED    = "#ffff77"
DIFF_COLOR_SUBTRACTED = "#ffaaaa"
DIFF_COLOR_LINE_NO    = "#e0e0e0"

#-------------------------------------------------------------------------------
def log(msg):
  idaapi.msg(f"[{time.asctime()}] {msg}")

#-------------------------------------------------------------------------------
def do_decompile(f):
  return idaapi.decompile(f, flags=idaapi.DECOMP_NO_WAIT)

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
    + DIFF_COLOR_ADDED
    + """;
  }
  .diff_chg {
  background-color: """
    + DIFF_COLOR_CHANGED
    + """;
  }
  .diff_sub {
  background-color: """
    + DIFF_COLOR_SUBTRACTED
    + """;
  }
  .diff_lineno {
  text-align: right;
  background-color: """
    + DIFF_COLOR_LINE_NO
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
class CHtmlViewer(idaapi.PluginForm):
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
    return idaapi.PluginForm.Show(self, title)

#-------------------------------------------------------------------------------
def decompile_and_get(ea):
  decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
  if decompiler_plugin is None:
    decompiler_plugin = "hexrays"
  if not idaapi.init_hexrays_plugin() and not (
    load_plugin(decompiler_plugin) and idaapi.init_hexrays_plugin()
  ):
    return False

  f = idaapi.get_func(ea)
  if f is None:
    return False

  cfunc = do_decompile(f)
  if cfunc is None:
    # Failed to decompile
    return False

  sv = cfunc.get_pseudocode()
  lines = []
  first_line = None
  for sline in sv:
    line = idaapi.tag_remove(sline.line)
    if line.startswith("//"):
      continue

    if first_line is None:
      first_line = line
    else:
      lines.append(line)

  return first_line, "\n".join(lines)

#-------------------------------------------------------------------------------
def get_disasm(ea):
  mnem = idc.print_insn_mnem(ea)
  op1 = idc.print_operand(ea, 0)
  op2 = idc.print_operand(ea, 1)
  line = f"{mnem.ljust(8)} {op1}"
  if op2 != "":
    line += f", {op2}"
  return line

#-------------------------------------------------------------------------------
def get_assembly(ea):
  f = int(ea)
  func = idaapi.get_func(f)
  if not func:
    log("Cannot get a function object for 0x%x" % f)
    return False

  lines = []
  flow = idaapi.FlowChart(func)
  for block in flow:
    if block.end_ea == 0 or block.end_ea == idaapi.BADADDR:
      log("0x%08x: Skipping bad basic block" % f)
      continue

    if block.start_ea != func.start_ea:
      lines.append("loc_%08x:" % (block.start_ea))
    for head in idautils.Heads(block.start_ea, block.end_ea):
      lines.append("     %s" % (get_disasm(head)))

  return "\n".join(lines)

#-------------------------------------------------------------------------------
class CLocalDiffer:
  def __init__(self):
    pass

  def get_pseudo_diff_data(self, ea1, ea2):
    html_diff = CHtmlDiff()
    tmp = decompile_and_get(int(ea1))
    if not tmp:
      log("[i] Cannot get the pseudo-code for the current function")
      return False
    proto1, tmp1 = tmp
    buf1 = proto1 + "\n" + tmp1

    tmp = decompile_and_get(int(ea2))
    if not tmp:
      log("Cannot get the pseudo-code for the second function")
      return False
    proto2, tmp2 = tmp
    buf2 = proto2 + "\n" + tmp2

    if buf1 == buf2:
      warning("Both pseudo-codes are equal.")

    fmt = HtmlFormatter()
    fmt.noclasses = True
    fmt.linenos = False
    fmt.nobackground = True
    src = html_diff.make_file(
      buf1.split("\n"), buf2.split("\n"), fmt, CppLexer()
    )

    name1 = idaapi.get_func_name(int(ea1))
    name2 = idaapi.get_func_name(int(ea2))
    title = f'Diff pseudo-code {name1} - {name2}'
    res = (src, title)
    return res

  def get_asm_diff_data(self, ea1, ea2):
    html_diff = CHtmlDiff()
    asm1 = get_assembly(ea1)
    asm2 = get_assembly(ea2)
    name1 = idaapi.get_func_name(int(ea1))
    name2 = idaapi.get_func_name(int(ea2))
    buf1 = f'{name1} proc near\n{asm1}\n{name1} endp'
    buf2 = f'{name2} proc near\n{asm2}\n{name2} endp'

    fmt = HtmlFormatter()
    fmt.noclasses = True
    fmt.linenos = False
    fmt.nobackground = True
    src = html_diff.make_file(
      buf1.split("\n"), buf2.split("\n"), fmt, NasmLexer()
    )

    title = f"Diff assembly {name1} - {name2}"
    res = (src, title)
    return res

  def diff_pseudo(self, main_ea, diff_ea):
    res = self.get_pseudo_diff_data(main_ea, diff_ea)
    self.show_res(res)

  def diff_assembly(self, main_ea, diff_ea):
    res = self.get_asm_diff_data(main_ea, diff_ea)
    self.show_res(res)

  def show_res(self, res):
    if res:
      (src, title) = res
      cdiffer = CHtmlViewer()
      cdiffer.Show(src, title)

  def diff(self, main_ea, diff_ea):
    self.diff_assembly(main_ea, diff_ea)
    self.diff_pseudo(main_ea, diff_ea)

#-------------------------------------------------------------------------------
class myplugin_t(idaapi.plugin_t):
  flags = idaapi.PLUGIN_UNL
  comment = "Locally diff functions"
  help = "Tool to diff functions inside this database"
  wanted_name = "Diaphora: Diff Local Function"
  wanted_hotkey = "Ctrl+Shift+D"

  def init(self):
    return idaapi.PLUGIN_OK

  def run(self, arg):
    main()

  def term(self):
    pass

def PLUGIN_ENTRY():
  return myplugin_t()

#-------------------------------------------------------------------------------
def main():
  ea = idc.get_screen_ea()
  func = idaapi.get_func(ea)
  if func is None:
    warning("Please place the cursor over a function before calling this plugin.")
    return

  func_name = idaapi.get_func_name(ea)
  line = f"Select the function to diff {func_name} against"
  diff_ea = idc.choose_func(line)
  if diff_ea == idaapi.BADADDR:
    return

  log("Selected function address 0x%08x\n" % diff_ea)
  differ = CLocalDiffer()
  differ.diff(ea, diff_ea)

if __name__ == "__main__":
  main()
