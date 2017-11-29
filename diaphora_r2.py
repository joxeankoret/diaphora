#!/usr/bin/python
"""
Diaphora, a diffing plugin for Radare2
Copyright (c) 2017, Sergi Alvarez

Based on IDA backend by:
Copyright (c) 2015-2017, Joxean Koret

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
import re
import ntpath
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

import r2pipe

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
BADADDR = 0xFFFFFFFFFFFFFFFF
r2 = None

#-----------------------------------------------------------------------

def block_succs(addr):
  res = []
  try:
    bb = r2.cmdj("afbj.@%s"%(addr))
  except:
    print("NO BASIC BLOCK AT %s"%(addr))
    return res
  bb = bb[0]
  try:
    res.append(int(bb["jump"]))
  except:
    pass
  try:
    res.append(int(bb['fail']))
  except:
    pass
  return res

def block_preds(addr):
  res = []
  try:
    bbs = r2.cmdj("afbj@%s"%(addr))
  except:
    print("NO BASIC BLOCKS FOR %s"%(addr))
    return res
  if not bbs:
    print("EMPTY BB LIST FOR %s"%(addr))
    return res
  for bb in bbs:
    try:
      if +bb["jump"] == addr:
        res.push (+bb["addr"])
    except:
      pass
    try:
      if +bb["fail"] == addr:
        res.push (+bb["addr"])
    except:
      pass
  return res

def GetMaxLocalType():
  # It's used, in IDA, to return the total number of structs, enums and
  # unions. I doubt there is something similar in r2.
  return int(r2.cmd('t~?'))

def get_switch_info_ex(ea):
  # TODO
  return []

def int16(x):
  try:
    return int(x, 16)
  except:
    if x != "":
      print "ERROR converting %s"%x
    return 0

def GetLocalTypeName(x):
  return ""

#-----------------------------------------------------------------------
def CodeRefsTo(x, y):
  # TODO: Return a list of code references to address 'x'. The value 'y',
  # in IDA, is used to consider the previous instruction (y=1) as a valid
  # code reference or if it should be ignored (y=0).
  return map(int16, r2.cmd('axtq.@ %s'%(x)).split('\n'))

def CodeRefsFrom(x, y):
  # ???
  return map(int16, r2.cmd('axfq.@ %s'%(x)).split('\n'))

def GetOperandValue(x, y):
  # TODO XXX
  return 0

#-----------------------------------------------------------------------
def r2_get_imagebase():
  #ep = ((int(r2.cmd("ieq"), 16) >> 24) << 24)
  ep = int(r2.cmd("S.~[0]"), 16)
  print "IMAGE BASE %s"%ep
  return ep

#-----------------------------------------------------------------------
def r2_get_idp_name():
  # TODO: idaapi.get_idp_name() returns the current processor (CPU arch)
  # of the opened binary.
  return r2.cmd('ij~{core.arch}')
  #return r2.cmd('e asm.arch')

#-----------------------------------------------------------------------
def GetStructIdByName(x):
  # Relevant to structs: get the internal id of a struct by its name.
  return None

#-----------------------------------------------------------------------
def decompile(ea):
  # If only it was that easy... Will partially work.
  return r2.cmd("pdc @ %s"%(ea))

#-----------------------------------------------------------------------
def get_func(ea):
  # In IDA, it should return a "function object". Mostly specific to get
  # the start and end address, as well as the size, etc...
  return {}

#-----------------------------------------------------------------------
def GetInstructionList():
  # TODO: Return a list of the total mnemonics supported by the current
  # disassembler. It's used to calculate the small-primes-product of the
  # function, by assigning a prime correspondent to the mnemonic in the
  # given list. Example:
  #
  # CPU_MY_ARCH = ["push", "pop", "call", "ret", "mov"]
  #
  # Given than example instruction set, push would be 2, pop 3, call 5,
  # ret 7 and mov 11. Then, for a function like this:
  #
  # push 1
  # pop  y
  # call x
  # ret
  #
  # ...it would calculate a SPP of 2*3*5*7 (210). If the instructions
  # are re-ordered, it will still give out the same "hash" value and,
  # also, if there are different instructions when comparing 2 functions
  # we can just remove all the common primes in the 2 sets and determine
  # which are the specific instructions that are different between them.
  #
  return []

#-----------------------------------------------------------------------
def Heads(startEA, endEA):
  # TODO: Return a list with all the instructions between 'startEA', the
  # start address, and 'endEA', the end address.
  res = r2.cmd("pId %d @ %s~[0]"%(endEA - startEA, startEA))
  return map(int16, res.split("\n"))

def GetCommentEx(x, type):
  return r2.cmd("CC.@ %s"%(x))

def diaphora_decode(x):
  decoded_size = int(r2.cmd("ao~size[1]"))
  #opinfo = r2.cmdj("aoj")
  ins = {'Operands': []}
  #ins["Operands"] = [ ] # XXX
  # if ins.Operands[0].type in [o_mem, o_imm, o_far, o_near, o_displ]:
  # AttributeError: 'unicode' object has no attribute 'Operands'
  return decoded_size, ins

#-----------------------------------------------------------------------
def SegStart(ea):
  # Just return the segment's start address
  return int(r2.cmd("S.~[0]"), 16)

#-----------------------------------------------------------------------
def GetFunctionFlags(fcn):
  # TODO: Return if it looks like a function library, a thunk or a jump
  return -1 # FUNC_LIB

#-----------------------------------------------------------------------
def GuessType(ea):
  # TODO: It should return the guessed type of the current function.
  #
  # For example: for a strcpy like function, it should return a prototype
  # like:
  #
  # char __cdecl *strcpy(char *dst, const char *src);
  #
  # NOTE: It expects a semi-colon (;) at the end of the prototype.
  # NOTE 2: The calling convention is optional.
  return None

#-----------------------------------------------------------------------
def GetFunctionCmt(ea, type):
  # Simply return the function's comment, if any
  return r2.cmd("CCf")

#-----------------------------------------------------------------------
def GetType(ea):
  # Used to get the already set type of the specified function. It is a
  # bit different to GuessType. GuessType() guesses the type regardless
  # of it being set or not. GetType() just returns whatever type is set
  # to the function
  return None

#-----------------------------------------------------------------------
def GetManyBytes(ea, size, use_dbg=False):
  # Return a buffer with the contents from 'ea' (address) to 'ea' + size.
  # The option argument 'use_dbg' is used to determine if the buffer is
  # read from the file or from memory (if using a debugger). That 3rd
  # optional parameter makes no sense in Diaphora.
  bytes = r2.cmdj('p8j %s @ %s'%(size, ea))
  return "".join(map(chr, bytes))


#-----------------------------------------------------------------------
def GetInputFileMD5():
  md5 = r2.cmd("!rahash2 -qa md5 $R2_FILE").split(" ")[0]
  print ("MD5 %s"%(md5))
  return "md5here"

#-----------------------------------------------------------------------
def MinEA():
    addresses = []
    r2_cmd_output = r2.cmd('S~:[6]')
    r2_cmd_output = r2_cmd_output.splitlines()
    if len(r2_cmd_output) > 1:
        for i in range(0,len(r2_cmd_output)):
            addresses.append(int(r2_cmd_output[i],16))
        return min(addresses)
    else:
        return int(r2.cmd('S~:[6]'),16)

#-----------------------------------------------------------------------
def MaxEA():
  # TODO: Return the maximum (read, last) address in the database.
  # For example, if the last segment in the program being analysed does
  # end at 0x401FFF, then, that's the maximum address.
  return int(r2.cmd('S=~:-1[3]'), 16)

def GetMnem(x):
  return r2.cmd('pi 1 @ %s'%(x)).split(' ')[0]

def GetDisasm(x):
  return r2.cmd('pi 1 @ %s'%(x))

def ItemSize(x):
  return int(r2.cmd('ao~size[1]'), 16)
#-----------------------------------------------------------------------
def askyn_c(a, b):
  # It doesn't make any sense to me for the r2 exporter. askyn_c is used
  # in IDA to show a dialog and ask the reverser to answer "Yes" or "No".
  return

#-----------------------------------------------------------------------
def Functions(min=0, max=0):
  print "LIST OF FUNCTION"
  ret = []
  fcns = r2.cmdj("aflj")
  if not fcns:
    print "[ERROR] No functions found"
    return ret
  for fcn in fcns:
    print(fcn['name'])
    ret.append(str(fcn['offset']))
  return ret

#-----------------------------------------------------------------------
def Names():
  # TODO: Return a dictionary with {"name_of_thing":0xaddress}
  #
  # Example: {"main": 0x401000, "foo":0x4010200, "global_var": 0x402010}
  res = {}
  for flag in r2.cmd("f").split("\n"):
    w = flag.split(" ")
    res[w[2]] = w[0]
  return res

#-----------------------------------------------------------------------
def log(msg):
  print("[%s] %s\n" % (time.asctime(), msg))

#-----------------------------------------------------------------------
def show_wait_box(msg, show=False):
  print(msg)

#-----------------------------------------------------------------------
def replace_wait_box(msg, show=False):
  print(msg)

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
def import_definitions():
  tmp_diff = diaphora.CBinDiff(":memory:")
  filename = AskFile(0, "*.sqlite", "Select the file to import structures, unions and enumerations from")
  if filename is not None:
    if askyn_c(1, "HIDECANCEL\nDo you really want to import all structures, unions and enumerations?") == 1:
      tmp_diff.import_definitions_only(filename)

#-----------------------------------------------------------------------
class timeraction_t(object):
  def __init__(self, func, args, interval):
    self.func = func
    self.args = args
    self.interval = interval
    self.obj = None # idaapi.register_timer(self.interval, self)
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
    self.obj = None # idaapi.register_timer(self.interval, self)
    if self.obj is None:
      raise RuntimeError, "Failed to register timer"
    self.g = g

  def __call__(self):
    if not "GetTForm" in dir(self.g):
      f = find_tform(self.g._title)
    else:
      f = self.g.GetTForm()

    switchto_tform(f, 1)
    process_ui_action("GraphZoomFit", 0)
    return -1

#-----------------------------------------------------------------------
class CDiffGraphViewer():
  def __init__(self, title, g, colours):
    try:
      GraphViewer.__init__(self, title, False)
      self.graph = g[0]
      self.relations = g[1]
      self.nodes = {}
      self.colours = colours
    except:
      print("CDiffGraphViewer: OnInit!!! " + str(sys.exc_info()[1]))

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
    diaphora.CBinDiff.__init__(self, db_name)
    self.names = [] # TODO dict(Names())
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
    # hide_wait_box()
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
    print "FUNC LISTING IS %s"%(func_list)
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

      print "PROPS FOR FUNC cur %s"%(func)
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
      print "Done"
      #hide_wait_box()

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
      print("Sorry, there is no assembly available for either the first or the second database.")
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

    print "IMPORT ONE"
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
      print("Sorry, there is no assembly available for the selected function.")
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
      print("Sorry, there is no pseudo-code available for the selected function.")
    else:
      fmt = HtmlFormatter()
      fmt.noclasses = True
      fmt.linenos = True
      func = "%s\n%s" % (row["prototype"], row["pseudocode"])
      src = highlight(func, CppLexer(), fmt)
      title = "Pseudo-code for %s" % row["name"]
      print(title)
      print(src)
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
      print("Sorry, there is no pseudo-code available for either the first or the second database.")
    else:
      row1 = rows[0]
      row2 = rows[1]

      html_diff = CHtmlDiff()
      buf1 = row1["prototype"] + "\n" + row1["pseudocode"]
      buf2 = row2["prototype"] + "\n" + row2["pseudocode"]
      src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))

      title = "Diff pseudo-code %s - %s" % (row1["name"], row2["name"])
      print(title)
      print(src)

    cur.close()

  def graph_diff(self, ea1, name1, ea2, name2):
    g1 = self.get_graph(str(ea1), True)
    g2 = self.get_graph(str(ea2))

    if g1 == ({}, {}) or g2 == ({}, {}):
      print("Sorry, graph information is not available for one of the databases.")
      return False

    colours = self.compare_graphs(g1, ea1, g2, ea2)

    title1 = "Graph for %s (primary)" % name1
    title2 = "Graph for %s (secondary)" % name2
    graph1 = CDiffGraphViewer(title1, g1, colours[0])
    graph2 = CDiffGraphViewer(title2, g2, colours[1])
    graph1.Show()
    graph2.Show()

    set_dock_pos(title1, title2, DP_RIGHT)
    uitimercallback_t(graph1, 10)
    uitimercallback_t(graph2, 10)

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
        cur.execute(sql, (str(ea1),))
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
        print "FCN IMPORT %s"%ea
        new_func = self.read_function(ea)
        self.delete_function(ea)
        self.save_function(new_func)
        total += 1
      self.db.commit()
    finally:
      print "Nothing"
      #hide_wait_box()

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
    #decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
    #if decompiler_plugin is None:
    #  decompiler_plugin = "hexrays"
    #if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
    #  return False

    f = get_func(ea)
    if f is None:
      return False

    cfunc = decompile(ea);
    if cfunc is None:
      # Failed to decompile
      return False

    self.pseudo_hash[ea] = 0 #visitor.primes_hash

    sv = cfunc # cfunc.get_pseudocode();
    self.pseudo[ea] = []
    first_line = None
    return sv.split('\n')[0]

  def guess_type(self, ea):
    t = GuessType(ea)
    if self.use_decompiler_always:
      try:
        ret = self.decompile_and_get(ea)
        if ret:
          t = ret
      except:
        log("Cannot decompile 0x%x: %s" % (ea, str(sys.exc_info()[1])))
    return t

  def register_menu_action(self, action_name, action_desc, handler, hotkey = None):
    print "NOPE"

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

    print("""AUTOHIDE REGISTRY\nIf you close one tab you can always re-open it by pressing F3
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
    if value < 0x10000:
      return False

    if value & 0xFFFFFF00 == 0xFFFFFF00 or value & 0xFFFF00 == 0xFFFF00 or \
       value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00 or \
       value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
      return False

    #no single bits sets - mostly defines / flags
    for i in xrange(64):
      if value == (1 << i):
        return False

    return True

  def is_constant(self, oper, ea):
    value = oper.value
    # make sure, its not a reference but really constant
    if value in DataRefsFrom(ea):
      return False

    return True

  # Most important function
  def read_function(self, f, discard=False):
    print "READ F %s"%f
    fcns = r2.cmdj("afij @ %s"%(f))
    if len(fcns) < 1:
      print("Cannot find function at %s"%(f))
      return False
    fcninfo = fcns[0]
    fcninfo.update({'startEA': fcninfo['offset']})
    name = fcninfo["name"]
    true_name = name
    demangled_name = r2.cmd("is.@ %s"%(f))
    if demangled_name == "":
      demangled_name = None

    if demangled_name is not None:
      name = demangled_name

    # WTF
    f = int(f)

    flow = r2.cmdj("afbj@ %s"%(f))
    size = 0

    if not self.ida_subs:
      # Unnamed function, ignore it...
      if name.startswith("sub.") or name.startswith("unk."):
        return False

      # TODO Already recognized runtime's function?
      #flags = GetFunctionFlags(f)
      #if flags & FUNC_LIB or flags == -1:
      #  return False

    #if self.exclude_library_thunk:
      # Skip library and thunk functions
    #  flags = GetFunctionFlags(f)
    #  if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
    #    return False

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

    mnemonics_spp = 1
    cpu_ins_list = GetInstructionList()
    cpu_ins_list.sort()

    image_base = self.get_base_address()
    print "FLOW %s"%(flow)
    for block in flow:
      nodes += 1
      block_startEA = +block['addr'];
      block_endEA = +block['addr'] + +block['size'];
      block.update({'startEA': block_startEA})
      block.update({'endEA': block_endEA})
      print "BB %s %s"%(block_startEA, block_endEA)
      instructions_data = []

      block_ea = block_startEA - image_base
      idx = len(bb_topological)
      bb_topological[idx] = []
      bb_topo_num[block_ea] = idx

      for x in list(Heads(block_startEA, block_endEA)):
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
            try:
              assembly[block_ea] = ["loc_%x:" % x, disasm]
            except:
              assembly[block_ea] = ["loc_%s:" % x, disasm]

        decoded_size, ins = diaphora_decode(x)
        #if ins.Operands[0].type in [o_mem, o_imm, o_far, o_near, o_displ]:
        #  decoded_size -= ins.Operands[0].offb
        #if ins.Operands[1].type in [o_mem, o_imm, o_far, o_near, o_displ]:
        #  decoded_size -= ins.Operands[1].offb
        #if decoded_size <= 0:
        #  decoded_size = 1

        for oper in []: # TODO ins.Operands:
          if oper.type == o_imm:
            if self.is_constant(oper, x) and self.constant_filter(oper.value):
              constants.append(oper.value)
          elif oper.type == o_mem or oper.type == o_idpspec0:
            drefs = list(DataRefsFrom(x))
            if len(drefs) > 0:
              for dref in drefs:
                if get_func(dref) is None:
                  str_constant = GetString(dref, -1, -1)
                  if str_constant is not None:
                    constants.append(oper.value)

        curr_bytes = GetManyBytes(x, decoded_size, False)
        if curr_bytes is None or len(curr_bytes) != decoded_size:
            log("Failed to read %s bytes at [%s]" % (decoded_size, x))
            continue

        bytes_hash.append(curr_bytes)
        bytes_sum += sum(map(ord, curr_bytes))

        function_hash.append(GetManyBytes(x, ItemSize(x), False))
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
      if block_ea not in bb_degree:
        # bb in degree, out degree
        bb_degree[block_ea] = [0, 0]

      #for succ_block in []: # TODO block.succs():
      for succ_block in block_succs(block_startEA):
        succ_base = succ_block - image_base #.startEA - image_base
        bb_relations[block_ea].append(succ_base)
        bb_degree[block_ea][1] += 1
        bb_edges.append((block_ea, succ_base))
        if succ_base not in bb_degree:
          bb_degree[succ_base] = [0, 0]
        bb_degree[succ_base][0] += 1

        edges += 1
        indegree += 1
        if not dones.has_key(succ_block):
          dones[succ_block] = 1

      for pred_block in block_preds(block_startEA):
        try:
          bb_relations[pred_block - image_base].append(block.startEA - image_base)
        except KeyError:
          bb_relations[pred_block - image_base] = [block.startEA - image_base]

        edges += 1
        outdegree += 1
        #if not dones.has_key(succ_block):
        #  dones[succ_block] = 1
        if not dones.has_key(pred_block):
          dones[pred_block] = 1

    for block in flow:
      block_startEA = +block['addr'];
      block_ea = block_startEA - image_base
      for succ_block in block_succs(block_startEA):
        succ_base = block_startEA - image_base
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
    keys = assembly.keys()
    keys.sort()

    # After sorting our the addresses of basic blocks, be sure that the
    # very first address is always the entry point, no matter at what
    # address it is.
    try:
      keys.remove(f - image_base)
    except:
      pass
    keys.insert(0, f - image_base)
    for key in keys:
      try:
        asm.extend(assembly[key])
      except:
        print sys.exc_info()[0].message
        pass
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

    try:
      clean_assembly = self.get_cmp_asm_lines(asm)
    except:
      clean_assembly = ""
      print "Error getting assembly for 0x%x" % f

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

    x = f
    seg_rva = x - SegStart(x)

    rva = f - self.get_base_address()
    return (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
             proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
             pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
             pseudo_hash2, pseudo_hash3, len(strongly_connected), loops, rva, bb_topological,
             strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches,
             function_hash, bytes_sum, md_index, constants, len(constants), seg_rva,
             basic_blocks_data, bb_relations)

  def get_base_address(self):
    return r2_get_imagebase()

  def save_callgraph(self, primes, all_primes, md5sum):
    cur = self.db_cursor()
    sql = "insert into main.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)"
    proc = r2_get_idp_name()
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

    # XXX this is not working
    for i in range(local_types):
      name = GetLocalTypeName(i+1)
      definition = "" # self.GetLocalType(i+1, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI | PRTYPE_PRAGMA)
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
    idb_path = "" # GetIdbPath()
    filename, ext = os.path.splitext(idb_path)
    til_path = "%s.til" % filename

    return None
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
        print("Malformed results database!")
        return False

      row = rows[0]
      version = row["version"]
      if version != diaphora.VERSION_VALUE:
        msg = "The version of the diff results is %s and current version is %s, there can be some incompatibilities."
        print(msg % (version, diaphora.VERSION_VALUE))

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
  if False:
    print("No IDA database opened or no function in the database.\nPlease open an IDA database and create some functions before running this script.")
    return

  opts = BinDiffOptions(**options)

  if opts.file_out == opts.file_in:
    print("Both databases are the same file!")
    return
  elif opts.file_out == "" or len(opts.file_out) < 5:
    print("No output database selected or invalid filename. Please select a database file.")
    return
  elif is_r2_file(opts.file_in) or is_r2_file(opts.file_out):
    print("TODO: this will run r2 with this script and no file opened, Support for projects must be done too.")
    return
  elif is_ida_file(opts.file_in) or is_ida_file(opts.file_out):
    print("Hahhahahh, no seriously, what are you trying to do?")
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

  bd = None
  try:
    bd = CIDABinDiff(opts.file_out)
    bd.use_decompiler_always = True #opts.use_decompiler
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
    global file_out
    total_functions = len(list(Functions()))
    sqlite_db = file_out  #os.path.splitext(GetIdbPath())[0] + ".sqlite"
    self.file_out = kwargs.get('file_out', sqlite_db)
    self.file_in  = kwargs.get('file_in', '')
    self.use_decompiler = kwargs.get('use_decompiler', True)
    self.exclude_library_thunk = kwargs.get('exclude_library_thunk', True)
    # Enable, by default, relaxed calculations on difference ratios for
    # 'big' databases (>20k functions)
    self.relax = kwargs.get('relax', total_functions > 20000)
    if self.relax:
      print(MSG_RELAXED_RATIO_ENABLED)
    self.unreliable = kwargs.get('unreliable', False)
    self.slow = kwargs.get('slow', False)
    self.experimental = kwargs.get('experimental', False)
    self.min_ea = 0 # kwargs.get('min_ea', MinEA())
    self.max_ea = -1 #kwargs.get('max_ea', MaxEA())
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
def is_r2_file(filename):
  fn = filename.lower()
  return fn.endswith(".r2")

def is_ida_file(filename):
  fn = filename.lower()
  return fn.endswith(".idb") or fn.endswith(".i64") or \
         fn.endswith(".til") or fn.endswith(".id0") or \
         fn.endswith(".id1") or fn.endswith(".nam")

#-----------------------------------------------------------------------
def remove_file(filename):
  print "Remove file %s"%(filename)

#-----------------------------------------------------------------------

file_out = ''

def main():
  global r2
  global file_out
  filename = os.getenv("R2_FILE")
  in_r2 = os.getenv("R2PIPE_IN") is not None

  if in_r2:
    print "Running from inside r2. Preserving the analysis information"
    r2 = r2pipe.open()
    # TODO: #!pipe doesnt setups the R2_ env
    filename = r2.cmd("o~[4]")
  else:
    if filename is None:
      if len(sys.argv) > 1:
        filename = sys.argv[1]
      else:
        print "Usage: diaphora-r2 [bin]"
        print "Usage: r2 -qAc '!diaphora-r2' /bin/ls"
        sys.exit(1)
    r2 = r2pipe.open(filename)
    #r2.cmd("aaa")
    r2.cmd("aab")
    #r2.cmd("aac")

  # perform analysis
  r2.cmd("e asm.flags=false")
  r2.cmd("e asm.bytes=false")
  r2.cmd("e scr.color=false")
  r2.cmd("e io.cache=true")
  r2.cmd("aeim")
  r2.cmd("e anal.hasnext=true")

  file_out = ntpath.basename(filename) + ".sqlite"
  # TODO parse arguments
  if bool(os.getenv("DIAPHORA_AUTO")):
    file_out = os.getenv("DIAPHORA_EXPORT_FILE")
    if file_out is None:
      raise Exception("No export file specified!")

  if os.path.exists(file_out):
    g_bindiff = None
    if raw_input("Remove %s? "%(file_out))[0].lower() == "y":
      os.unlink(file_out)
      _diff_or_export(True)
    else:
      print("Please remove %s and run again"%(file_out))
      r2.quit()
      sys.exit(1)
  else:
    _diff_or_export(True)
  print("File created %s"%(file_out))
  r2.quit()

if __name__ == "__main__":
  main()
