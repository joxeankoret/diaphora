#-------------------------------------------------------------------------------
#
# IDAPython script to show many features extracted from debugging strings. It's
# also able to rename functions based on the guessed function name & rename
# functions based on the source code file they belong to.
#
# Copyright (c) 2018-2024, Joxean Koret
# Licensed under the GNU Affero General Public License v3.
#
#-------------------------------------------------------------------------------

import os
import sys

import re

from collections import Counter

import idaapi

from idc import *
from idaapi import *
from idautils import *

try:
  from PyQt5 import QtWidgets
except ImportError as e:
  print(f'{os.path.basename(__file__)} importerror {e}')

sys.path.append("..")
import diaphora_config as config

try:
  import nltk
  from nltk.tokenize import word_tokenize
  from nltk.tag import pos_tag
  has_nltk = True
except ImportError as e:
  if config.SHOW_IMPORT_WARNINGS:
    print("WARNING: NLTK is not installed. It's recommended to install python-nltk. It's optional, but significantly improves the results.")
    print("INFO: Alternatively, you can silence this warning by changing the value of SHOW_IMPORT_WARNINGS in diaphora_config.py.")
  has_nltk = False

#-------------------------------------------------------------------------------
PROGRAM_NAME = "IMS"

#-------------------------------------------------------------------------------
SOURCE_FILES_REGEXP = r"([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| )"

LANGS = {}
LANGS["C/C++"] = ["c", "cc", "cxx", "cpp", "h", "hpp"]
LANGS["C"] = ["c"]
LANGS["C++"] = ["cc", "cxx", "cpp", "hpp", "c++"]
LANGS["Obj-C"] = ["m"]
LANGS["Rust"] = ["rs"]
LANGS["Golang"] = ["go"]
LANGS["OCaml"] = ["ml"]

#-------------------------------------------------------------------------------
FUNCTION_NAMES_REGEXP = r"([a-z_][a-z0-9_]+((::)+[a-z_][a-z0-9_]+)*)"
CLASS_NAMES_REGEXP    = r"([a-z_][a-z0-9_]+(::(<[a-z0-9_]+>|~{0,1}[a-z0-9_]+))+)\({0,1}"
NOT_FUNCTION_NAMES = ["copyright", "char", "bool", "int", "unsigned", "long",
  "double", "float", "signed", "license", "version", "cannot", "error",
  "invalid", "null", "warning", "general", "argument", "written", "report",
  "failed", "assert", "object", "integer", "unknown", "localhost", "native",
  "memory", "system", "write", "read", "open", "close", "help", "exit", "test",
  "return", "libs", "home", "ambiguous", "internal", "request", "inserting",
  "deleting", "removing", "updating", "adding", "assertion", "flags",
  "overflow", "enabled", "disabled", "enable", "disable", "virtual", "client",
  "server", "switch", "while", "offset", "abort", "panic", "static", "updated",
  "pointer", "reason", "month", "year", "week", "hour", "minute", "second",
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
  'september', 'october', 'november', 'december', "arguments", "corrupt",
  "corrupted", "default", "success", "expecting", "missing", "phrase",
  "unrecognized", "undefined",
  ]

#-------------------------------------------------------------------------------
FOUND_TOKENS = {}
TOKEN_TYPES = ["NN", "NNS", "NNP", "JJ", "VB", "VBD", "VBG", "VBN", "VBP", "VBZ"]
def nltk_preprocess(strings):
  if not has_nltk:
    return

  strings = "\n".join(map(str, list(strings)))
  tokens = re.findall(FUNCTION_NAMES_REGEXP, strings)
  l = []
  for token in tokens:
    l.append(token[0])
  word_tags = nltk.pos_tag(l)
  for word, tag in word_tags:
    try:
      FOUND_TOKENS[word.lower()].add(tag)
    except:
      FOUND_TOKENS[word.lower()] = set([tag])

#-------------------------------------------------------------------------------
def get_strings(strtypes = [0, 1]):
  strings = Strings()
  strings.setup(strtypes = strtypes)
  return strings

#-------------------------------------------------------------------------------
def get_lang(full_path):
  """
  Try to guess the programming language from the file extension.
  """
  _, file_ext  = os.path.splitext(full_path.lower())
  file_ext = file_ext.strip(".")
  for key in LANGS:
    if file_ext in LANGS[key]:
      return key
  return None

#-------------------------------------------------------------------------------
def add_source_file_to(d, src_langs, refs, full_path, s):
  """
  Add single source file to the given dictionary and try to guess which language
  was that source file written in.
  """
  if full_path not in d:
    d[full_path] = []

  lang = get_lang(full_path)
  if lang is not None:
    src_langs[lang] += 1

  for ref in refs:
    d[full_path].append([ref, get_func_name(ref), str(s)])

  return d, src_langs

#-------------------------------------------------------------------------------
def get_source_strings(min_len, strtypes):
  """
  Find source code files from strings in the binary
  """
  strings = get_strings(strtypes)

  # Search string references to source files
  src_langs = Counter()
  total_files = 0
  d = {}
  for s in strings:
    if s and s.length > min_len:
      ret = re.findall(SOURCE_FILES_REGEXP, str(s), re.IGNORECASE)
      if ret and len(ret) > 0:
        refs = list(DataRefsTo(s.ea))
        if len(refs) > 0:
          total_files += 1
          full_path    = ret[0][0]
          d, src_langs = add_source_file_to(d, src_langs, refs, full_path, s)

  # Use the loaded debugging information (if any) to find source files
  for f in list(Functions()):
    done = False
    func = idaapi.get_func(f)
    if func is not None:
      cfg = idaapi.FlowChart(func)
      for block in cfg:
        if done:
          break

        head = block.start_ea
        full_path = get_sourcefile(head)
        if full_path is not None:
          total_files += 1
          d, src_langs = add_source_file_to(d, src_langs, [head], full_path, f"Symbol: {full_path}")

  nltk_preprocess(strings)
  if len(d) > 0 and total_files > 0:
    print("Programming languages found:\n")
    for key in src_langs:
      percent = src_langs[key] * 100. / total_files
      print(f"  {key.ljust(10)} {percent}%")
    print()

  return d, strings

#-------------------------------------------------------------------------------
def handler(item, column_no):
  ea = item.ea
  if is_mapped(ea):
    jumpto(ea)

#-------------------------------------------------------------------------------
class CBaseTreeViewer(PluginForm):
  def populate_tree(self, d):
    # Clear previous items
    self.tree.clear()

    # Build the tree
    for key in d:
      src_file_item = QtWidgets.QTreeWidgetItem(self.tree)
      src_file_item.setText(0, key)
      src_file_item.ea = BADADDR

      for ea, name, str_data in d[key]:
        item = QtWidgets.QTreeWidgetItem(src_file_item)
        item.setText(0, "%s [0x%08x] %s" % (name, ea, str_data))
        item.ea = ea

    self.tree.itemDoubleClicked.connect(handler)

  def OnCreate(self, form):
    # Get parent widget
    self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

    # Create tree control
    try:
      self.tree = QtWidgets.QTreeWidget()
    except NameError as e:
      print(f'[idamagic] nameerror {e}')
      return
    self.tree.setHeaderLabels(("Names",))
    self.tree.setColumnWidth(0, 100)

    if self.d is None:
      self.d, self.s = get_source_strings(4, [0, 1])
    d = self.d

    # Create layout
    layout = QtWidgets.QVBoxLayout()
    layout.addWidget(self.tree)
    self.populate_tree(d)

    # Populate PluginForm
    self.parent.setLayout(layout)

  def Show(self, title, d = None):
    self.d = d
    return PluginForm.Show(self, title, options = PluginForm.WOPN_PERSIST)

#-------------------------------------------------------------------------------
def basename(path):
  pos1 = path[::-1].find("\\")
  pos2 = path[::-1].find("/")

  if pos1 == -1: pos1 = len(path)
  if pos2 == -1: pos2 = len(path)
  pos = min(pos1, pos2)

  return path[len(path)-pos:]

#-------------------------------------------------------------------------------
class command_handler_t(ida_kernwin.action_handler_t):
  def __init__(self, obj, cmd_id, num_args = 1):
    self.obj = obj
    self.cmd_id = cmd_id
    self.num_args = num_args
    ida_kernwin.action_handler_t.__init__(self)

  def activate(self, ctx):
    if self.num_args == 1:
      return self.obj.OnCommand(self.cmd_id)
    return self.obj.OnCommand(self.obj, self.cmd_id)

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class CIDAMagicStringsChooser(Choose):
  def __init__(self, title, columns, options):
    Choose.__init__(self, title, columns, options)
    self.actions = []

  def AddCommand(self, menu_name, shortcut=None):
    action_name = "IDAMagicStrings:%s" % menu_name.replace(" ", "")
    self.actions.append([len(self.actions), action_name, menu_name, shortcut])
    return len(self.actions)-1

  def OnPopup(self, form, popup_handle):
    for num, action_name, menu_name, shortcut in self.actions:
      handler = command_handler_t(self, num, 2)
      desc = ida_kernwin.action_desc_t(action_name, menu_name, handler, shortcut)
      ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)

#-------------------------------------------------------------------------------
class CSourceFilesChooser(CIDAMagicStringsChooser):
  def __init__(self, title):
    columns = [ ["Line", 4], ["Full path", 20], ["Filename", 15], ["EA", 16], ["Function Name", 18], ["String data", 40], ]
    CIDAMagicStringsChooser.__init__(self, title, columns, Choose.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []
    self.selected_items = []

    d, s = get_source_strings(4, [0,1])
    keys = list(d.keys())
    keys.sort()

    i = 0
    for key in keys:
      for ea, name, str_data in d[key]:
        line = ["%03d" % i, key, basename(key), "0x%08x" % ea, name, str_data]
        self.items.append(line)
        i += 1

    self.d = d
    self.s = s

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    self.cmd_all          = self.AddCommand("Rename all to filename_EA")
    self.cmd_all_sub      = self.AddCommand("Rename all sub_* to filename_EA")
    self.cmd_selected     = self.AddCommand("Rename selected to filename_EA")
    self.cmd_selected_sub = self.AddCommand("Rename selected sub_* to filename_EA")
    return self.d

  def OnCommand(self, n, cmd_id):
    # Aditional right-click-menu commands handles
    if cmd_id == self.cmd_all:
      l = list(range(len(self.items)))
    elif cmd_id == self.cmd_all_sub:
      l = []
      for i, item in enumerate(self.items):
        if item[4] is not None and item[4].startswith("sub_"):
          l.append(i)
    elif cmd_id == self.cmd_selected:
      l = list(self.selected_items)
    elif cmd_id == self.cmd_selected_sub:
      l = []
      for i, item in enumerate(self.items):
        if item[4].startswith("sub_"):
          if i in self.selected_items:
            l.append(i)

    self.rename_items(l)

  def rename_items(self, items):
    for i in items:
      item = self.items[i]
      ea = int(item[3], 16)
      candidate, _ = os.path.splitext(item[2])
      candidate = candidate
      name = "%s_%08x" % (candidate, ea)
      func = idaapi.get_func(ea)
      if func is not None:
        ea = func.start_ea
        set_name(ea, name, SN_CHECK)
      else:
        print(f'[idamagic] {self.title} cannot rename {ea} {name} snc:{SN_CHECK}' )

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    n = len(self.items)
    return n

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnRefresh(self, n):
    return n

  def OnSelectLine(self, n):
    self.selcount += 1
    row = self.items[n[0]]
    ea = int(row[3], 16)
    if is_mapped(ea):
      jumpto(ea)

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list

#-------------------------------------------------------------------------------
class CCandidateFunctionNames(CIDAMagicStringsChooser):
  def __init__(self, title, final_list):
    columns = [ ["Line", 4], ["EA", 16], ["Function Name", 25], ["Candidate", 25], ["FP?", 2], ["Strings", 50], ]
    CIDAMagicStringsChooser.__init__(self, title, columns, Choose.CH_MULTI)
    self.n = 0
    self.icon = -1
    self.selcount = 0
    self.modal = False
    self.items = []
    self.selected_items = []

    idx = 0
    for item in final_list:
      bin_func  = item[1]
      candidate = item[2]
      seems_false = str(int(self.looks_false(bin_func, candidate)))
      line = ["%03d" % idx, "0x%08x" % item[0], item[1], item[2], seems_false, ", ".join(item[3]) ]
      self.items.append(line)
      idx += 1

    self.items = sorted(self.items, key=lambda x: x[4])

  def show(self):
    ret = self.Show(False)
    if ret < 0:
      return False

    self.cmd_rename_all      = self.AddCommand("Rename all functions")
    self.cmd_rename_sub      = self.AddCommand("Rename all sub_* functions")
    self.cmd_rename_selected = self.AddCommand("Rename selected function(s)")
    self.cmd_rename_sub_sel  = self.AddCommand("Rename selected sub_* function(s)")

  def OnCommand(self, n, cmd_id):
    # Aditional right-click-menu commands handles
    if cmd_id == self.cmd_rename_all:
      l = list(range(len(self.items)))
    elif cmd_id == self.cmd_rename_selected:
      l = list(self.selected_items)
    elif cmd_id == self.cmd_rename_sub:
      l = []
      for i, item in enumerate(self.items):
        if item[2].startswith("sub_"):
          l.append(i)
    elif cmd_id == self.cmd_rename_sub_sel:
      l = []
      for i, item in enumerate(self.items):
        if item[2].startswith("sub_"):
          if i in self.selected_items:
            l.append(i)
    else:
      raise Exception("Unknown menu command!")

    self.rename_items(l)

  def rename_items(self, items):
    idx = 0
    for i in items:
      idx +=1
      item = self.items[i]
      ea = int(item[1], 16)
      candidate = item[3].replace(':','')
      candidate = candidate.replace(' ','_')
      set_name(ea, candidate, SN_CHECK)
      print(f'[idamagic] {self.title} i:{idx}/{len(items)} rename {item[2]} addr: {item[1]} to {candidate} snc:{SN_CHECK}')

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    n = len(self.items)
    return n

  def OnDeleteLine(self, n):
    del self.items[n]
    return n

  def OnRefresh(self, n):
    return n

  def OnSelectLine(self, n):
    self.selcount += 1
    row = self.items[n[0]]
    ea = int(row[1], 16)
    if is_mapped(ea):
      jumpto(ea)

  def OnSelectionChange(self, sel_list):
    self.selected_items = sel_list

  def looks_false(self, bin_func, candidate):
    bin_func  = bin_func.lower()
    candidate = candidate.lower()
    if not bin_func.startswith("sub_"):
      if bin_func.find(candidate) == -1 and candidate.find(bin_func) == -1:
        return True
    return False

  def OnGetLineAttr(self, n):
    item = self.items[n]
    bin_func  = item[2]
    candidate = item[3]
    if self.looks_false(bin_func, candidate):
      return [0x026AFD, 0]
    return [0xFFFFFF, 0]

#-------------------------------------------------------------------------------
class CClassXRefsChooser(idaapi.Choose):
  def __init__(self, title, items):
    idaapi.Choose.__init__(self, title, [ ["Address", 8], ["String", 80] ])
    self.items = items

  def OnGetLine(self, n):
    return self.items[n]

  def OnGetSize(self):
    return len(self.items)

#-------------------------------------------------------------------------------
def get_string(ea):
  tmp = idc.get_strlit_contents(ea, strtype=0)
  if tmp is None or len(tmp) == 1:
    unicode_tmp = idc.get_strlit_contents(ea, strtype=1)
    if unicode_tmp is not None and len(unicode_tmp) > len(tmp):
      tmp = unicode_tmp

  if tmp is None:
    tmp = ""
  elif type(tmp) != str:
    tmp = tmp.decode("utf-8")
  return tmp

#-------------------------------------------------------------------------------
def classes_handler(item, column_no):
  if item.childCount() == 0:
    ea = item.ea
    if is_mapped(ea):
      jumpto(ea)

#-------------------------------------------------------------------------------
class CClassesTreeViewer(PluginForm):
  def populate_tree(self):
    # Clear previous items
    self.tree.clear()
    self.nodes = {}

    self.classes = sorted(self.classes, key=lambda x: x[1][0])
    for ea, tokens in self.classes:
      for i, node_name in enumerate(tokens):
        full_name = "::".join(tokens[:tokens.index(node_name)+1])
        if full_name not in self.nodes:
          if full_name.find("::") == -1:
            parent = self.tree
          else:
            parent_name = "::".join(tokens[:tokens.index(node_name)])
            try:
              parent = self.nodes[parent_name]
            except Exception as e:
              print(f"[idamagic] Error {e.with_traceback} ea:{ea} parent_name: {parent_name} sys:{str(sys.exc_info()[1])} ")  #, self.nodes, parent_name, str(sys.exc_info()[1]))
            except KeyError as e:
              print(f"[idamagic] KeyError {e.with_traceback} ea:{ea} parent_name: {parent_name} sys:{str(sys.exc_info()[1])} ")  #, self.nodes, parent_name, str(sys.exc_info()[1]))

          node = QtWidgets.QTreeWidgetItem(parent)
          node.setText(0, full_name)
          node.ea = ea
          self.nodes[full_name] = node

    self.tree.itemDoubleClicked.connect(classes_handler)

  def OnCreate(self, form):
    # Get parent widget
    self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

    # Create tree control
    self.tree = QtWidgets.QTreeWidget()
    self.tree.setHeaderLabels(("Classes",))
    self.tree.setColumnWidth(0, 100)

    # Create layout
    layout = QtWidgets.QVBoxLayout()
    layout.addWidget(self.tree)
    self.populate_tree()

    # Populate PluginForm
    self.parent.setLayout(layout)

  def Show(self, title, classes):
    self.classes = classes
    return PluginForm.Show(self, title, options = PluginForm.WOPN_PERSIST)

#-------------------------------------------------------------------------------
class CClassesGraph(idaapi.GraphViewer):
  def __init__(self, title, classes, final_list):
    idaapi.GraphViewer.__init__(self, title)
    self.selected = None
    self.classes = classes
    self.final_list = final_list
    self.nodes = {}
    self.nodes_ea = {}
    self.graph = {}

    self.last_cmd = 0

    dones = set()
    for ea, tokens in self.classes:
      refs = DataRefsTo(ea)
      refs_funcs = set()
      for ref in refs:
        func = idaapi.get_func(ref)
        if func is not None:
          refs_funcs.add(func.start_ea)

      if len(refs_funcs) == 1:
        func_ea = list(refs_funcs)[0]
        if func_ea in dones:
          continue
        dones.add(func_ea)

        func_name = get_func_name(func_ea)
        tmp = demangle_name(func_name, INF_SHORT_DN)
        if tmp is not None:
          func_name = tmp

        element = [func_ea, func_name, "::".join(tokens), [get_string(ea)]]
        self.final_list.append(element)

  def OnRefresh(self):
    self.Clear()
    self.graph = {}
    for ea, tokens in self.classes:
      for node_name in tokens:
        full_name = "::".join(tokens[:tokens.index(node_name)+1])
        if full_name not in self.nodes:
          node_id = self.AddNode(node_name)
          self.nodes[full_name] = node_id
          self.graph[node_id] = []
        else:
          node_id = self.nodes[full_name]

        try:
          self.nodes_ea[node_id].add(ea)
        except KeyError:
          self.nodes_ea[node_id] = set([ea])

        parent_name = "::".join(tokens[:tokens.index(node_name)])
        if parent_name != "" and parent_name in self.nodes:
          parent_id = self.nodes[parent_name]
          try:
            self.AddEdge(parent_id, node_id)
          except AssertionError as e:
            print(f'[idamagic] onrefresh AssertionError {e} parent:{parent_name} pid:{parent_id} nid:{node_id}')
          except Exception as e:
            print(f'[idamagic] onrefresh ERR {e} parent:{parent_name} pid:{parent_id} nid:{node_id}')
          self.graph[parent_id].append(node_id)

    return True

  def OnGetText(self, node_id):
    ogt = ''
    try:
      ogt = str(self[node_id])
    except KeyError as e:
      print(f'[idamagic] {self} ogt keyerror {e} nodeid={node_id}')
    return ogt

  def OnDblClick(self, node_id):
    eas = self.nodes_ea[node_id]
    if len(eas) == 1:
      jumpto(list(eas)[0])
    else:
      items = []
      for ea in eas:
        func = idaapi.get_func(ea)
        if func is None:
          s = idc.get_strlit_contents(ea)
          s = s.decode("utf-8")
          if s is not None and s.find(str(self[node_id])) == -1:
            s = idc.get_strlit_contents(ea, strtype=1)
          else:
            s = GetDisasm(ea)
        else:
          s = get_func_name(func.start_ea)

        items.append(["0x%08x" % ea, repr(s)])

      chooser = CClassXRefsChooser("XRefs to %s" % str(self[node_id]), items)
      idx = chooser.Show(1)
      if idx > -1:
        jumpto(list(eas)[idx])

  def OnCommand(self, cmd_id):
    if self.cmd_dot == cmd_id:
      fname = ask_file(1, "*.dot", "Dot file name")
      if fname:
        f = open(fname, "w")
        buf = 'digraph G {\n graph [overlap=scale]; node [fontname=Courier]; \n\n'
        for n in self.graph:
          name = str(self[n])
          buf += ' a%s [shape=box, label = "%s", color="blue"]\n' % (n, name)
        buf += '\n'

        dones = set()
        for node_id in self.graph:
          for child_id in self.graph[node_id]:
            s = str([node_id, child_id])
            if s in dones:
              continue
            dones.add(s)
            buf += " a%s -> a%s [style = bold]\n" % (node_id, child_id)

        buf += '\n'
        buf += '}'
        f.write(buf)
        f.close()
    elif self.cmd_gml == cmd_id:
      fname = ask_file(1, "*.gml", "GML file name")
      if fname:
        f = open(fname, "w")
        buf = 'graph [ \n'
        for n in self.graph:
          name = str(self[n])
          buf += 'node [ id %s \n label "%s"\n fill "blue" \n type "oval"\n LabelGraphics [ type "text" ] ] \n' % (n, name)
        buf += '\n'

        dones = set()
        for node_id in self.graph:
          for child_id in self.graph[node_id]:
            s = str([node_id, child_id])
            if s in dones:
              continue
            dones.add(s)
            buf += " edge [ source %s \n target %s ]\n" % (node_id, child_id)

        buf += '\n'
        buf += ']'
        f.write(buf)
        f.close()

  def OnPopup(self, form, popup_handle):
    self.cmd_dot = 0
    cmd_handler = command_handler_t(self, self.cmd_dot)
    desc = ida_kernwin.action_desc_t("IDAMagicStrings:GraphvizExport", "Export to Graphviz",
                                     cmd_handler, "F2")
    ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)

    self.cmd_gml = 1
    cmd_handler = command_handler_t(self, self.cmd_gml)
    desc = ida_kernwin.action_desc_t("IDAMagicStrings:GmlExport","Export to GML",
                                     cmd_handler, "F3")
    ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)

  def OnClick(self, item):
    self.selected = item
    return True

  def Show(self):
    if not idaapi.GraphViewer.Show(self):
      return False
    return True

#-------------------------------------------------------------------------------
def show_tree(d = None):
  tree_frm = CBaseTreeViewer()
  tree_frm.Show(PROGRAM_NAME + ": Source code tree", d)

#-------------------------------------------------------------------------------
def seems_function_name(candidate):
  if len(candidate) >= 6 and candidate.lower() not in NOT_FUNCTION_NAMES:
    if candidate.upper() != candidate:
      return True
  return False

#-------------------------------------------------------------------------------
class CFakeString:
  def __init__(self, ea, s):
    self.ea = ea
    self.s = s

  def __str__(self):
    return str(self.s)

  def __repr__(self):
    return self.__str__()

#-------------------------------------------------------------------------------
def find_function_names(strings_list):
  rarity = {}
  func_names = {}
  raw_func_strings = {}
  class_objects = []

  class_tmp_names = []
  for ea, name in Names():
    func = idaapi.get_func(ea)
    if func is None:
      continue

    true_name = name
    if name.find("::") == -1:
      name = demangle_name(name, INF_SHORT_DN)
      if name is not None and name != "" and name.find("::") > -1:
        true_name = name

    if true_name.find("::") > -1:
      s = CFakeString(ea, true_name)
      class_tmp_names.append(s)

  class_tmp_names.extend(strings_list)
  for s in class_tmp_names:
    # Find class members
    class_ret = re.findall(CLASS_NAMES_REGEXP, str(s), re.IGNORECASE)
    if len(class_ret) > 0:
      for element in class_ret:
        candidate = element[0]
        if candidate.find("::") > 0:
          tokens = candidate.split("::")
          if tokens not in class_objects:
            class_objects.append([s.ea, tokens])

    # Find just function names
    ret = re.findall(FUNCTION_NAMES_REGEXP, str(s), re.IGNORECASE)
    if len(ret) > 0:
      candidate = ret[0][0]
      if seems_function_name(candidate):
        ea = s.ea
        refs = DataRefsTo(ea)
        found = False
        for ref in refs:
          func = idaapi.get_func(ref)
          if func is not None:
            found = True
            key = func.start_ea

            if has_nltk:
              if candidate not in FOUND_TOKENS:
                continue

              found = False
              for tkn_type in TOKEN_TYPES:
                if tkn_type in FOUND_TOKENS[candidate]:
                  found = True
                  break

              if not found:
                continue

            try:
              rarity[candidate].add(key)
            except KeyError:
              rarity[candidate] = set([key])

            try:
              func_names[key].add(candidate)
            except KeyError:
              func_names[key] = set([candidate])

            try:
              raw_func_strings[key].add(str(s))
            except:
              raw_func_strings[key] = set([str(s)])

  return func_names, raw_func_strings, rarity, class_objects

#-------------------------------------------------------------------------------
def show_function_names(strings_list):
  found_func_names = find_function_names(strings_list)
  func_names, raw_func_strings, rarity, classes = found_func_names
  final_list = []
  for key in func_names:
    candidates = set()
    for candidate in func_names[key]:
      if len(rarity[candidate]) == 1:
        candidates.add(candidate)

    if len(candidates) == 1:
      raw_strings = list(raw_func_strings[key])
      raw_strings = list(map(repr, raw_strings))

      func_name = get_func_name(key)

      tmp_func_name = demangle_name(func_name, INF_SHORT_DN)
      if tmp_func_name is not None:
        func_name = tmp_func_name

      candidate = candidate.replace('::', '_')
      final_list.append([key, func_name, list(candidates)[0], raw_strings])

  if len(classes) > 0:
    class_graph = CClassesGraph(PROGRAM_NAME + ": Classes Hierarchy", classes, final_list)
    class_graph.Show()

    class_tree = CClassesTreeViewer()
    class_tree.Show(PROGRAM_NAME + ": Classes Tree", classes)

    final_list = class_graph.final_list

  if len(final_list) > 0:
    cfn = CCandidateFunctionNames(PROGRAM_NAME + ": Candidate Function Names", final_list)
    cfn.show()

#-------------------------------------------------------------------------------

class magicstrings(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDA Magic Strings plugin"

    help = "This is magicstrings help"
    wanted_name = "Magic Strings"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return magicstrings()

def main():
  ch = CSourceFilesChooser(PROGRAM_NAME + ": Source code files")
  if len(ch.items) > 0:
    ch.show()

  d = ch.d
  if len(d) > 0:
    show_tree(d)

  show_function_names(ch.s)

if __name__ == "__main__":
  main()
