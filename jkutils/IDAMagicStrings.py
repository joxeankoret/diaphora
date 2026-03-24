#-------------------------------------------------------------------------------
#
# IDAPython plugin to show many features extracted from debugging strings. It's
# also able to rename functions based on the guessed function name & rename
# functions based on the source code file they belong to.
#
# Copyright (c) 2018-2019, 2026, Joxean Koret
# Licensed under the GNU GPL v3.
#
#-------------------------------------------------------------------------------

from __future__ import print_function

import os
import re
import sys

from collections import Counter

import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_gdl
import ida_graph
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name

try:
    from PySide6 import QtCore, QtGui, QtWidgets
    has_pyside6 = True
except ImportError:
    has_pyside6 = False

try:
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.tag import pos_tag

    has_nltk = True
except ImportError:
    has_nltk = False

#-------------------------------------------------------------------------------
PROGRAM_NAME = "IMS"

PLUGIN_NAME     = "IDA Magic Strings"
ACTION_NAME     = "IDAMagicStrings:run"
MENU_PATH       = "View/Open subviews/IDA Magic Strings"
WANTED_SHORTCUT = "Ctrl-Shift-D"

VERSION = "1.2"

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
CLASS_NAMES_REGEXP        = r"([a-z_][a-z0-9_]+(::(<[a-z0-9_]+>|~{0,1}[a-z0-9_]+))+)\({0,1}"
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
    strings = idautils.Strings()
    strings.setup(strtypes = strtypes)
    return strings

#-------------------------------------------------------------------------------
def get_lang(full_path):
    _, file_ext    = os.path.splitext(full_path.lower())
    file_ext = file_ext.strip(".")
    for key in LANGS:
        if file_ext in LANGS[key]:
            return key
    return None

#-------------------------------------------------------------------------------
def add_source_file_to(d, src_langs, refs, full_path, s):
    if full_path not in d:
        d[full_path] = []

    lang = get_lang(full_path)
    if lang is not None:
        src_langs[lang] += 1

    for ref in refs:
        d[full_path].append([ref, idc.get_func_name(ref), str(s)])

    return d, src_langs

#-------------------------------------------------------------------------------
def find_source_files_in_strings(strings, min_len, d, src_langs):
    total_files = 0
    for s in strings:
        if not s or s.length <= min_len:
            continue
        ret = re.findall(SOURCE_FILES_REGEXP, str(s), re.IGNORECASE)
        if not ret:
            continue
        refs = list(idautils.DataRefsTo(s.ea))
        if refs:
            total_files += 1
            d, src_langs = add_source_file_to(d, src_langs, refs, ret[0][0], s)
    return total_files

#-------------------------------------------------------------------------------
def find_source_files_in_debug_info(d, src_langs):
    total_files = 0
    for f in idautils.Functions():
        func = ida_funcs.get_func(f)
        if func is None:
            continue
        for block in ida_gdl.FlowChart(func):
            for head in idautils.Heads(block.start_ea, block.end_ea):
                full_path = ida_lines.get_sourcefile(head)
                if full_path is not None:
                    total_files += 1
                    d, src_langs = add_source_file_to(d, src_langs, [head], full_path, "Symbol: %s" % full_path)
    return total_files

#-------------------------------------------------------------------------------
def get_source_strings(min_len = 4, strtypes = [0, 1]):
    strings = get_strings(strtypes)

    src_langs = Counter()
    d = {}
    total_files = find_source_files_in_strings(strings, min_len, d, src_langs)
    total_files += find_source_files_in_debug_info(d, src_langs)

    nltk_preprocess(strings)
    if d and total_files > 0:
        print("Programming languages found:\n")
        for key in src_langs:
            print("    %s %f%%" % (key.ljust(10), src_langs[key] * 100. / total_files))
        print("\n")

    return d, strings

#-------------------------------------------------------------------------------
def handler(item, column_no):
    ea = item.ea
    if ida_bytes.is_mapped(ea):
        ida_kernwin.jumpto(ea)

#-------------------------------------------------------------------------------
class CBaseTreeViewer(ida_kernwin.PluginForm):
    def populate_tree(self, d):
        # Clear previous items
        self.tree.clear()

        # Build the tree
        for key in d:
            src_file_item = QtWidgets.QTreeWidgetItem(self.tree)
            src_file_item.setText(0, key)
            src_file_item.ea = ida_idaapi.BADADDR

            for ea, name, str_data in d[key]:
                item = QtWidgets.QTreeWidgetItem(src_file_item)
                item.setText(0, "%s [0x%08x] %s" % (name, ea, str_data))
                item.ea = ea

        self.tree.itemDoubleClicked.connect(handler)

    def OnCreate(self, form):
        # Get parent widget
        self.parent = ida_kernwin.PluginForm.FormToPyQtWidget(form)

        # Create tree control
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("Names",))
        self.tree.setColumnWidth(0, 100)

        if self.d is None:
            self.d, self.s = get_source_strings()
        d = self.d

        # Create layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.populate_tree(d)

        # Populate PluginForm
        self.parent.setLayout(layout)

    def Show(self, title, d = None):
        self.d = d
        return ida_kernwin.PluginForm.Show(self, title, options = ida_kernwin.PluginForm.WOPN_PERSIST)

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
        return ida_kernwin.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class CIDAMagicStringsChooser(ida_kernwin.Choose):
    def __init__(self, title, columns, options):
        ida_kernwin.Choose.__init__(self, title, columns, options)
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
        CIDAMagicStringsChooser.__init__(self, title, columns, ida_kernwin.Choose.CH_MULTI)
        self.n = 0
        self.icon = -1
        self.selcount = 0
        self.modal = False
        self.items = []
        self.selected_items = []

        d, s = get_source_strings()
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

        self.cmd_all = self.AddCommand("Rename all to filename_EA")
        self.cmd_all_sub = self.AddCommand("Rename all sub_* to filename_EA")
        self.cmd_selected = self.AddCommand("Rename selected to filename_EA")
        self.cmd_selected_sub = self.AddCommand("Rename selected sub_* to filename_EA")
        return self.d

    def OnCommand(self, n, cmd_id):
        # Aditional right-click-menu commands handles
        if cmd_id == self.cmd_all:
            l = list(range(len(self.items)))
        elif cmd_id == self.cmd_all_sub:
            l = []
            for i, item in enumerate(self.items):
                if item[4].startswith("sub_"):
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
            name = "%s_%08x" % (candidate, ea)
            func = ida_funcs.get_func(ea)
            if func is not None:
                ea = func.start_ea
                idc.set_name(ea, name, ida_name.SN_CHECK)
            else:
                line = "WARNING: Cannot rename 0x%08x to %s because there is no function associated."
                print(line % (ea, name))

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
        if ida_bytes.is_mapped(ea):
            ida_kernwin.jumpto(ea)

    def OnSelectionChange(self, sel_list):
        self.selected_items = sel_list

#-------------------------------------------------------------------------------
class CCandidateFunctionNames(CIDAMagicStringsChooser):
    def __init__(self, title, l):
        columns = [ ["Line", 4], ["EA", 16], ["Function Name", 25], ["Candidate", 25], ["FP?", 2], ["Strings", 50], ]
        CIDAMagicStringsChooser.__init__(self, title, columns, ida_kernwin.Choose.CH_MULTI)
        self.n = 0
        self.icon = -1
        self.selcount = 0
        self.modal = False
        self.items = []
        self.selected_items = []

        i = 0
        for item in l:
            bin_func    = item[1]
            candidate = item[2]
            seems_false = str(int(self.looks_false(bin_func, candidate)))
            line = ["%03d" % i, "0x%08x" % item[0], item[1], item[2], seems_false, ", ".join(item[3]) ]
            self.items.append(line)
            i += 1

        self.items = sorted(self.items, key=lambda x: x[4])

    def show(self):
        ret = self.Show(False)
        if ret < 0:
            return False

        self.cmd_rename_all = self.AddCommand("Rename all functions")
        self.cmd_rename_sub = self.AddCommand("Rename all sub_* functions")
        self.cmd_rename_selected = self.AddCommand("Rename selected function(s)")
        self.cmd_rename_sub_sel = self.AddCommand("Rename selected sub_* function(s)")

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
        for i in items:
            item = self.items[i]
            ea = int(item[1], 16)
            candidate = item[3]
            idc.set_name(ea, candidate, ida_name.SN_CHECK)

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
        if ida_bytes.is_mapped(ea):
            ida_kernwin.jumpto(ea)

    def OnSelectionChange(self, sel_list):
        self.selected_items = sel_list

    def looks_false(self, bin_func, candidate):
        bin_func    = bin_func.lower()
        candidate = candidate.lower()
        if not bin_func.startswith("sub_"):
            if bin_func.find(candidate) == -1 and candidate.find(bin_func) == -1:
                return True
        return False

    def OnGetLineAttr(self, n):
        item = self.items[n]
        bin_func    = item[2]
        candidate = item[3]
        if self.looks_false(bin_func, candidate):
            return [0x026AFD, 0]
        return [0xFFFFFF, 0]

#-------------------------------------------------------------------------------
class CClassXRefsChooser(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(self,
                                         title,
                                         [ ["Address", 8], ["String", 80] ])
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
        if ida_bytes.is_mapped(ea):
            ida_kernwin.jumpto(ea)

#-------------------------------------------------------------------------------
class CClassesTreeViewer(ida_kernwin.PluginForm):
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
                        except:
                            print("Error adding node?", self.nodes, parent_name, str(sys.exc_info()[1]))

                    node = QtWidgets.QTreeWidgetItem(parent)
                    node.setText(0, full_name)
                    node.ea = ea
                    self.nodes[full_name] = node

        self.tree.itemDoubleClicked.connect(classes_handler)

    def OnCreate(self, form):
        # Get parent widget
        self.parent = ida_kernwin.PluginForm.FormToPyQtWidget(form)

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
        return ida_kernwin.PluginForm.Show(self, title, options = ida_kernwin.PluginForm.WOPN_PERSIST)

#-------------------------------------------------------------------------------
class CClassesGraph(ida_graph.GraphViewer):
    def __init__(self, title, classes, final_list):
        ida_graph.GraphViewer.__init__(self, title)
        self.selected = None
        self.classes = classes
        self.final_list = final_list
        self.nodes = {}
        self.nodes_ea = {}
        self.graph = {}
        self.last_cmd = 0
        self.build_final_list()

    def build_final_list(self):
        dones = set()
        for ea, tokens in self.classes:
            refs_funcs = set()
            for ref in idautils.DataRefsTo(ea):
                func = ida_funcs.get_func(ref)
                if func is not None:
                    refs_funcs.add(func.start_ea)

            if len(refs_funcs) != 1:
                continue

            func_ea = list(refs_funcs)[0]
            if func_ea in dones:
                continue
            dones.add(func_ea)

            func_name = idc.get_func_name(func_ea)
            tmp = idc.demangle_name(func_name, ida_ida.inf_get_short_demnames())
            if tmp is not None:
                func_name = tmp

            self.final_list.append([func_ea, func_name, "::".join(tokens), [get_string(ea)]])

    def build_graph(self):
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

                self.nodes_ea.setdefault(node_id, set()).add(ea)

                parent_name = "::".join(tokens[:tokens.index(node_name)])
                if parent_name and parent_name in self.nodes:
                    parent_id = self.nodes[parent_name]
                    self.AddEdge(parent_id, node_id)
                    self.graph[parent_id].append(node_id)

    def OnRefresh(self):
        self.build_graph()
        return True

    def OnGetText(self, node_id):
        return str(self[node_id])

    def OnDblClick(self, node_id):
        eas = self.nodes_ea[node_id]
        if len(eas) == 1:
            ida_kernwin.jumpto(list(eas)[0])
        else:
            items = []
            for ea in eas:
                func = ida_funcs.get_func(ea)
                if func is None:
                    s = idc.get_strlit_contents(ea)
                    s = s.decode("utf-8")
                    if s is not None and s.find(str(self[node_id])) == -1:
                        s = idc.get_strlit_contents(ea, strtype=1)
                    else:
                        s = idc.generate_disasm_line(ea, 0)
                else:
                    s = idc.get_func_name(func.start_ea)

                items.append(["0x%08x" % ea, repr(s)])

            chooser = CClassXRefsChooser("XRefs to %s" % str(self[node_id]), items)
            idx = chooser.Show(1)
            if idx > -1:
                ida_kernwin.jumpto(list(eas)[idx])

    def export_to_dot(self):
        fname = ida_kernwin.ask_file(1, "*.dot", "Dot file name")
        if not fname:
            return

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

        buf += '\n}'
        with open(fname, "w") as f:
            f.write(buf)

    def export_to_gml(self):
        fname = ida_kernwin.ask_file(1, "*.gml", "GML file name")
        if not fname:
            return

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

        buf += '\n]'
        with open(fname, "w") as f:
            f.write(buf)

    def OnCommand(self, cmd_id):
        if self.cmd_dot == cmd_id:
            self.export_to_dot()
        elif self.cmd_gml == cmd_id:
            self.export_to_gml()

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
        if not ida_graph.GraphViewer.Show(self):
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
def collect_class_names_from_symbols():
    class_names = []
    for ea, name in idautils.Names():
        func = ida_funcs.get_func(ea)
        if func is None:
            continue

        true_name = name
        if name.find("::") == -1:
            demangled = idc.demangle_name(name, ida_ida.inf_get_short_demnames())
            if demangled and demangled.find("::") > -1:
                true_name = demangled

        if true_name.find("::") > -1:
            class_names.append(CFakeString(ea, true_name))

    return class_names

#-------------------------------------------------------------------------------
def find_class_objects(strings):
    class_objects = []
    for s in strings:
        for match in re.findall(CLASS_NAMES_REGEXP, str(s), re.IGNORECASE):
            candidate = match[0]
            if candidate.find("::") > 0:
                tokens = candidate.split("::")
                if tokens not in class_objects:
                    class_objects.append([s.ea, tokens])
    return class_objects

#-------------------------------------------------------------------------------
def is_valid_nltk_token(candidate):
    if not has_nltk:
        return True
    if candidate not in FOUND_TOKENS:
        return False
    return any(tkn_type in FOUND_TOKENS[candidate] for tkn_type in TOKEN_TYPES)

#-------------------------------------------------------------------------------
def collect_function_name_refs(strings):
    rarity = {}
    func_names = {}
    raw_func_strings = {}

    for s in strings:
        ret = re.findall(FUNCTION_NAMES_REGEXP, str(s), re.IGNORECASE)
        if not ret:
            continue

        candidate = ret[0][0]
        if not seems_function_name(candidate) or not is_valid_nltk_token(candidate):
            continue

        for ref in idautils.DataRefsTo(s.ea):
            func = ida_funcs.get_func(ref)
            if func is None:
                continue

            key = func.start_ea
            rarity.setdefault(candidate, set()).add(key)
            func_names.setdefault(key, set()).add(candidate)
            raw_func_strings.setdefault(key, set()).add(str(s))

    return func_names, raw_func_strings, rarity

#-------------------------------------------------------------------------------
def find_function_names(strings_list):
    all_strings = collect_class_names_from_symbols()
    all_strings.extend(strings_list)

    class_objects = find_class_objects(all_strings)
    func_names, raw_func_strings, rarity = collect_function_name_refs(all_strings)

    return func_names, raw_func_strings, rarity, class_objects

#-------------------------------------------------------------------------------
def show_function_names(strings_list):
    l = find_function_names(strings_list)
    func_names, raw_func_strings, rarity, classes = l

    final_list = []
    for key in func_names:
        candidates = set()
        for candidate in func_names[key]:
            if len(rarity[candidate]) == 1:
                candidates.add(candidate)

        if len(candidates) == 1:
            raw_strings = list(raw_func_strings[key])
            raw_strings = list(map(repr, raw_strings))

            func_name = idc.get_func_name(key)
            tmp = idc.demangle_name(func_name, ida_ida.inf_get_short_demnames())
            if tmp is not None:
                func_name = tmp
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
def main():
    ch = CSourceFilesChooser(PROGRAM_NAME + ": Source code files")
    if len(ch.items) > 0:
        ch.show()

    d = ch.d
    if len(d) > 0:
        show_tree(d)

    show_function_names(ch.s)

#-------------------------------------------------------------------------------
class CIDAMagicStringsMod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()

    def run(self, arg):
        main()
        return True

#-------------------------------------------------------------------------------
class CIDAMagicStringsAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin_mod):
        super().__init__()
        self.plugin_mod = plugin_mod

    def activate(self, ctx):
        self.plugin_mod.run(0)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class IDAMagicStringsPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Show features extracted from debugging strings"
    help = "Extract source files, function names, and class names from debugging strings"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = WANTED_SHORTCUT

    def init(self):
        plugin_mod = CIDAMagicStringsMod()

        action = ida_kernwin.action_desc_t(
            ACTION_NAME,
            PLUGIN_NAME,
            CIDAMagicStringsAction(plugin_mod),
            WANTED_SHORTCUT,
            "Extract features from debugging strings",
        )
        ida_kernwin.register_action(action)
        ida_kernwin.attach_action_to_menu(MENU_PATH, ACTION_NAME, ida_kernwin.SETMENU_APP)

        return plugin_mod

#-------------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return IDAMagicStringsPlugin()

#-------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
