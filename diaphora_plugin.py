"""
Diaphora's IDA plugin

Copyright (c) 2015-2026, Joxean Koret

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

import idaapi
import ida_kernwin
import ida_idaapi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diaphora_ida

#-------------------------------------------------------------------------------
PLUGIN_NAME = "Diaphora"
MENU_ID = "diaphora_menu"
MENU_PATH = "Diaphora/"

#-------------------------------------------------------------------------------
def local_diff():
  """
  Run the local-diff helper from extras/diaphora_local.
  """
  from extras.diaphora_local import main as run_local_diff
  run_local_diff()

#-------------------------------------------------------------------------------
MENU_ITEMS = [
  ("diaphora:export",      "Diff or export",           diaphora_ida.main,                    None),
  ("diaphora:show",        "Show results",             diaphora_ida.show_choosers,           "F3"),
  None,
  ("diaphora:load",        "Load results",             diaphora_ida.load_results,            None),
  ("diaphora:save",        "Save results",             diaphora_ida.save_results,            None),
  ("diaphora:load_import", "Load and import results",  diaphora_ida.load_and_import_results, None),
  None,
  ("diaphora:imp_defs",    "Import definitions",       diaphora_ida.import_definitions,      None),
  None,
  ("diaphora:local_diff",  "Local diff",               local_diff,                           None),
]

#-------------------------------------------------------------------------------
class CDiaphoraAction(ida_kernwin.action_handler_t):
  def __init__(self, fn):
    super().__init__()
    self.fn = fn

  def activate(self, ctx):
    self.fn()
    return 1

  def update(self, ctx):
    return ida_kernwin.AST_ENABLE_ALWAYS

#-------------------------------------------------------------------------------
class CDiaphoraPlugin(ida_idaapi.plugin_t):
  flags = ida_idaapi.PLUGIN_KEEP
  comment = "Diaphora by Joxean Koret"
  help = "Export, diff, and import results between binaries"
  wanted_name = PLUGIN_NAME
  wanted_hotkey = ""

  def init(self):
    diaphora_ida.IS_DIAPHORA_PLUGIN = True

    ida_kernwin.create_menu(MENU_ID, PLUGIN_NAME, "Options")
    for item in MENU_ITEMS:
      if item is None:
        # Legacy add_menu_item supported separators on IDA 7 & 8
        try:
          idaapi.add_menu_item(MENU_PATH, "-", "", 0, lambda: None, ())
        except AttributeError:
          pass
        continue

      name, label, fn, hotkey = item
      desc = ida_kernwin.action_desc_t(
        name, label, CDiaphoraAction(fn), hotkey or "", label
      )
      ida_kernwin.register_action(desc)
      ida_kernwin.attach_action_to_menu(
        MENU_PATH + label, name, ida_kernwin.SETMENU_APP
      )

    return ida_idaapi.PLUGIN_KEEP

  def term(self):
    for item in MENU_ITEMS:
      if item is None:
        continue
      name, label, *_ = item
      ida_kernwin.detach_action_from_menu(MENU_PATH + label, name)
      ida_kernwin.unregister_action(name)

  def run(self, arg):
    diaphora_ida.main()
    return True

#-------------------------------------------------------------------------------
def PLUGIN_ENTRY():
  return CDiaphoraPlugin()

