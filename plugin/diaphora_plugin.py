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

import os
import sys
import configparser

import idaapi
from idaapi import warning

#-------------------------------------------------------------------------------
def resolve_diaphora():
  config_dir = os.path.dirname(__file__)
  config_file = os.path.join(config_dir, "diaphora_plugin.cfg")
  if not os.path.exists(config_file):
    warning(f"The configuration file {config_file} does not exist.")
    return None
  
  config = configparser.ConfigParser()
  config.read(config_file)

  path = config["Diaphora"]["path"]
  sys.path.append(path)

  from diaphora_ida import main
  return main

#-------------------------------------------------------------------------------
class DiaphoraPlugin(idaapi.plugin_t):
  wanted_name = "Diaphora"
  version = "3.2.0"
  wanted_hotkey = ""
  comment = "Diaphora by joxeankoret"
  website = "https://github.com/joxeankoret/diaphora"
  help = "Export the current binary or diff against another binary"
  flags = 0

  def init(self):
    self.diaphora_main = None
    return idaapi.PLUGIN_KEEP

  def term(self):
    pass

  def run(self, arg):
    if self.diaphora_main is None:
      self.diaphora_main = resolve_diaphora()

    if self.diaphora_main is not None:
      self.diaphora_main()

    return True

#-------------------------------------------------------------------------------
def PLUGIN_ENTRY():
  return DiaphoraPlugin()

