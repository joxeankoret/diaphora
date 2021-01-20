#!/usr/bin/python

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

import diaphora_ida
import imp
imp.reload(diaphora_ida)
from diaphora_ida import import_definitions

from idaapi import IDA_SDK_VERSION

if IDA_SDK_VERSION < 690:
  # In versions prior to IDA 6.9 PySide is used...
  from PySide import QtGui
else:
  # ...while in IDA 6.9, they switched to PyQt5
  from PyQt5 import QtGui

#-----------------------------------------------------------------------
def main():
  import_definitions()

if __name__ == "__main__":
  main()
