#!/usr/bin/python

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015, Joxean Koret

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

import diaphora
reload(diaphora)
from diaphora import load_results

from idaapi import IDA_SDK_VERSION

if IDA_SDK_VERSION < 690:
  # In versions prior to IDA 6.9 PySide is used...
  from PySide import QtGui
else:
  # ...while in IDA 6.9, they switched to PyQt5
  from PyQt5 import QtGui

#-----------------------------------------------------------------------
def main():
  load_results()

if __name__ == "__main__":
  main()
