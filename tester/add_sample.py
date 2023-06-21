#!/usr/bin/python3

"""

Script used to create a skeleton .cfg file needed by the testing suite

Diaphora testing suite
Copyright (c) 2015-2022, Joxean Koret

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

#-------------------------------------------------------------------------------
EXCLUDED_EXTENSIONS = [".idb", ".i64", ".sqlite", ".til", ".nam", ".id0",
  ".id1", ".id2", ".cfg", ".log", ".db", ".py", ".sqlite-crash",
  ".sqlite-journal", ".cpp", ".asm"]

BASE_CFG = """
[Testcase]
filename=%s
export=%s.sqlite
ida-binary=idat64
decompiler=1
slow=0
script=

[Export]
total basic blocks=0
total bblocks instructions=0
total bblocks relations=0
total call graph items=0
total constants=0
total functions bblocks=0
total functions=0
total instructions=0
total program items=0
total program data items=0
call graph primes=0
compilation units=0
named compilation units=0
total microcode basic blocks=0
total microcode instructions=0
"""

#-------------------------------------------------------------------------------
def add_sample(filename):
  with open("%s.cfg" % filename, "w") as f:
    basename = os.path.basename(filename)
    f.write(BASE_CFG % (basename, basename))
  print("Created %s.cfg" % filename)

#-------------------------------------------------------------------------------
def is_excluded(filename):
  for extension in EXCLUDED_EXTENSIONS:
    if filename.endswith(extension):
      return True
  return False

#-------------------------------------------------------------------------------
def main():
  for f in os.listdir("."):
    if os.path.isfile(f) and not is_excluded(f):
      if not os.path.exists("%s.cfg" % f):
        print("New sample found: %s" % f)
        add_sample(f)

if __name__ == "__main__":
  main()
