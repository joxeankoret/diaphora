#!/usr/bin/python3

"""
Diaphora testing suite
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

import time
import sqlite3

from diaphora_heuristics import HEURISTICS

#-------------------------------------------------------------------------------
def log(msg):
  print("[%s] %s" % (time.asctime(), msg))

#-------------------------------------------------------------------------------
class CIndicesChecker:
  def __init__(self):
    self.db = None
    self.indices = []

  def __del__(self):
    if self.db is not None:
      self.db.close()

  def sqlite3_connect(self, db_name):
    self.db = sqlite3.connect(db_name, check_same_thread=False)
    self.db.text_factory = str
    self.db.row_factory = sqlite3.Row

  def connect(self, db1, db2):
    self.sqlite3_connect(db1)
    cur = self.db.cursor()
    try:
      cur.execute('attach "%s" as diff' % db2)
    finally:
      cur.close()

  def check_one(self, name, sql):
    log("Checking index for heuristic '%s'" % name)
    sql = sql.replace("%POSTFIX%", "")
    sql = "EXPLAIN QUERY PLAN\n%s" % sql
    cur = self.db.cursor()
    try:
      cur.execute(sql)
      for row in cur.fetchall():
        print(dict(row))
    finally:
      cur.close()

  def check(self, db1, db2):
    self.connect(db1, db2)
    for heur in HEURISTICS:
      name = heur["name"]
      sql = heur["sql"]
      self.check_one(name, sql)

#-------------------------------------------------------------------------------
def main(db1, db2):
  checker = CIndicesChecker()
  checker.check(db1, db2)

if __name__ == "__main__":
  main("../samples/ls.sqlite", "../samples/ls-old.sqlite")

