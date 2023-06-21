#!/usr/bin/python3

import sys
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

