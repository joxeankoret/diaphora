#!/usr/bin/python3

import sqlite3
import argparse

#-------------------------------------------------------------------------------
def sqlite3_connect(db_name):
  db = sqlite3.connect(db_name, check_same_thread=False)
  db.text_factory = str
  db.row_factory = sqlite3.Row
  return db

#-------------------------------------------------------------------------------
class CFPSChecker:
  def __init__(self, symbols, anonymous, results):
    print(symbols, anonymous)
    self.db = sqlite3_connect(symbols)
    cur = self.db.cursor()
    try:
      sql = 'attach "%s" as diff' % anonymous
      cur.execute(sql)

      db2 = sqlite3_connect(results)
      db2.execute("create table if not exists dummy(col)")
      db2.close()
      
      sql = 'attach "%s" as output' % results
      cur.execute(sql)

      sql = "drop table if exists output.results"
      cur.execute(sql)
    finally:
      cur.close()

  def get_total_matches(self):
    cur = self.db.cursor()
    total = 0
    try:
      sql = "select count(0) from main.results where type != 'multimatch'"
      cur.execute(sql)
      row = cur.fetchone()
      total = row[0]
    finally:
      cur.close()
    return total

  def check(self, output_database):
    sql = """
      select dr.description, count(0)
        from main.results r,
             diff.results dr
       where r.address = dr.address
         and r.address2 != dr.address2
         and dr.type != 'multimatch'
         and dr.name != dr.name2
       group by dr.description
       order by 2 desc"""
    cur = self.db.cursor()
    try:
      cur.execute(sql)
      rows = list(cur.fetchall())
      if len(rows) > 0:
        print("{:<65} {:>12}".format("Heuristic", "Total"))
        print("-"*78)
        total = 0
        for row in rows:
          print("{:<65} {:>12}".format(row[0], row[1]))
          total += row[1]
        print("")
        
        total_matches = self.get_total_matches()
        print("Total of %d (%f%%) false positive(s)" % (total, (total*100.)/total_matches))

      sql2 = """
      create table output.results
      as
      select r.address main_address, r.address2 main_address2, r.name main_name, r.name2 main_name2, r.bb1 main_bb1, r.bb2 main_bb2, r.ratio main_ratio, r.description main_description, r.type main_type,
             dr.address diff_address, dr.address2 diff_address2, dr.name diff_name, dr.name2 diff_name2, dr.bb1 diff_bb1, dr.bb2 diff_bb2, dr.ratio diff_ratio, dr.description diff_description, dr.type diff_type
       from main.results r,
          diff.results dr
      where r.address = dr.address
        and r.address2 != dr.address2
        and dr.name != dr.name2
        and dr.type != 'multimatch'
      """
      cur.execute(sql2)
    finally:
      cur.close()

#-------------------------------------------------------------------------------
def main():
  parser = argparse.ArgumentParser(description='Diaphora tool to test for false positives')
  parser.add_argument('symbols', help="Diaphora diffing database with function names")
  parser.add_argument('anonymous', help="Diaphora diffing database WITHOUT function names")
  parser.add_argument('results', help="SQLite database with false positives results")
  args = parser.parse_args()

  checker = CFPSChecker(args.symbols, args.anonymous, args.results)
  checker.check(args.results)

if __name__ == "__main__":
  main()

