#!/usr/bin/env python

import sqlite3
import sys
import os

if len(sys.argv) != 2:
    print("{} [file_name]".format(sys.argv[0]))
    sys.exit(0)

if os.path.isfile(sys.argv[1]) == False:
    print("File {} does not exist.".format(sys.argv[1]))
    sys.exit(0)

dbname = sys.argv[1]
db = sqlite3.connect(dbname)
cur = db.cursor()

try:
    cur.execute('select * from results');
except sqlite3.OperationalError as e:
    print("Error: {}".format(e))
    sys.exit(0)

while True:
	r = cur.fetchone()
	if r == None:
		break
	#print("%s %s %s %s"%(r["ratio"], r["type"], r["address"], r["name"]))
	print(r)
#ret = row["total"] == 1
db.close()
