#!/usr/bin/env python

import sqlite3
dbname = "a_vs_b.diaphora";
db = sqlite3.connect(dbname)
cur = db.cursor()
cur.execute('select * from results');
while True:
	r = cur.fetchone()
	if r == None:
		break
	#print("%s %s %s %s"%(r["ratio"], r["type"], r["address"], r["name"]))
	print(r)
#ret = row["total"] == 1
db.close()
