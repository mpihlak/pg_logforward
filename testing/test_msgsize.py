#!/usr/bin/env python

import sys, psycopg2

if len(sys.argv) < 2:
    print "usage: %s <max> [min]" % sys.argv[0]
    sys.exit(1)

upper = int(sys.argv[1])
if len(sys.argv) > 2:
    lower = int(sys.argv[2])
else:
    lower = 0

con = psycopg2.connect("")
cur = con.cursor()

print "Ready?"
sys.stdin.readline()

for i in range(lower, upper):
    q = "select '%s'" % ('x' * i)
    print i
    cur.execute(q)
    cur.fetchall()
    con.commit()

