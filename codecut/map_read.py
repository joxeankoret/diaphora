#!/usr/bin/python

##############################################################################################
# Copyright 2018 The Johns Hopkins University Applied Physics Laboratory LLC
# All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
# OR OTHER DEALINGS IN THE SOFTWARE.
#
# HAVE A NICE DAY.

import sys

#Syntax: map_read.py <ground truth .map file> <LFA produced .map file>
#Reads the two map files and outputs a score
#Score is % overlap, % underlap, and % gap (the sum of which should be 100%)

#Raw list of modules
g_mod_list1 = []
g_mod_list2 = []
#"Reconciled" module list - after modules have been combined to represent best alignment
g_rec_list1 = []
g_rec_list2 = []

#name
#offset - starting address of the module
#mlen - length of the module
#reach - end address of the module (offset + mlen)
#gap - when collapsing two modules, 

class bin_mod:
	def __init__(self, n, o, ml):
		self.name = n
		self.offset = o
		self.mlen = ml
		self.reach = o+ml
		self.gap = 0

#map_parse(function, mlist):
#Parse a gcc/ld formatted .map file
# (mlist == 1): ground truth map, saved to g_mod_list1
# (mlist == 2): LFA map, saved to g_mod_list2
def map_parse(f,mlist):
	global g_mod_list1
	global g_mod_list2

	line = f.readline()
	prev_name = ""
	while (line != ""):
		#print "line %s" % line
		if (not line.startswith(" .text") or (len(line) < 17)):
			line = f.readline()
			continue
		#line wrap case	
		if not ((line[16] == '0') and (line[17] == 'x')):
			seg = line.strip()
			line = f.readline()
		else:
			seg = line[0:15].strip()
		offset = int(line[16:34],16)
		mlen = int(line[35:45].strip(),16)
		name = line[46:].strip()

		#print "%s\n%s\n%s\n%s\n"% (line[0:15],line[16:33],line[34:45],line[46:])		

		#print "Seg: %s Offset: %x Len: %x Name: %s" % (seg,offset,mlen,name)

		if (offset == 0) or (mlen == 0):
			line = f.readline()
			continue

		#print "Seg: %s Offset: %x Len: %x Name: %s" % (seg,offset,mlen,name)
		if (name == prev_name):
			#print "Combining"
			if (mlist == 1):
				new_reach = offset+mlen
				begin = g_mod_list1[-1].offset
				new_len = new_reach-begin
				g_mod_list1[-1].mlen = new_len
				g_mod_list1[-1].reach = new_reach
			else:
				new_reach = offset+mlen
				begin = g_mod_list2[-1].offset
				new_len = new_reach-begin
				g_mod_list2[-1].mlen = new_len
				g_mod_list2[-1].reach = new_reach
			#print "Seg: %s Offset: %x Len: %x Name: %s" % (seg,begin,new_len,name)
		else:	
			bm = bin_mod(name,offset,mlen)
			if (mlist == 1):
				g_mod_list1.append(bm)
			else:
				g_mod_list2.append(bm)
			
		#read next line
		line = f.readline()
		prev_name = name			

#map_print():
#Print both ground truth and LFA map output
def map_print(n):
	if (n==1):
		print("Map 1 (ground truth):")
		mod_list = g_mod_list1
	else:
		print("Map 2:")
		mod_list = g_mod_list2
	print("# of modules: %d" % len(mod_list))
	for x in range(len(mod_list)):
		print("Name: %s Offset: %x Len: %x" % (mod_list[x].name,mod_list[x].offset,mod_list[x].mlen))


#score_underlap(module1,module2):
#opposite of overlap - actually "disjoint areas" might be more accurate
#For the purposes of scoring this is the area of m1 that m2 doesn't cover
#to ensure that the underlap does not get counted twice
def score_underlap(m1,m2):
	#Assume that the m1s are contiguous (from .map files)
	#Only measure the portion of this m1 that the m2 doesn't cover
	#This ensures that disjoint areas don't get counted twice
	m2_upper = max(m1.offset,m2.offset)
	m2_lower = min(m1.reach, m2.reach) 
	ul = abs (m1.offset - m2_upper)
	ul += abs (m1.reach - m2_lower)
	return ul	
	
#mod_underlap(m1,m2):
#Like score underlap but this is a simpler calculation for use with module list reconciliation
def mod_underlap(m1,m2):
	ul = abs (m1.offset - m2.offset)
	ul += abs (m1.reach - m2.reach)
	return ul	


#mod_collapse(module1,module2):
#Return a module object that is the combination of the two modules
#Does not update either of the global module lists
def mod_collapse(m1,m2):
	nname = m1.name + "_and_" + m2.name
	noffset = min(m1.offset,m2.offset)
	nr = max(m1.reach,m2.reach)
	nlen = nr - noffset

	cm = bin_mod(nname, noffset, nlen)

	cm.gap = m1.gap
	cm.gap += m2.gap
	#will work regardless of module order, 
	#the correct one will be positive, the wrong one negative
	cm.gap += max(m2.offset - m1.reach, m1.offset - m2.reach)
	
	return cm

#mod_print(m):
#Print a single module	
def mod_print(m):
	#print "%s: %08x - %08x" % (m.name,m.offset,m.reach),
	print("%08x - %08x" % (m.offset,m.reach), end=' ')
	if (m.gap != 0):
		print(" gap: %x" % m.gap, end=' ')

#rec_list_print():
#Print side by side the reconciled module lists		
def rec_list_print():
	i1 = len(g_rec_list1)
	i2 = len(g_rec_list2)
	if (i1 != i2):
		print("Error: List lengths don't match, not fully reconciled (%d and %d)." % (i1,i2))
		return
	for i in range(i1):
		mod_print(g_rec_list1[i])
		mod_print(g_rec_list2[i])
		print("u: %x" % (score_underlap(g_rec_list1[i],g_rec_list2[i])))

#final_score():
#Determine the scores by iterating through the reconciled module lists
#and tallying underlap areas and gap areas		
def final_score():
	start = min(g_rec_list1[0].offset,g_rec_list2[0].offset)
	end = max(g_rec_list1[-1].reach,g_rec_list2[-1].reach)
	i1 = len(g_rec_list1)
	i2 = len(g_rec_list2)
	if (i1 != i2):
		print("Error: List lengths don't match, not fully reconciled (%d and %d)." % (i1,i2))
		return
	s=0
	g=0
	for i in range(0,i1):
		s+=score_underlap(g_rec_list1[i],g_rec_list2[i])
		#only count gaps from the "compare" map file (the one we generate with LFA)
		g+=g_rec_list2[i].gap
	#Area of overlap - total area - (underlaps + gaps)
	good_area = (end-start) - (s+g)
	print("Length: 0x%x Good: 0x%x (%2f) Underlap: 0x%x (%2f) Gaps: 0x%x (%2f)" % (end-start,good_area, good_area*100.0/(end-start),s,s*100.0/(end-start),g,g*100.0/(end-start)))
	return (s+g)/1.0/(end-start)	
			
#map_reconcile():
#Attempt to combine modules in either list to make the maps more similar
#When combining modules, keep track of gaps between the modules so we can account for that in the overall score
#This might seem like cheating, but here's why it's not:
# - we want to give the algorithm credit if it finds a couple of clusters of functionality within a .o file
#   (i.e. it says one .o file is really 2 or 3 .o files)
# - we want to give the algorithm credit if it says nearby .o files are so inter-related that they are essentially one
#   (i.e. it says that 2 or 3 adjacent .o files are really one .o file
#
#I'm definitely open to suggestions on better ways to do this
def map_reconcile():
	i1 = 0
	i2 = 0

	while (i1 < len(g_mod_list1)) and (i2 < len(g_mod_list2)):
		m1 = g_mod_list1[i1]
		m2 = g_mod_list2[i2]
	
		#"reach" - aka the end of the current modules under consideration
		m1r = m1.reach
		m2r = m2.reach

		#current underlap
		po = mod_underlap(m1,m2)
		pc = 0x10000000000

		print("  m1 (%d): " % i1, end=' ')
		mod_print(m1)
		print("  m2 (%d): " % i2, end=' ')
		mod_print(m2)
		print("  underlap: %x" % (po))

		d=0
		#module 1 is longer than module 2, so attempt to collapse modules in list 2 to optimize
		if (m1r > m2r):
			nm2 = g_mod_list2[i2]
			#add/collapse m2 modules, but check to see if makes it better
			while (d == 0) and (i2+1 < len(g_mod_list2)):
				pnm2 = nm2
				nm2 = mod_collapse(nm2,g_mod_list2[i2+1])
				pc = mod_underlap(m1, nm2)
				print("nm2 (%d): (%x)" % (i2+1,pc), end=' ')
				mod_print(nm2)	
				print("")
				if (pc < po):
					po = pc
					i2+=1
				else:
					d=1
			print("Collapsed m2 (%d): " % i2, end=' ')
			mod_print(pnm2)
			print("")
			
			#add final collapsed modules to reconciled list
			g_rec_list1.append(m1)
			g_rec_list2.append(pnm2)
		#module 2 is longer than module 1, so attempt to collapse modules in list 1 to optimize	
		else:
			nm1 = g_mod_list1[i1]
			while (d==0) and (i1+1 < len(g_mod_list1)):
				pnm1 = nm1
				nm1 = mod_collapse(nm1,g_mod_list1[i1+1])
				pc = mod_underlap(nm1, m2)
				print("nm1 (%d): (%x)" % (i1 + 1, pc), end=' ')
				mod_print(nm1)
				print("")
				if (pc < po):
					po = pc
					i1 += 1
				else:
					d=1
			print("Collapsed m1 (%d): " % i1, end=' ')
			mod_print(pnm1)
			print("")
			g_rec_list1.append(pnm1)
			g_rec_list2.append(m2)

		i1+=1
		i2+=1

		print("")

		#end case
		#if we've got one module left on either side,
		#collapse all the other modules on the other side to match
		if (i1 == len(g_mod_list1)-1):
			m1 = g_mod_list1[i1]
			print("end m1 (%d):" % (i1), end=' ')
			mod_print(m1)
			print("")
			nm2 = g_mod_list2[i2]
			i2 += 1
			while (i2 < len(g_mod_list2)):
				nm2 = mod_collapse(nm2,g_mod_list2[i2])
				print("end nm2 (%d):" % (i2), end=' ')
				mod_print(nm2)
				print("")
				i2 += 1
			g_rec_list1.append(m1)
			g_rec_list2.append(nm2)
		if (i2 == len(g_mod_list2)-1):
			m2 = g_mod_list2[i2]
			print("end m2 (%d):" % (i2), end=' ')
			mod_print(m2)
			print("")
			nm1 = g_mod_list1[i1]
			i1 += 1
			while (i1 < len(g_mod_list1)):
				nm1 = mod_collapse(nm1,g_mod_list1[i1])
				print("end nm1 (%d):" % (i1), end=' ')
				mod_print(nm1)
				print("")
				i1 += 1
			g_rec_list1.append(nm1)
			g_rec_list2.append(m2)

	
			
#"ground truth" map file
f = open(sys.argv[1], 'r')
map_parse(f,1)
#map file to compare
f2 = open(sys.argv[2], 'r')
map_parse(f2,2)

map_print(1)
map_print(2)

#"Reconcile" maps to make them more similar - see comment above for why we do this
map_reconcile()

#Print reconciled map
rec_list_print()

#Print score
print("Score: %f" % (final_score()))
f.close()
f2.close()
