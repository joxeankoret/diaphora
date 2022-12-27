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

################################################################################
###  Object File Boundary Detection in IDA Pro with Local Function Affinity  ###
################################################################################

# LFA Metric
# Local Function Affinity (LFA) is a measurement of the direction a function
# is being "pulled" by the functions it calls and the functions that call it.
# By looking at an average of the log of the distance between these functions
# we get a measurement of whether the function is related to functions in the
# positive or negative direction.

# Edge Detection
# In a standard C/C++ development environment, the project is divided into
# multiple source files, which are compiled to object files, then linked into
# the final binary in order.  If external references are eliminated (LFA does
# this imperfectly by just eliminating calls whose distance is above a chosen
# threshold) we would expect to see LFA starting positive, switching to
# negative over the course of a source file, then switching back to positive
# at the beginning of the next file.  So object file boundaries 

# What is code anyway?
# Don't get too hung up on "object file boundaries" - for LFA (or any other
# attempt to solve the problem) to be perfect, the design and implementation
# of the code would have to be perfect.  What LFA is really finding is clusters
# of functionality, that should be more or less related to object files
# but it will often break up large object files into multiple clusters or
# detect 2 or 3 related object files as one file.

IDA_VERSION = 7
import basicutils_7x as basicutils

#External dependencies
import math

#CodeCut dependencies
import cc_base
import module

#Threshold above which a function call is considered "external"
#For published research - 0x1000 = 4K
MAX_CALL = 0x1000

#This is a list of the LFA scores for all functions
g_function_list = []

#This is a list of modules a.k.a. object files after the edge_detect()
#function is executed 
g_module_list = []


#func_callers_weight(f):
#Return the LFA score for functions that this functions calls (i.e. the "calls from" score)
#If there are no references, return 0
def func_callers_weight(f):
	fc = 0
	fs = 0
	for xref in basicutils.FuncXrefsFrom(f):
		dist = abs(xref - f)
		#print "%08x:  %08x %d " % (f, xref, dist),
		if dist > MAX_CALL:
			continue
		if (dist != 0):
			logdist = math.log(dist)
		else: #recursive function call
			logdist = 0
		if (xref - f < 0):
			o = -logdist
		else:
			o = logdist
			#print " %f " % o,
		fs += o
		fc += 1

	if fc == 0:
		score = 0
	else:		
		score = fs / fc
	return score

#func_callee_weight(f):
#Return the LFA score for calls where this function is the "callee" (i.e. the "calls to" score)
#If there are no references, return 0
def func_callee_weight(f):
	fc = 0
	fs = 0
	a = 0
	for xref in basicutils.CodeRefsTo(f):
	
		dist = abs(xref - f)
		#print "%08x:  %08x %d " % (f, xref, dist),
		if dist > MAX_CALL:
			continue
		if (dist != 0):
			logdist = math.log(dist)
		else: #recursive function call
			logdist = 0
		if (xref - f < 0):
			o = -logdist
		else:
			o = logdist
			#print " %f " % o,
		fs += o
		fc += 1

		
	if fc == 0:
		score = 0
	else:		
		score = fs / fc
	return score
	
#func_call_weight(start,end):
#Iterate over each function in the range and calculated the LFA scores
# If both scores are 0, skip the function altogether, exclude it from the list
# If one score is 0, interpolate that score from the previous score	
def func_call_weight(f_start, f_end):
	global g_function_list
	
	c = 1
	f = f_start
	fe = f_end
	
	if f==0:
		f = basicutils.NextFunction(0)
		f_end = basicutils.BADADDR
	
	prevscore = 0
	prevscore_1 = 0
	prevscore_2 = 0
	z1 = 0
	z2 = 0
	
	#for each function in range
	while (f < fe):
		
		#get both LFA scores for the function
		score_1 = func_callers_weight(f)
		score_2 = func_callee_weight(f)

		#if both scores are 0 (i.e. no references for the function or all refs are above the threshold)
		#then skip the function altogether
		if (score_1 == 0) and (score_2 == 0):
			#print("Skipping 0x%08x\n" % f)
			prevscore_1 = 0
			prevscore_2 = 0
			z1 = 1
			z2 = 1
			finf = module.func_info(f,0,0)
			finf.lfa_skip=1
			g_function_list.append(finf)
			f = basicutils.NextFunction(f)
			continue
		
		#if 1st or 2nd score is zero, interpolate using previous score and an assumed negative linear slope
		#otherwise use the score
		if (score_1 == 0):
			score_1 = prevscore_1 - z1 * .4
			z1 += 1
		else:
			prevscore_1 = score_1
			z1 = 1
		if (score_2 == 0):
			score_2 = prevscore_2 - z2 * .4
			z2 += 1
		else:
			prevscore_2 = score_2
			z2 = 1
		
		total_score = score_1 + score_2
		
		#Output scores in log window
		#print("0x%08x, %d , %f, %f, %f" % (f, c,score_1, score_2, total_score))
		
		#Add scores to the global function score list
		finf = module.func_info(f,score_1,score_2)
		finf.lfa_skip=0
		g_function_list.append(finf)
		
		line = "0x%08x, %d , %f, %f, %f\n" % (f,c,score_1, score_2, total_score)
		f=basicutils.NextFunction(f)
		c+=1
		
#get_last _three and get_lfa_start:
#Previously LFA would just skip functions if they had no caller or callee score
#it would effectively drop them.  This meant that when doing edge detection we
#knew every function in the function list had a score.  Now we're putting all
#functions in the function list, and we have a "skip" field if LFA should skip it
#for scoring purposes.  So these functions help parse that skip field, since for
#edge detection we look at the previous three scores.
def get_last_three(index):
	c=0
	i = index-1
	p=[]
	while ((c<3) and (i>0)):
		#print "get_last_3: %d,%d" % (c,i)
		if (g_function_list[i].lfa_skip == 0):
			p.append(g_function_list[i])
			c+=1
		i-=1
	if (c==3):
		return p[0],p[1],p[2]
	else:
		print("Error: could not find 3 scored entries before index: %d  (%d,%d)" % (index, i, c))
		return 0,0,0

def get_lfa_start():
	c=0;
	i=0;
	while (c < 4):
		#print "get_lfa_start: %d,%d" % (c,i)
		if (g_function_list[i].lfa_skip==0):
			c+=1
		i+=1
	return i
		
#edge_detect():
# Determine boundaries between object files
#  Edge condition is a delta of at least 2 where the current score is positive 
#      and 2 of the last 3 scores were negative (negative trend) 		
def edge_detect():
	global g_function_list
	global g_module_list
	
	#For published research
	EDGE_THRESHOLD = 2
	
	c=get_lfa_start()
	#do edge detection
	while (c<len(g_function_list)):
		if (g_function_list[c].lfa_skip == 0):
			f_1,f_2,f_3 = get_last_three(c)
			p_1 = f_1.total_score
			p_2 = f_2.total_score
			p_3 = f_3.total_score
			s = g_function_list[c].total_score
			#if score is positive and it is diff of at least 2 from previous
			#and the previous function was not an edge
			if ((not f_1.edge[0] == 1) and (s > 0) and ((s - p_1) > EDGE_THRESHOLD)):
				#if 2 of last 3 were negative
				m = sorted([p_1,p_2,p_3])
				if (m[1] < 0):
					g_function_list[c].edge[0]=1
		c+=1
	#assign modules based on where the edges are
	c=0
	mod_start = g_function_list[0].loc
	while(c<len(g_function_list)):
		f = g_function_list[c]
		if (f.edge[0] == 1):
			#change from previous code, this will make the modules contiguous
			b_mod = module.bin_module(mod_start,f.loc-1,0,"")
			mod_start = f.loc #set the start of the next module to this function (where edge was detected)
			g_module_list.append(b_mod)
		c+=1

#Main entry point - returns an LFA module list and a global function list (with the LFA module edges marked)	
def analyze():
	global g_function_list
	global g_module_list

	g_function_list.clear()
	g_module_list.clear()

	#Define range to analyze
	#Just start from the first function in DB
	start = basicutils.NextFunction(0)
	end = basicutils.BADADDR
	
	#Calculate LFA score for all functions
	func_call_weight(start,end)
	#Detect edges - object file boundaries
	edge_detect()
	
	return g_function_list, g_module_list
