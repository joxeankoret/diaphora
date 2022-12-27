##############################################################################################
# Copyright 2019 The Johns Hopkins University Applied Physics Laboratory LLC
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

import basicutils_7x as basicutils
import json
import os
import modnaming

## Utilities

#escape_for_graphviz()
#Return the string escaped for usage in a GraphViz file
def escape_for_graphviz(string):
    return json.dumps(string)

## CodeCut Basics
## A couple of functions for working with function and module lists and outputting results

#locate_module()
#Return the module information for a given function
#This assumes that the module list is in order, but not necessarily contiguous
def locate_module(module_list, f):
	found=0
	c=0
	#print "Finding %08x in module list length: %d" % (f,len(module_list))
	while ( (found != 1) and (c < len(module_list))):
		m = module_list[c]
		#print "\t%x - %x: %s" % (m.start,m.end,m.name)
		#this is the case where a function falls in the cracks between modules (because it wasn't cool enough to get a score)
		if (f < m.start):
			found = 1
			ret = None
		elif ((f >= m.start) and (f <= m.end)):
			found = 1
			ret = m
		c+=1
	return m	

		
#gen_mod_graph()
#Output a module-to-module call graph in GraphViz format
#For each module m_1
#  For each function <f> in the module
#    For each function that <f> calls
#      Lookup the module info for <f> m_2
#        If it's been assigned a module, add edge m_1 -> m_2 to the graph
def gen_mod_graph(module_list, suffix):
	c=0
	g=set()
	while (c < len(module_list)):
		m = module_list[c]
		f = m.start
		while (f <= m.end):
			for xref in basicutils.FuncXrefsFrom(f):
				target = locate_module(module_list,xref)
				if (target):
					g.add((m.name,target.name))
			f = basicutils.NextFunction(f)
		c+=1

	root_name = basicutils.GetRootName()
	file = open(root_name + "_" + suffix + "_mod_graph.gv", "w")
	
	file.write("digraph g {\n")
	
	for (node1,node2) in g:
		line = "%s -> %s\n" % (escape_for_graphviz(node1),escape_for_graphviz(node2))
		file.write(line)
		
	file.write("}\n")
	file.close()

#gen_rename_script()
#Output the module list with names as a Python script
#This script can then be run on the database if in the same directory as the basicutils libraries
#Look at basicutils.RenameRangeWithAddr to see the "canonical" name format - 
#  you can also tweak that function to use a different naming convention
def gen_rename_script(module_list, suffix):
	c=0

	root_name = basicutils.GetRootName()
	file = open(root_name + "_" + suffix + "_labels.py", "w")
	
	#if (IDA_VERSION < 7):
	#	file.write("import basicutils_6x as basicutils\n");
	#else:
	file.write("import basicutils_7x as basicutils\n");
	file.write("\ndef go():\n");
	
	while (c<len(module_list)):
		m=module_list[c]
		file.write("\tbasicutils.RenameRangeWithAddr(0x%x,0x%x,%r)\n"%(m.start,m.end,m.name))
		c+=1
		
	file.write("\n")
	file.write("if __name__ == \"__main__\":\n")
	file.write("\treload(basicutils)\n")
	file.write("\tgo()\n")
	file.close()

#gen_map_file()
#Produce a .map file similar to that produced by the ld option -Map=foo.map
#Use map_read.py to test accuracy when a ground truth map file is available
def gen_map_file(module_list, suffix):
	c=0

	root_name = basicutils.GetRootName()
	file = open(root_name + "_" + suffix + "_map.map", "w")
	
	while (c<len(module_list)):
		m=module_list[c]
		#mlen = basicutils.NextFunction(m.end) - m.start 
		mlen = m.end - m.start
		mlen_str = "0x%x" % mlen
		file.write("%s0x%016x%s %s\n" % (" .text".ljust(16),m.start,mlen_str.rjust(11),m.name))
		c+=1
		
	file.close()
	
#print_results():
#Write all of the results to <target>.csv - which can be opened in your favorite spreadsheet program		
def print_results(function_list, module_list1, module_list2):
	c=0
	root_name = basicutils.GetRootName()
	file = open(root_name + "_cc_results.csv", "w")
	
	#write header
	file.write("Function,Function #,LFA Score 1,LFA Score 2,LFA Total,LFA Edge,MC Edge,Function Name,Suggested Mod Name (LFA), Suggested Mod Name(MC),Source Str Ref\n");
	
	while (c<len(function_list)):
		f = function_list[c]
		fname = basicutils.GetFunctionName(f.loc)
		m1 = locate_module(module_list1, f.loc)
		m2 = locate_module(module_list2, f.loc)
		mname1 = m1.name
		mname2 = m2.name
		#hacky - should actually find the extent of the function
		#for now we'll just skip the last one
		if (c < (len(function_list) - 1)):
			nf = basicutils.NextFunction(f.loc)
			func_str_ref, score = modnaming.source_file_strings(f.loc, nf-1)
		else:
			func_str_ref=""
		line = "0x%08x, %d , %f, %f, %f, %d, %d, %s, %s, %s, %s\n" % (f.loc,c+1,f.score1, f.score2, f.total_score,f.edge[0],f.edge[1],fname, mname1, mname2, func_str_ref)
		file.write(line)
		c+=1
