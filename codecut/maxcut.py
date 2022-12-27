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

###############################################################
###  Object File Boundary Detection in IDA Pro with MaxCut  ###
###############################################################

import snap
import sys
import snap_cg
import module

g_maxcut_modlist = []

#make_subgraph()
#returns a Snap subgraph for just the address region specified
#(i.e. the subgraph will not have any edges that originate outside the region
#or terminate outside the region)

def make_subgraph(region_start,region_end, graph):
	print("make_subgraph: start: 0x%x and end: 0x%x" % (region_start,region_end))
	NIdV = snap.TIntV()
	#this would be much faster if we had a linear list of functions (nodes)
	for Node in graph.Nodes():
		start = Node.GetId()
		if (start >= region_start) and (start <= region_end):
			NIdV.Add(start)
		if (start > region_end):
			break
	return snap.GetSubGraph(graph, NIdV)

#make_cut()
#This function analyzes the region specified and returns the cut address for the address with the 
#maximum score, i.e. the address that has the highest average distance call length of function calls 
#that go across the address.  If multiple addresses with zero calls are found (inf. score) the one 
#closest to the middle of the region is returned.  	
def make_cut(region_start, region_end, graph):

	print("make_cut: start: 0x%x end: 0x%x" % (region_start,region_end))

	weight = {}
	z = 0
	zeroes = []
	for Node in graph.Nodes():
		start = Node.GetId() 
		#iterate only over nodes in this region
		cut_address = start - 1
		if cut_address < region_start:
			continue
			
		weight[cut_address] = 0
		edge_count = 0

		for Edge in graph.Edges():
			edge_start = Edge.GetSrcNId()
			edge_end = Edge.GetDstNId()
			#only look at edges that cross the possible cut address
			#handle both cases for the directed graph
			if (edge_start < cut_address and edge_end > cut_address) or (edge_end < cut_address and edge_start > cut_address):
				#print "      cut %x, %x to %x cross" % (cut_address,edge_start,edge_end)
				weight[cut_address] += abs(edge_end - edge_start)
				edge_count +=1
			
		#If we have a place where we have no edges crossing - keep track of it
		#We will pick the place closest to the center of the module
		if edge_count == 0:
			print("  returning 0 weight count at: 0x%0x" % cut_address)
			z+=1
			zeroes.append(cut_address)
			weight[cut_address] = 0
		else:
			weight[cut_address] = weight[cut_address]/ edge_count
			#print "w: %x: %x" % (cut_address, weight[cut_address])

	#if we had edges with zero crossings, pick the one closest to the center	
	if (z > 0):
		print("  total of %d zero weight counts" % (z))
		center = region_start + ((region_end-region_start)/2)
		min_dist = sys.maxsize
		for i in range(z):
			dist = abs(center - zeroes[i])
			if dist < min_dist:
				min_dist = dist
				min_zero = zeroes[i]
		print("  returning zero cut at addr: %x" % min_zero)
		return min_zero
		
	#otherwise pick the edge with the maximum weight score
	max_weight=0
	#print "   weight table:"
	for addr,w in weight.items():
		#print "      %x: %x" % (addr,w)
		if w > max_weight:
			max_addr = addr
			max_weight = w

	print("   returning max weight: %f at addr: 0x%x" % (max_weight,max_addr))
	return max_addr

#do_cutting()
#This is the main recursive algorithm for MaxCut
#Find a cut address, split the graph into two subgraphs, and recurse on those subgraphs
#Stop if the area being cut is below a particular threshold	
def do_cutting(start, end, graph):
	nodes = graph.GetNodes()
	print("do_cutting: start: 0x%x end: 0x%x nodes: 0x%x" % (start, end, nodes))
	THRESHOLD = 0x1000
	#THRESHOLD = 0x2000
	
	if (end - start > THRESHOLD) and (nodes > 1):
		cut_address = make_cut(start, end,graph)

		graph1 = make_subgraph(start,cut_address,graph)
		graph2 = make_subgraph(cut_address+1,end,graph)

		do_cutting(start,cut_address,graph1)
		do_cutting(cut_address+1,end,graph2)
	else:
		print("Module 0x%x to 0x%x" % (start, end))
		b_mod = module.bin_module(start,end,0,"")
		g_maxcut_modlist.append(b_mod)

#func_list_annotate()
#This function copies our list of modules into the function list
#This allows us to have a single function list with modules from multiple algorithms (LFA and MaxCut)
def func_list_annotate(flist):
	c=0
	m=0
	while (m < len(g_maxcut_modlist)):
		start = g_maxcut_modlist[m].start
		while (flist[c].loc < start):
			#print "F: %08x M: %08x" % (flist[c].loc, start)
			c+=1
			if (c == len(flist)):
				print("Error: Maxcut module list does not reconcile with function list")
				return None
		flist[c].edge[1]=1
		#print "MC: Set %08x func edge to 1" % flist[c].loc
		m+=1
	return flist

#Main entry point
#Returns a global function list (annotated with MaxCut edges) and a global module list
def analyze(flist):		

	sys.setrecursionlimit(5000)
	UGraph = snap_cg.create_snap_cg()

	g_min_node=sys.maxsize
	g_max_node=0

	for Node in UGraph.Nodes():
		id = Node.GetId()
		if id < g_min_node:
			g_min_node = id
		if id > g_max_node:
			g_max_node = id
 
	do_cutting(g_min_node,g_max_node, UGraph)
	
	r_flist = func_list_annotate(flist)
	
	return r_flist,g_maxcut_modlist


