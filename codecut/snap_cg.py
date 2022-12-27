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

## This code creates a Snap PNGraph object that represents the call graph of a binary
## (the .text section)

import snap
import sys

import idc
import struct
import idautils
import basicutils_7x as basicutils

MAX_DIST = 0


UGraph = []

def add_edge(f, t):
	global UGraph
	n = basicutils.GetFunctionName(f)
	if n != "":
		#since we're only doing one edge for each xref, we'll do weight based on distance from the middle of the caller to the callee
		f_start = idc.get_func_attr(f, idc.FUNCATTR_START)
		
		if (not UGraph.IsNode(f_start)):
			print("Error: had to add node (to): %08x" % f_start)
			UGraph.AddNode(f_start)
		
		print("%08x -> %08x" % (f_start, t))
		UGraph.AddEdge(t,f_start)
		
		#print "s_%#x -> s_%#x" % (f_start,t)," [len = ",get_weight(func_mid, t), "]"


def add_node(f):
	basicutils.ForEveryXrefToD(f, add_edge)
	
def create_snap_cg():
	global UGraph
	UGraph= snap.PNGraph.New()
	
	#Add every function linearly, this makes sure the nodes are in order
	basicutils.ForEveryFuncInSeg(".text",UGraph.AddNode)
	basicutils.ForEveryFuncInSeg(".text",add_node)
	
	for NI in UGraph.Nodes():
		print("node id 0x%x with out-degree %d and in-degree %d" %(
			NI.GetId(), NI.GetOutDeg(), NI.GetInDeg()))
	
	return UGraph
