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

import maxcut
import lfa
import module
import modnaming
import cc_base
import basicutils_7x as basicutils
import snap_cg
import imp

def go():
	
	#Do LFA and MaxCut Analysis to find module boundaries
	lfa_funclist, lfa_modlist = lfa.analyze()
	merge_flist,maxcut_modlist = maxcut.analyze(lfa_funclist)
	
	#Guess names for the modules using NLP
	lfa_modlist = modnaming.guess_module_names(lfa_modlist)
	maxcut_modlist = modnaming.guess_module_names(maxcut_modlist)
	
	#Output all results as .csv
	cc_base.print_results(merge_flist, lfa_modlist, maxcut_modlist)
	
	#Output module-to-module call graph as a Graphviz .gv file
	cc_base.gen_mod_graph(lfa_modlist, "lfa")
	cc_base.gen_mod_graph(maxcut_modlist, "mc")
	
	#Output a Python script that will rename modules
	cc_base.gen_rename_script(lfa_modlist, "lfa")
	cc_base.gen_rename_script(maxcut_modlist, "mc")
	
	#Output .map file (for comparison against ground truth, when available)
	cc_base.gen_map_file(lfa_modlist, "lfa")
	cc_base.gen_map_file(maxcut_modlist, "mc")

	return True

if __name__ == "__main__":
	imp.reload(modnaming)
	imp.reload(module)
	imp.reload(cc_base)
	imp.reload(lfa)
	imp.reload(maxcut)
	imp.reload(snap_cg)
	imp.reload(basicutils)
	go()