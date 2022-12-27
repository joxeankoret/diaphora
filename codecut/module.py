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

#This represents the information we want to record about an individual function
#The function lists returned by LFA and MaxCut are made up of these
class func_info():
  def __init__(self,loc,score1,score2):
    self.loc = loc        #the effective address of the function
    self.score1=score1    #"Calls from" local function affinity score
    self.score2=score2    #"Calls to" local function affinity score 
    self.total_score=score1+score2
    self.lfa_skip=0        #Set to 1 if "skipped" (not scored) by LFA
    self.edge=[0,0]         #Set by edge_detect() - if 1, this is the start of a new module
                #index 0 for LFA, 1 for MaxCut 

  def __repr__(self):
    return "Function: 0x%08x" % (self.loc)

  def __str__(self):
    return self.__repr__()

#This represents the object files (aka modules) identified by LFA and MaxCut  
class bin_module():
  def __init__(self,start,end,score,name):
    self.start=start
    self.end=end
    self.score=score  #Currently unused
    self.name=name

  def __repr__(self):
    line = "Module at 0x%08x:0x%08x" % (self.start, self.end)
    if self.name != "" and self.name is not None:
      line += " (name %s)" % self.name
    return line

  def __str__(self):
    return self.__repr__()
