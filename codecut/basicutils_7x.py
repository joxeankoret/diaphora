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

# basicutils - a version-agnostic API for IDA Pro with some (slightly) higher level functionality
# This is the 7.x version - see basicutils_6x for the 7.x version
import os

import ida_bytes
import ida_funcs
import ida_nalt
import ida_ua
import ida_name
import idc
import struct
import idautils
import ida_idaapi
import ida_segment
import re

BADADDR = ida_idaapi.BADADDR

def SegByName(n):
	t = ida_segment.get_segm_by_name(n)
	if (t and t.start_ea != ida_idaapi.BADADDR):
		start = t.start_ea
		end = t.end_ea
	else:
		start = ida_idaapi.BADADDR
		end = ida_idaapi.BADADDR
	return (start,end)

def GetFunctionName(x):
	return idc.get_func_name(x)

def GetInputFile():
	return idc.get_root_filename()

def GetIdbFile():
    return idc.get_idb_path()

def GetRootName():
    return os.path.join(os.path.dirname(GetIdbFile()), os.path.basename(GetInputFile()))

def NextFunction(x):
	return idc.get_next_func(x)

def PrevFunction(x):
	return idc.get_prev_func(x)

MAX_OPCODE_LEN = 15	
def PrevInstr(ea):
    # TODO this will return an inst_t type. Need to figure out how to populate it/make workflow happy
	out=ida_ua.insn_t()
	ida_ua.decode_prev_insn(out, ea)
	return out.ea
	
def CodeRefsTo(target):
    return idautils.CodeRefsTo(target,0)

def ForEveryUniqXrefTo( target, fun ):
    a = 0
    for xref in idautils.CodeRefsTo(target,0):
        if idc.get_func_attr(xref,idc.FUNCATTR_START) != a :
            fun(xref)
            a = idc.get_func_attr(xref, idc.FUNCATTR_START);
            
def ForEveryXrefTo( target, fun ):
    for xref in idautils.CodeRefsTo(target,0):
        fun(xref)

def ForEveryUniqXrefToD( target, fun ):
    a = 0
    for xref in idautils.CodeRefsTo(target,0):
        if idc.get_func_attr(xref,idc.FUNCATTR_START) != a :
            fun(xref, target)
            a = idc.get_func_attr(xref, idc.FUNCATTR_START);
        
def ForEveryXrefToD( target, fun ):
    for xref in idautils.CodeRefsTo(target,0):
        fun(xref, target)

def ForEveryFuncInDb( fun ):
    f = NextFunction(0)
    while (f != ida_idaapi.BADADDR):
        """print "ev: %#x" % f"""
        fun(f)
        f=NextFunction(f)

def ForEveryFuncInSeg( seg, fun ):
    start,end = SegByName(".text")
    if (start == BADADDR):
        start = NextFunction(0)
        end = BADADDR
    f = start
    while (f < end):
        """print "ev: %#x" % f"""
        print(f)
        fun(f)
        f=NextFunction(f)		
		
		
def NFuncUp( fun, n ) :
    i=0
    f=fun
    while ((i<n) and (f!=ida_idaapi.BADADDR)):
        f=PrevFunction(f)
        i=i+1
    return f
    
def NFuncDown( fun, n ) :
    i=0
    f=fun
    while ((i<n) and (f!=ida_idaapi.BADADDR)):
        f=NextFunction(f)
        i=i+1
    return f

def FuncMidPt( fun ):
    fstart = idc.get_func_attr(fun, idc.FUNCATTR_START)
    fend = idc.get_func_attr(fun, idc.FUNCATTR_END)
    return fstart+((fend-fstart)/2)


def FuncXrefsFrom ( fun ) :
    f = set()
    for item in idautils.FuncItems(fun):
        for x in idautils.CodeRefsFrom(item,0):
            s = idc.get_func_attr(x, idc.FUNCATTR_START)
            if (x == s):
                f.add(x)
    #print "func xrefs from"
    #print f
    return f

def XrefFromRange ( fun ) :
    f = FuncXrefsFrom(fun)
    if f:
        return (min(f),max(f))
    else:
        return (0,0)
    
def ProgramAddrRange() :
    return ida_funcs.get_prev_func(ida_idaapi.BADADDR) - ida_funcs.get_next_func(0)

def MemCopy( dest, src, length ) :
    for i in range(0, length):
        #if (i < 20):
        #	print "set byte at %#x to %#x" % (dest+i, idc.Byte(src+i))
        ida_bytes.patch_byte(dest+i,ida_bytes.get_byte(src+i))
        
def PrefixRange(start, end, prefix) :
    x = start
    while x < end:
        n = idc.get_func_name(x)
        if n.startswith("sub_"):
            nn = prefix + n
            print("Renaming %s to %s\n" % (n, nn))
            ida_name.set_name(x,nn)
        x = NextFunction(x)

        
def snakeToCamelCase(s):
    f = s.lstrip("_")
    nf = ""
    nx = 0
    x=0
    while (x<len(f)):
        #print "%s" % (f[x])
        if f[x] == '_':
            nf+=(f[x+1].upper())
            x+=2
        else:
            nf+=f[x]
            x+=1
        nx+=1
    return nf
    
def isSnakeCase(s) :
    p = re.compile("[a-zA-Z0-9]+(_[a-zA-Z0-9]+)+\Z")
    if p.match(s):
        return True
    return False
    
#Todo - right now this is going to miss something like FooBARFunction
def isCamelCase(s) :
    p = re.compile("([A-Z][a-z0-9]+)([A-Z][a-z0-9]+)+\Z")
    if p.match(s):
        return True
    return False
    
#Todo - weed out if it's all uppercase or all uppercase and _, etc.
def isUCSnakeCase(s):
    p = re.compile("[A-Z0-9]+(_[A-Z0-9]+)+\Z")
    if p.match(s):
        return True
    return False

def isPlausibleFunction(s):
    if isSnakeCase(s):
        if isUCSnakeCase(s):
            return False
        return True
    if isCamelCase(s):
        return True
    return False

def PrependStrToFuncName(f,s):
    n = idc.get_func_name(f)
    n = s + n
    ida_name.set_name(f,n)

#The "canonical" name format (for now) is <module name>_<func name>_<address>
#where <module_name> and <func_name> are in camel case.
#This is not ideal for a number of reasons but this is a workaround for now	

#Return just the "function name" part of the canonical name	
def GetCanonicalName(f):
    n = idc.get_func_name(f)
    parts = n.split("_")
    if len(parts) == 3:
        return parts[1]
    else:
        return None

#Put function in canonical format, given the function name and module name        
def NameCanonical(f,mod_name,func_name):
    n = "%s_%s_%08x" % (mod_name,func_name,f)
    print("Renaming %s to %s\n" % (idc.get_func_name(f),n))
    ida_name.force_name(f,n)

#Put function in canonical format when it doesn't have a name, but you know the module name    
def RenameFuncWithAddr(f,s):
    func_name = "unk"
    NameCanonical(f,s,func_name)

#Use this if you have pre-existing named functions in the DB that are in non-canonical format
def RenameRangeWithAddr(start,end,s):
    x = start
    while (x<=end):
        n = idc.get_func_name(x)
        if (n.startswith("sub_")):
            RenameFuncWithAddr(x,s)
        else:
            NameCanonical(x,s,n)
        x = NextFunction(x)
		
#Rename a function in canonical format without changing the module name
def CanonicalFuncRename(f,name):
    n = idc.get_func_name(f)
    parts = n.split("_")
    new_name = "%s_%s_%08x" % (parts[0],name,f)
    print("Renaming %s to %s\n" % (n, new_name))
    ida_name.set_name(f,new_name)

#Rename the module name without changing the function name		
def RenameFuncWithNewMod(f,mod):
    n = idc.get_func_name(f)
    parts = n.split("_")
    new_name = "%s_%s_%08x" % (mod,parts[1],f)
    print("Renaming %s to %s\n" % (n, new_name))
    ida_name.set_name(f,new_name)

#Rename a module (all functions that start with <mod>_)	
def RenameMod(orig, new):
    i = idc.get_next_func(0)
    while (i != BADADDR):
        n = idc.get_func_name(i)
        if n.startswith(orig+"_"):
            RenameFuncWithNewMod(i,new)
        i = NextFunction(i)
	
#Just rename the module over a given range (can be used to split a module and give part a new name)
def RenameModRange(start, end, new):
    x = start
    while (x<=end):
        n = idc.get_func_name(x)
        RenameFuncWithNewMod(x,new)
        x = NextFunction(x)
		
#Given a range of functions, some of which may have names and module names
# and a module name, put names in canonical format        
def CanonicalizeRange(start,end,mod):
    x = start
    while (x<=end):
        n = idc.get_func_name(x)
        #if it already starts with mod name, assume it's canonical
        if (not n.startswith(mod+"_")):
            if (n.startswith("sub_")):
                RenameFuncWithAddr(x,mod)
            #this should be contains "_"
            elif ("_" in n):
                n = snakeToCamelCase(n)
                NameCanonical(x,mod,n)
            else:
                NameCanonical(x,mod,n)
        x = NextFunction(x)	

#Returns a string that is the concatenation of all of the string references from a function, separated by <sep>
#Iterates through every item in function and looks for data references that are strings        
def CompileTextFromFunction(f,sep):
    s=""
    faddr = list(idautils.FuncItems(f))
    for c in range(len(faddr)):
        for d in idautils.DataRefsFrom(faddr[c]):
            t = ida_nalt.get_str_type(d)
            if ((t==0) or (t==3)):
                s += " "+ sep + " " + idc.GetStrLitContents(d)
    return s

#Returns a string which is the concatenation all of the string references 
# for an address range in the program, separated by <sep>
#Similar to above, but iterates over the whole set of functions in the given range    
def CompileTextFromRange(start,end,sep):
    x = start
    s = ""
    while (x<=end):
        faddr = list(idautils.FuncItems(x))
        #print "items list: %d" % len(faddr)
        for c in range(len(faddr)):
            for d in idautils.DataRefsFrom(faddr[c]):
                #print "Found ref at %x: %x " % (faddr[c],d)
                t = ida_nalt.get_str_type(d)
                if ((t==0) or (t==3)):
                     s += " " + sep + " " + GetStrLitContents(d).decode("utf-8")
        x = NextFunction(x)
    return s

#Returns a string which is a concatenation of all the function names in the given range
# separated by <sep>	
def CompileFuncNamesFromRangeAsText(start,end,sep):
    x = start
    s = ""
    while (x<=end):
        n = idc.get_func_name(x)
        if (not n.startswith("sub_")):
            s += " " + sep + " " + n
        x = NextFunction(x)
    return s
	
#helper function which checks for both ASCII and Unicode strings at the given ea	
def GetStrLitContents(ea):
    potential_len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C_16)
    if(potential_len > 0):
        # If we get a non zero length, this is likely our string
        return ida_bytes.get_strlit_contents(ea, potential_len, ida_nalt.STRTYPE_C_16)
    # If we didn't get a good length out of C_16, try 8 bit strings
    potential_len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
    if(potential_len > 0):
        return ida_bytes.get_strlit_contents(ea, potential_len, ida_nalt.STRTYPE_C)
    #print("Error! %lu not a string" % (ea))
    return ""
