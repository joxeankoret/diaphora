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

IDA_VERSION = 7

if (IDA_VERSION < 7):	
	import idc
	import struct
	import idautils
	import basicutils_6x as basicutils
else:
	import ida_idaapi
	import ida_idc
	import ida_funcs
	import ida_nalt
	import ida_segment
	import idautils
	import basicutils_7x as basicutils

import math
import nltk
import nltk.collocations
import re


### NLP Section ###

# This section of code attempts to name the modules based on common strings in the string references
# Not really based on any sound science or anything - your mileage may heavily vary. :-D

#string_range_tokenize(start,end,sep):
#Compile all string references between start and end as a list of strings (called "tokens")
# <sep> should be a nonsense word, and will show up in the list
def string_range_tokenize(start,end,sep):
	# get all string references in this range concatenated into a single string
	t = basicutils.CompileTextFromRange(start,end,sep)
	
	#Enable this if you already have a bunch of function names and want to include that in the mix
	#t+= basicutils.CompileFuncNamesFromRangeAsText(start,end,sep)
	
	#print "string_range_tokenize: raw text:"
	#print t
	#remove printf/sprintf format strings
	tc = re.sub("%[0-9A-Za-z]+"," ",t)
	#convert dash to underscore
	tc = re.sub("-","_",tc)
	#replace _ and / with space - may want to turn this off sometimes
	#this will break up snake case and paths
	#problem is that if you have a path that is used throughout the binary it will probably dominate results
	tc = re.sub("_"," ",tc)
	#replace / and \\ with a space
	tc = re.sub("[/\\\\]"," ",tc)
	#remove anything except alphanumeric, spaces, . (for .c, .cpp, etc) and _
	tc = re.sub("[^A-Za-z0-9_\.\s]"," ",tc)
	
	#lowercase it - and store this as the original set of tokens to work with
	tokens = [tk.lower() for tk in tc.split()]
	
	#remove English stop words
	#this is the list from the MIT *bow project
	eng_stopw = {"about","all","am","an","and","are","as","at","be","been","but","by","can","cannot","did","do","does","doing","done","for","from","had","has","have","having","if","in","is","it","its","of","on","that","the","these","they","this","those","to","too","want","wants","was","what","which","will","with","would"}
	#remove "code" stop words
	#e.g. common words in debugging strings
	code_sw = {"error","err","errlog","log","return","returned","byte","bytes","status","len","length","size","ok","0x","warning","fail","failed","failure","invalid","illegal","param","parameter","done","complete","assert","assertion","cant","didnt","class","foundation","cdecl","stdcall","thiscall"}
	stopw = eng_stopw.union(code_sw)
	c = 0
	
	tokens_f = []
	
	for t in tokens:
		if t not in stopw:
			tokens_f.append(t)
			
	return tokens_f

#bracket_strings(start,end,b_brack,e_brack):
#Return the most common string in the range <star,end> that begins with b_brack and ends with e_brack
#  The count of how many times this string appeared is also returned
#I find somewhat often people format debug strings like "[MOD_NAME] Function X did Y!"
#This function is called by guess_module_names() - if you see this format with different brackets
#you can edit that call
def bracket_strings(start,end,b_brack,e_brack):
	sep = "tzvlw"
	t = basicutils.CompileTextFromRange(start,end,sep)
	tokens = [tk.lower() for tk in t.split(sep)]
	
	b=[]
	for tk in tokens:
		tk = tk.strip()
		
		if tk.startswith(b_brack) :
			b_contents = tk[1:tk.find(e_brack)]
			#Hack to get rid of [-],[+],[*] - could also try to remove non alpha
			if (len(b_contents) > 3):
				#Hack for debug prints that started with [0x%x]
				if (b_contents != "0x%x"):
					b.append(tk[1:tk.find(e_brack)])
			
	print("bracket_strings tokens:")
	print(tokens)
	print(b)
	
	u_gram=""
	u_gram_score=0
	if (len(b) > 0):
		f = nltk.FreqDist(b)
		u_gram = f.most_common(1)[0][0]
		u_gram_score = f.most_common(1)[0][1]
		
	return (u_gram,u_gram_score)

#source_file_strings(start,end):
#Return the most common string that looks like a source file name in the given range
#  The count of how many times this string appeared is also returned
def source_file_strings(start,end):
	sep = "tzvlw"
	t = basicutils.CompileTextFromRange(start,end,sep)
	#normally would do lower here to normalize but we lose camel case that way
	tokens = [tk for tk in t.split(sep)]
	
	#for each string, remove quotes and commas, then tokenize based on spaces to generate the final list
	tokens2=[]
	for tk in tokens:
		tk = tk.strip()
		#strip punctuation, need to leave in _ for filenames and / and \ for paths 
		tk = re.sub("[\"\'\,]"," ",tk)
		for tk2 in tk.split(" "):
			tokens2.append(tk2)
	
	b=[]
	for tk in tokens2:
		tk = tk.strip()
		if tk.endswith(".c") or tk.endswith(".cpp") or tk.endswith(".cc"):
			#If there's a dir path, only use the end filename
			#This could be tweaked if the directory structure is part of the software architecture
			#e.g. if there are multiple source directories with meaningful names
			if tk.rfind("/") != -1:
				ntk = tk[tk.rfind("/")+1:]
			elif tk.rfind("\\") != -1:
				ntk = tk[tk.rfind("\\")+1:]
			else:
				ntk = tk
			b.append(ntk)
			
	print("source_file_strings tokens:")
	#print tokens
	print(b)
	
	#a better way to do this (if there are multiple)
	#would be to sort, uniquify, and then make the name foo.c_and_bar.c
	u_gram=""
	u_gram_score=0
	if (len(b) > 0):
		f = nltk.FreqDist(b)
		u_gram = f.most_common(1)[0][0]
		u_gram_score = f.most_common(1)[0][1]
		
	return (u_gram,u_gram_score)
	
#common_strings(start,end):
#Return a list of the common strings in the given range	
#Uses NLTK to generate a list of unigrams, bigrams, and trigrams (1 word, 2 word phrase, 3 word phrase)
#If the trigram score > 1/2 * bigram score, the most common trigram is used
#If the bigram score > 1/2 * unigram score, the most common bigram is used
#Otherwise the most common unigram (single word is used)
def common_strings(start,end):
	CS_THRESHOLD = 6
	sep = "tvlwz"
	
	tokens = string_range_tokenize(start,end,sep)
	
	#make a copy since we're going to edit it
	u_tokens = tokens
	c=0
	while (c<len(u_tokens)):
		if u_tokens[c] == sep:
			del u_tokens[c]
		else:
			c+=1
	
	print("common_strings tokens:")
	print(tokens)
	
	if len(u_tokens) < CS_THRESHOLD:
		#print "%08x - %08x : %s" % (start,end,"no string")
		return ("",0)	
	
	f = nltk.FreqDist(u_tokens)
	u_gram = f.most_common(1)[0][0]
	u_gram_score = f.most_common(1)[0][1]
	
	#print "Tokens:"
	#print tokens
	#print len(tokens)
	
	bgs = list(nltk.bigrams(tokens))
	c=0
	while (c<len(bgs)):
		if sep in bgs[c]:
			del bgs[c]
		else:
			c+=1
	
	#print "Bigrams:"
	#print bgs
	if (len(bgs) != 0):
		fs = nltk.FreqDist(bgs)
		b_gram = fs.most_common(1)[0][0]
		#print "Most Common:"
		#print b_gram
		b_str = b_gram[0] + "_" + b_gram[1]
		b_gram_score = fs.most_common(1)[0][1]
	else:
		b_str =""
		b_gram_score = 0
		
	tgs = list(nltk.trigrams(tokens))
	c=0
	while (c<len(tgs)):
		if sep in tgs[c]:
			del tgs[c]
		else:
			c+=1
	#print "Trigrams:"
	#print tgs
	if (len(tgs) != 0):
		ft = nltk.FreqDist(tgs)
		t_gram = ft.most_common(1)[0][0]
		t_str = t_gram[0] + "_" + t_gram[1] + "_" + t_gram[2]
		t_gram_score = ft.most_common(1)[0][1]
	else:
		t_str = ""
		t_gram_score = 0
		
	
	#print "1: %s - %d 2: %s - %d 3: %s - %d\n" % (u_gram,u_gram_score,b_str,b_gram_score,t_str,t_gram_score)
	
	if (b_gram_score * 2 >= u_gram_score):
		if (t_gram_score * 2 >= b_gram_score):
			ret = t_str
			ret_s = t_gram_score
		else:
			ret = b_str
			ret_s = b_gram_score
	else:
		ret = u_gram
		ret_s = u_gram_score
	
	#print "%08x - %08x : %s" % (start,end,ret)
	
	return (ret,ret_s)

### End of NLP Section ###	



#guess_module_names():
#Use the NLP section (above) to guess the names of modules and add them to the global module list
#Attempts to find common bracket strings (e.g. "[MOD_NAME] Debug print!")
#then source file names (most often left over from calls to assert())
#then common trigram/bigram/unigrams
#You can tweak the switchover thresholds below.
def guess_module_names(module_list):
	#idea - make score threshold based on the size of the module
	# (e.g. smaller modules should have a smaller threshold
	C_SCORE_THRESHOLD = 3
	S_SCORE_THRESHOLD = 1
	B_SCORE_THRESHOLD = 1
	c=0
	unk_mod=0
	while (c<len(module_list)):
		m = module_list[c]
		# first look for strings that start with [FOO], (bracket strings)
		# then look for strings that contain source files (.c,.cpp,etc.)
		# then try common strings
		# above thresholds can be tweaked - they represent the number of strings that have to be repeated
		# in order to use that string as the module name
		(name,scr) = bracket_strings(m.start,m.end,"[","]")
		if (scr < B_SCORE_THRESHOLD):
			(name,scr) = source_file_strings(m.start,m.end)
			if (scr < S_SCORE_THRESHOLD):
				(name,scr) = common_strings(m.start,m.end)
				if (scr < C_SCORE_THRESHOLD):
					#Couldn't come up with a name so name it umod1, umod2, etc.
					name = "umod%d" % (unk_mod)
					#"word cloud" or something to get an idea of what the module is
					#print basicutils.CompileTextFromRange(m.start,m.end," ")
					unk_mod+=1
		module_list[c].name = name
		module_list[c].score = scr
		print("%08x - %08x : %s (%d)" % (m.start,m.end,name,scr))
		c+=1
		
	return module_list
