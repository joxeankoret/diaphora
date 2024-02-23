#!/usr/bin/python3

"""
Script to find patches that could be fixing vulnerabilities by simply doing
pattern matching between pseudo-codes for partial matches.

Joxean Koret
Public domain
"""

from difflib import unified_diff

from diaphora import CChooser, log

#-------------------------------------------------------------------------------
# pylint: disable=unused-argument
# pylint: disable=missing-function-docstring

#-------------------------------------------------------------------------------
PATTERNS = [
  # Generic C 'unsafe' functions
  "cpy", "printf", "strcat", "strncat", "gets", "mem", "system",
  "scanf", "alloc", "free", "strto",
  # Windows 'unsafe' APIs
  "ShellExecute", "WinExec", "LoadLibrary", "CreateProcess",
  # Functions that may be interesting for Windows kernel drivers
  "ProbeForWrite", "ProbeForRead",
  # UNC paths related pattern
  "UNC"
]

COMPARISONS = [" < ", " > ", " <= ", " >= "]

#-------------------------------------------------------------------------------
class CVulnSearchResults:
  """
  Results from a heuristic to find vulnerabilities
  """
  def __init__(self):
    self.found = False
    self.description = None
    self.line = None

#-------------------------------------------------------------------------------
SIGNED_UNSIGNED_LIST = {}
SIGNED_UNSIGNED_LIST["jl"] = "jb"
SIGNED_UNSIGNED_LIST["jle"] = "jbe"
SIGNED_UNSIGNED_LIST["jg"] = "ja"
SIGNED_UNSIGNED_LIST["jge"] = "jae"

_key = None
for _key in list(SIGNED_UNSIGNED_LIST.keys()):
  value = SIGNED_UNSIGNED_LIST[_key]
  SIGNED_UNSIGNED_LIST[value] = _key
del _key

#-------------------------------------------------------------------------------
class CVulnerabilityPatches:
  """
  Class used to find potentially fixed vulnerabilities by searching for patterns.
  """
  def __init__(self, diaphora_obj):
    """ @diaphora_obj is the CIDABinDiff object being used.
    """
    self.diaphora = diaphora_obj
    self.db_name = self.diaphora.db_name

    self.results = []
    self.dones = set()

    # This is the chooser we're going to create
    self.chooser = self.diaphora.chooser("Interesting matches", self.diaphora)
    self.diaphora.interesting_matches = self.chooser

  def before_export_function(self, ea, func_name):
    return True

  def after_export_function(self, d):
    return d

  def get_heuristics(self, category, heuristics):
    return heuristics

  def on_launch_heuristic(self, name, sql):
    return sql

  def get_queries_postfix(self, category, postfix):
    return postfix

  def on_finish(self):
    # If we found some cool match, show this chooser
    if len(self.chooser.items) > 0:
      self.chooser.show(force=True)

  def search_pseudo_patterns(self, src_line):
    """
    Find potential vulnerabilities by simply doing pattern matching
    """
    ret = CVulnSearchResults()
    # Search all of our function calls patterns
    for pattern in PATTERNS:
      if src_line.find(pattern) > -1:
        pattern = f'Pattern {repr(pattern)}'
        ret.found = True
        ret.description = pattern
        ret.line = src_line
        break

    return ret

  def search_for_added_size_check(self, src_line):
    """
    Try to guess if it looks like a newly added size check
    """
    ret = CVulnSearchResults()
    if src_line.startswith("if "):
      for pattern in COMPARISONS:
        if src_line.find(pattern) > -1:
          # Ignore comparisons with 0?
          if src_line.find(f"{pattern}0 ") == -1:
            ret.description = 'Potential size check added'
            ret.found = True
            ret.line = src_line
            break
    return ret

  def find_vulns_using_assembly(self, func1, func2, ratio):
    """
    Try to search for signedness fixed issues
    """
    results = CVulnSearchResults()

    # Get the assembly for both and do a typical 'diff' of both
    asm1 = func1["asm"]
    asm2 = func2["asm"]
    if asm1 is None or asm2 is None:
      return results

    lines = unified_diff(asm1.split("\n"), asm2.split("\n"))
    lines = list(lines)
    added = None
    removed = None
    found = False

    for line in lines:
      c = line[0]
      # Only consider removed/added lines (which also means modified lines)
      if c in ["-", "+"]:
        if c == "+":
          added = line[1:]
        elif c == "-":
          if line[1:].endswith(":"):
            continue
          removed = line[1:]

        if added is not None and removed is not None:
          # Check the list of known signed <-> unsigned instructions
          mnem1 = added.split(" ")[0].lower()
          mnem2 = removed.split(" ")[0].lower()
          if mnem1 in SIGNED_UNSIGNED_LIST:
            if SIGNED_UNSIGNED_LIST[mnem1] == mnem2:
              found = True
              break
          elif mnem1[0] == "b" and mnem2[0] == "b":
            # Check for branch instructions where only one is signed
            last_c1 = mnem1[len(mnem1)-1]
            last_c2 = mnem2[len(mnem2)-1]
            if (last_c1 == "s" or last_c2 == "s") and last_c1 != last_c2:
              found = True
              break

    if found:
      results.description = "Signed/Unsigned check changed"
      results.found = True
      results.line = f"Added: {repr(added)}\tRemoved: {repr(removed)}"

    return results

  def find_vulns_using_pseudocode(self, func1, func2, ratio):
    results = CVulnSearchResults()

    # Get the decompiled code for both and do a typical 'diff' of both
    pseudo1 = func1["pseudo"]
    pseudo2 = func2["pseudo"]
    if pseudo1 is None or pseudo2 is None:
      return results

    lines = unified_diff(pseudo1.split("\n"), pseudo2.split("\n"))
    for line in lines:
      c = line[0]
      # Only consider removed/added lines (which also means modified lines)
      if c in ["-", "+"]:
        src_line = line[2:].strip(" ")

        results = self.search_pseudo_patterns(src_line)
        if not results.found:
          # Search for potentially newly added checks
          if c == "+":
            results = self.search_for_added_size_check(src_line)

      if results.found:
        break

    return results

  def on_match(self, func1, func2, description, ratio):
    # Ignore matches with ratio 1.0, as they contain no changes
    if ratio < 1.0:
      name1 = func1["name"]
      name2 = func2["name"]
      
      # We might receive 2 times a match in some cases, avoid analysing it twice
      key = str([name1, name2])
      if key in self.dones:
        return True, ratio
      self.dones.add(key)

      results = self.find_vulns_using_assembly(func1, func2, ratio)
      if not results.found:
        results = self.find_vulns_using_pseudocode(func1, func2, ratio)

      # We found something that might be cool, save this function and stop
      # finding more stuff for this function.
      if results.found:
        # Report matches while it's still finding for exciting reversers
        msg = f"Potentially interesting patch found (pattern {repr(results.description)}): {name1} - {name2}"
        self.diaphora.log_refresh(msg)
        log(f"> {results.line}")

        # And finally add the item in the chooser we created
        ea1 = func1["ea"]
        ea2 = func2["ea"]
        bb1 = func1["nodes"]
        bb2 = func2["nodes"]
        item = CChooser.Item(ea1, name1, ea2, name2, results.description, ratio, bb1, bb2)
        self.chooser.add_item(item)

    return True, ratio

HOOKS = {"DiaphoraHooks": CVulnerabilityPatches}
CATEGORY = "PatchDiff"
