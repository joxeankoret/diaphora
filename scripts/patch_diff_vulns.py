#!/usr/bin/python3

"""
Script to find patches that could be fixing vulnerabilities by simply doing
pattern matching between pseudo-codes for partial matches.

Joxean Koret
Public domain
"""

from difflib import ndiff

from diaphora import CChooser, log

#-------------------------------------------------------------------------------
# pylint: disable=unused-argument
# pylint: disable=missing-function-docstring

#-------------------------------------------------------------------------------
PATTERNS = ["memcpy", "strcpy", "strcat", "printf"]
COMPARISONS = [" < ", " > ", " <= ", " >= "]

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

      # Get the decompiled code for both and do a typical 'diff' of both
      pseudo1 = func1["pseudo"]
      pseudo2 = func2["pseudo"]
      lines = ndiff(pseudo1.split("\n"), pseudo2.split("\n"))
      bcontinue = True
      for line in lines:
        if not bcontinue:
          break

        c = line[0]
        # Only consider removed/added lines (which also means modified lines)
        if c in ["-", "+"]:
          src_line = line[2:].strip(" ")

          # Search all of our function calls patterns
          for pattern in PATTERNS:
            if src_line.find(pattern) > -1:
              pattern = f'Pattern {pattern}'
              bcontinue = False
              break

          # Search for potentially newly added checks
          if c == "+":
            if src_line.startswith("if "):
              for pattern in COMPARISONS:
                if src_line.find(pattern) > -1:
                  # Ignore comparisons with 0?
                  if src_line.find(f"{pattern}0 ") == -1:
                    pattern = 'Potential size check added'
                    bcontinue = False
                    break

          # We found something that might be cool, save this function and stop
          # finding more stuff for this function.
          if not bcontinue:
            # Report matches while it's still finding for exciting reversers
            msg = f"Potentially interesting patch found (pattern {repr(pattern)}): {name1} - {name2}"
            log(msg)
            log(f"> {line}")

            # And finally add the item in the chooser we created
            ea1 = func1["ea"]
            ea2 = func2["ea"]
            bb1 = func1["bb"]
            bb2 = func2["bb"]
            item = CChooser.Item(ea1, name1, ea2, name2, pattern, ratio, bb1, bb2)
            self.chooser.add_item(item)
            break

    return True, ratio

HOOKS = {"DiaphoraHooks": CVulnerabilityPatches}
CATEGORY = "PatchDiff"
