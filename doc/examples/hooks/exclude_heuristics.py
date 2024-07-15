#!/usr/bin/python

"""
Script to exclude specific heuristics
Created by Joxean Koret

Public domain
"""

#-------------------------------------------------------------------------------
EXCLUDE_HEURISTICS = ["pseudo-code fuzzy ast hash"]

#-------------------------------------------------------------------------------
class CExcludeHeuristicHooks:
  def __init__(self, diaphora_obj):
    self.diaphora = diaphora_obj

  def get_heuristics(self, category, heuristics):
    """
    Build a new list with the SQL based heuristics that we want Diaphora to use.
    """
    new_heurs = []
    for heur in heuristics:
      name = heur["name"]
      if name.lower() not in EXCLUDE_HEURISTICS:
        new_heurs.append(heur)
      else:
        self.diaphora.log(f"Note: Heuristic {name} excluded")
    return new_heurs

  def on_special_heuristic(self, heuristic, iteration):
    """
    We need to use this event too because some special heuristics not based on
    SQL queries are handled differently. Basically, we just check the @heuristic
    and return True/False if it's allowed or not.
    """
    if heuristic.lower() in EXCLUDE_HEURISTICS:
      self.diaphora.log(f"Note: Special heuristic {heuristic} disabled")
      return False
    return True

HOOKS = {"DiaphoraHooks": CExcludeHeuristicHooks}

