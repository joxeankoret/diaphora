#!/usr/bin/python

"""
Skeleton script to write project specific rules for Diaphora.
Created by Joxean Koret.

Public domain
"""

#-------------------------------------------------------------------------------
class CExampleDiaphoraHooks:
  def __init__(self, diaphora_obj):
    """ @diaphora_obj is the CIDABinDiff object being used.
    """
    self.diaphora = diaphora_obj
    self.db_name = self.diaphora.db_name

  def before_export_function(self, ea, func_name):
    """ @ea is the address of the function that is going to be read.    
        Return True for the function to be read, or False to ignore it.
    """
    return True

  def after_export_function(self, d):
    """ @d is a dictionary with everything exported by Diaphora for the current
        function. Transformations can be applied to the dictionary like changing
        some strings or constants or whatever else. The function must return a
        new dictionary with the modifications.
    """
    return d

  def get_heuristics(self, category, heuristics):
    """ @category is the category for which heuristics are going to be executed
        by Diaphora. @heuristics is the list of heuristics that are going to be
        executed, the generic heuristics based on SQL queries specified in the
        'diaphora_heuristics.py' source file.
        
        It's possible to modify, remove or add new heuristics depending on
        whatever is required for a diffing project. The function must return the
        heuristics that the user wants to run for the specific category.
    """
    #print("CExampleDiaphoraHooks.get_heuristics")
    return heuristics

  def on_launch_heuristic(self, name, sql):
    """ @name is the heuristic to be run and @sql is the SQL query that is going
        to be executed to find matches. Modify the @sql query to, for example,
        add some new statements to the 'where' clause. The function must return
        a SQL query or None if it should be skipped.

        The method is executed before running the specified heuristic.
    """
    #print("CExampleDiaphoraHooks.on_launch_heuristic", name)
    return sql

  def get_queries_postfix(self, category, postfix):
    """ @category is the type of heuristics that are being launched, which can
        be 'Best', 'Partial', 'Unreliable' or 'Experimental'. @postfix is some
        SQL code to specify filters in the where statement.
        
        The function must return a valid string with the filters to append to
        the where statement.
    """
    print("CExampleDiaphoraHooks.get_queries_postfix", category, postfix)
    return postfix

  def on_match(self, func1, func2, description, ratio):
    """ @func1 and @func2 are dictionaries with data relative to the functions
        that are matched for, respectively, the current databse and the database
        that is being diffed against. @description is the heuristic description
        and @ratio is the calculated similarity ratio, between 0.0 and 1.0.
        
        The function must return 2 elements: if the match is accepted and the
        ratio for it. Some examples:
        
          - return False,  0    # The match will be ignored
          - return True, 1.0    # The match will have a 1.0 score ratio

        The Python dict objects @func1 and @func2 will contain the following
        elements:
        
          - "ea": The address of the function.
          - "bb": The number of basic blocks.
          - "name": The name of the function.
          - "ast": Pseudo-code primes based on the Abstract Syntax Tree (AST).
          - "md": The MD-Index calculated for the function's Control Flow Graph.
          - "pseudo": The pseudo-code's textual representation.
          - "asm": The assembler's textual representation.

    """
    #print("CExampleDiaphoraHooks.on_match", description, ratio, func1["name"], func2["name"])
    name1 = func1["name"]
    name2 = func2["name"]
    if name1 != name2 and not name1.startswith("sub_") and not name2.startswith("sub_"):
      if name1.find(name2) == -1 and name2.find(name1) == -1:
        print("on_match(): False positive found %s -> %s, discarded..." % (name1, name2))
        return False, 0

    return True, ratio

HOOKS = {"DiaphoraHooks": CExampleDiaphoraHooks}
