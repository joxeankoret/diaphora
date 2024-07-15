#!/usr/bin/python

"""
Example Diaphora export hooks script for debugging problems.
Joxean Koret, admin@joxeankoret.com

Public Domain
"""

#-----------------------------------------------------------------------
class CDebuggingHelper:
  def __init__(self, diaphora_obj):
    """ @diaphora_obj is the object with all the Diaphora APIs.
    """
    self.diaphora = diaphora_obj

    self.last_ea = None
    self.last_name = None

  def before_export_function(self, ea, func_name):
    """ @ea is the address of the function that is going to be read.    
        Return True for the function to be read, or False to ignore it.
    """
    self.last_ea = ea
    self.last_name = func_name
    print("Exporting function 0x%08x: %s" % (ea, func_name))
    return True

  def on_export_crash(self):
    """ @ea is the address of the function where Diaphora crashed exporting it.
        Return True to crash the export process, or False to ignore this error.
    """
    if self.last_ea is None:
      print("Diaphora crashed before exporting a single function!!!")
    else:
      print("Export crashed at function 0x%08x: %s" % (self.last_ea, self.last_name))
    return True

  def after_export_function(self, d):
    """ @d is a dictionary with everything that Diaphora exports for the current
        function. You can freely modify values here or simply inspect to verify
        it didn't do something wrong here or there.
        
        Check 'create_function_dictionary()' in diaphora_ida.py to get the full
        list of fields in the dictionary @d.
    """
    return d

HOOKS = {"DiaphoraHooks": CDebuggingHelper}
