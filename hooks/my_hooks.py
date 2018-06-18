#!/usr/bin/python

"""
Example Diaphora export hooks script. In this example script the following fake
scenario is considered:

  1) There is a something-user.i64 database, for user-land stuff.
  2) There is a something-kernel.i64 database, for kernel-land stuff.
  3) We export all functions from the something-user.i64 database.
  4) We only export from something-kernel.i64 the syscall_* or sys_* prefixed
     functions.
  5) In both databases there are constants referencing the build identifier but
     they are different for both databases: BUILD-1000 in the user-land part and
     BUILD-2000 in the kernel-land part. For making a perfect match based on the
     constants found in both databases, we change the strings BUILD-XXX to the
     generic string "BUILD-ID" for both databases.

"""

#-----------------------------------------------------------------------
FUNC_PREFIXES = ["syscall_", "sys_"]
BUILD_IDS = ["BUILD-1000", "BUILD-2000"]

#-----------------------------------------------------------------------
class CMyHooks:
  def __init__(self, diaphora_obj):
    """ @diaphora_obj is the CIDABinDiff object being used.
    """
    self.diaphora = diaphora_obj
    self.db_name = self.diaphora.db_name

  def before_export_function(self, ea, func_name):
    """ @ea is the address of the function that is going to be read.    
        Return True for the function to be read, or False to ignore it.
    """

    # If the IDB name has the word 'user' on it, it's the user-land database for
    # which we want to export everything.
    if self.db_name.find("user") > -1:
      return True

    # Otherwise, it's the kernel-land IDB for which we only want to export the
    # syscall functions.
    if func_name:
      # Is it a syscall?
      for prefix in FUNC_PREFIXES:
        if func_name.startswith(prefix):
          return True

    return False

  def after_export_function(self, d):
    """ @d is a dictionary with everything exported by Diaphora for the current
        function. Transformations can be applied to the dictionary like changing
        some strings or constants or whatever else. The function must return a
        new dictionary with the modifications.
    """
    
    # Search if any of the constants in the dictionary has the string "BUILD-*"
    # and, if so, change it in the export process to a generic "BUILD-ID" string
    # that will match more functions.
    for build_id in BUILD_IDS:
      for key in d:
        if type(d[key]) is str:
          if d[key].find(build_id) > -1:
            d[key] = d[key].replace(build_id, "GENERIC-BUILD-ID")

    return d

HOOKS = {"DiaphoraHooks": CMyHooks}
