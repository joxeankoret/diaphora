#!/usr/bin/python3

"""
The Diaphora testing suite
Copyright (c) 2015-2022, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import print_function

import os
import sys
import time
import sqlite3
import datetime
import traceback
import threading
import subprocess

from threading import Lock
from configparser import ConfigParser
from multiprocessing.pool import ThreadPool

#-------------------------------------------------------------------------------
EXPORT_QUERY = """
select 1, "Total Basic Blocks", count(*) from basic_blocks where asm_type = 'native'
union
select 2, "Total BBlocks Instructions", count(*) from bb_instructions
union
select 3, "Total BBlocks Relations", count(*) from bb_relations
union
select 4, "Total Call Graph items", count(*) from callgraph
union
select 5, "Total Constants", count(*) from constants
union
select 6, "Total Functions BBlocks", count(*) from function_bblocks
union
select 7, "Total Functions", count(*) from functions
union
select 8, "Total Instructions", count(*) from instructions where asm_type = 'native'
union
select 9, "Total Program Items", count(*) from program
union
select 10, "Total Program Data Items", count(*) from program_data
union
select 11, "Call Graph Primes", callgraph_primes from program
union
select 12, "Compilation Units", count(*) from compilation_units
union
select 13, "Named Compilation Units", count(*) from compilation_units where name != '' and name is not null
union
select 14, "Total Microcode Basic Blocks", count(*) from basic_blocks where asm_type = 'microcode'
union
select 15, "Total Microcode Instructions", count(*) from instructions where asm_type = 'microcode'
union
select 16, "Total Callers", count(*) from callgraph where type = 'caller'
union
select 17, "Total Callees", count(*) from callgraph where type = 'callee'
"""

DIFF_QUERY = """
select 1, "Best", count(*) from results where type = 'best'
union
select 2, "Partial", count(*) from results where type = 'partial'
union
select 3, "Unreliable", count(*) from results where type = 'unreliable'
union
select 4, "Multimatches", count(*) from results where type = 'multimatch'
"""

#-------------------------------------------------------------------------------
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

#-------------------------------------------------------------------------------
def debug(msg):
  if os.getenv("TESTER_DEBUG") is not None:
    log(msg)

#-------------------------------------------------------------------------------
def log(msg):
  print(f"[{time.asctime()} {threading.get_ident()}] {msg}")
  sys.stdout.flush()

#-----------------------------------------------------------------------
def thread_manager(total_threads, target, args):
  """ Run a total of @total_threads running @target """
  
  pool = ThreadPool(processes=int(total_threads))
  pool.map(target, args)

#-------------------------------------------------------------------------------
class CDiaphoraBaseChecker:
  def __init__(self, db_path, section, sql):
    self.section = section
    self.db_path = db_path
    self.sql_query = sql
    self.db = sqlite3.connect(db_path)
    self.db.text_factory = str

  def check(self, cfg_file):
    ret = True
    try:
      d = dict(cfg_file[self.section])
    except:
      print(f"Error reading section '{self.section}': {str(sys.exc_info()[1])}")
      d = {}

    cur = self.db.cursor()
    try:
      cur.execute(self.sql_query)
      rows = list(cur.fetchall())
      total = 0
      for row in rows:
        key = row[1].lower()
        value = row[2]
        if key not in d:
          log(f"ERROR: Key {repr(key)} not in testcase!")
          ret = False
        else:
          total += float(value)
          if d[key] != str(value):
            log(f"WARNING: Value for {repr(key)} differ ({d[key]} -> {value})")
            ret = None

      if total == 0:
        log("ERROR: All values are 0!")
        ret = False

      if ret is False or ret is None:
        testcase = cfg_file["Testcase"]["filename"]
        print(f"Current {self.section} data ({testcase})")
        print("-"*(13 + len(self.section)))
        print(f"[{self.section}]")
        for row in rows:
          key = row[1].lower()
          value = row[2]
          print(f"{key}={value}")
        print("-"*(13 + len(self.section)) + "\n")
    finally:
      cur.close()

    return ret

#-------------------------------------------------------------------------------
class CDiaphoraExportChecker(CDiaphoraBaseChecker):
  def __init__(self, db_path):
    CDiaphoraBaseChecker.__init__(self, db_path, "Export", EXPORT_QUERY)

#-------------------------------------------------------------------------------
class CDiaphoraDiffChecker(CDiaphoraBaseChecker):
  def __init__(self, db_path):
    CDiaphoraBaseChecker.__init__(self, db_path, "Diff", DIFF_QUERY)

#-------------------------------------------------------------------------------
class CDiaphoraTester:
  def __init__(self, cfg_file):
    self.slow = False
    self.cfg_file = cfg_file
    self.read_configuration()
    self.reset()
    self.lock = Lock()

  def reset(self):
    self.total = 0
    self.errors = 0
    self.warnings = 0

  def read_configuration(self):
    self.cfg = ConfigParser()
    self.cfg.read(self.cfg_file)

    self.directory = self.cfg["General"]["samples-directory"]
    self.diaphora_script = self.cfg["General"]["diaphora-script"]
    self.slow = False

    self.ida_path = self.cfg["IDA"]["path"]
    self.python = self.cfg["Python"]["path"]

    self.cpus = 1
    if "cpus" in self.cfg["General"]:
      self.cpus = int(self.cfg["General"]["cpus"])

  def check_export(self, sample_cfg, db_file):
    checker = CDiaphoraExportChecker(db_file)
    return checker.check(sample_cfg)

  def launch_export(self, sample_cfg, filename):
    testcase = sample_cfg["Testcase"]["filename"]
    testcase_dir = self.directory
    testcase = os.path.join(testcase_dir, testcase)

    log_file = filename.replace(".cfg", ".log")
    db_file = sample_cfg["Testcase"]["export"]
    db_file = os.path.join(testcase_dir, db_file)
    db_file = os.path.abspath(db_file)
    ida_binary = sample_cfg["Testcase"]["ida-binary"]

    if os.path.exists(db_file):
      debug(f"Removing previous SQLite file {db_file}...")
      os.remove(db_file)
      #os.sync()
    
    if os.path.exists(log_file):
      debug(f"Removing previous log file {log_file}...")
      os.remove(log_file)

    os.putenv("DIAPHORA_CPU_COUNT", "1")
    os.putenv("DIAPHORA_AUTO", "1")
    os.putenv("DIAPHORA_LOG_PRINT", "1")
    os.putenv("DIAPHORA_EXPORT_FILE", db_file)
    if sample_cfg["Testcase"]["decompiler"] == "1":
      os.putenv("DIAPHORA_USE_DECOMPILER", "1")

    os.putenv("PYTHONWARNINGS", "ignore")
    cmd = "%s/%s -A -B -S%s -L%s %s"
    cmd = cmd % (self.ida_path, ida_binary, \
                 self.diaphora_script, log_file, testcase)
    debug(f"Launching '{cmd}'\n")
    ret = subprocess.call(cmd, shell=True)
    if ret != 0:
      log(f"Error exporting test-case {testcase}, return code {ret}!")
      return False

    return self.check_export(sample_cfg, db_file)

  def launch_diff(self, sample_cfg, filename):
    diff = sample_cfg["Diff"]
    db1 = sample_cfg["Testcase"]["export"]
    db2 = diff["against"]
    output = diff["output"]
    log_file = filename.replace(".cfg", ".log")

    db1 = os.path.join(self.directory, db1)
    db2 = os.path.join(self.directory, db2)
    output = os.path.join(self.directory, output)

    slow = True
    if "slow" in sample_cfg["Testcase"]:
      if sample_cfg["Testcase"]["slow"] == "0":
        slow = False

    if slow:
      os.putenv("DIAPHORA_SLOW_HEURISTICS", "1")

    os.putenv("DIAPHORA_LOG_PRINT", "1")
    os.putenv("PYTHONWARNINGS", "ignore")

    cmd = "%s %s %s %s -o %s >> %s"
    cmd %= (self.python, self.diaphora_script, db1, db2, output, log_file)
    debug(f"Launching command {cmd}")
    ret = subprocess.call(cmd, shell=True)
    if ret != 0:
      log(f"First run failed with exit code {ret}, launching testcase again...")
      # For a reason beyond me, the very first test case might fail :shrug:
      ret = subprocess.call(cmd, shell=True)
      if ret != 0:
        log(f"Error: Diffing returned exit code {ret} for {filename}!")
        return False
    return self.check_diff(sample_cfg, output)

  def check_diff(self, sample_cfg, db_file):
    checker = CDiaphoraDiffChecker(db_file)
    return checker.check(sample_cfg)

  def skip_slow_test(self, sample_cfg):
    if not self.slow:
      if "slow" in sample_cfg["Testcase"]:
        if int(sample_cfg["Testcase"]["slow"]) == 1:
          return True
    return False

  def do_launch_test(self, args):
    """
    NOTE: This function used to have good names for arguments instead of having
    a list holding the arguments, but ThreadPool() doesn't support that... for a
    reason.
    """
    step, sample_cfg, testcase_filename = args
    ret = -1
    try:
      if step == "export" and "Export" in sample_cfg.sections():
        log(f"Launching probe '{step}' for test {testcase_filename} ...")
        ret = self.launch_export(sample_cfg, testcase_filename)
      elif step == "diff" and "Diff" in sample_cfg.sections():
        log(f"Launching probe '{step}' for test {testcase_filename} ...")
        ret = self.launch_diff(sample_cfg, testcase_filename)
    except:
      log(f"Error running test {testcase_filename}")
      print(sys.exc_info()[1])
      traceback.print_exc()
      ret = False

    with self.lock:
      if ret is None:
        self.warnings += 1
        log(f"Total of {self.warnings} test cases causing warnings so far")
      elif not ret:
        self.errors += 1
        log(f"Total of {self.errors} test cases causing errors so far")

    log(f"Probe '{testcase_filename}' completed")

  def test(self, filename, step):
    self.reset()

    test_cases = []
    if filename is not None:
      base_filename = os.path.basename(filename)

    for f in os.listdir(self.directory):
      if not f.endswith(".cfg"):
        continue

      base_f = os.path.basename(f)
      if filename is not None and base_f != base_filename:
        continue

      self.total += 1

      testcase_filename = os.path.join(self.directory, f)
      sample_cfg = ConfigParser()
      sample_cfg.read(testcase_filename)
      if self.skip_slow_test(sample_cfg):
        log(f"Skipping slow test-case {testcase_filename}...")
        continue

      test_cases.append([step, sample_cfg, testcase_filename])

    thread_manager(self.cpus, self.do_launch_test, args=test_cases)
    return self.errors

#-------------------------------------------------------------------------------
def launch_tests(do_export=True, do_diff=True, slow=False):
  t = time.time()
  cfg_file = "tester.cfg"
  tester_cfg = os.getenv("DIAPHORA_TESTER_CFG")
  if tester_cfg is not None:
    cfg_file = tester_cfg

  tester = CDiaphoraTester(cfg_file)
  tester.slow = slow
  if do_export:
    ret = tester.test(None, step="export")
  if do_diff:
    ret = tester.test(None, step="diff")
  msg = "Total test-case(s) executed %d. Total of %d error(s) and %d warning(s)."
  log(msg % (tester.total, tester.errors, tester.warnings))

  final_time = time.time() - t
  log(f"Done in {datetime.timedelta(seconds=final_time)}")
  sys.exit(ret)

#-------------------------------------------------------------------------------
def main():
  cfg_file = "tester.cfg"
  tester_cfg = os.getenv("DIAPHORA_TESTER_CFG")
  if tester_cfg is not None:
    cfg_file = tester_cfg

  tester = CDiaphoraTester(cfg_file)
  steps = ["export", "diff"]
  for arg in sys.argv[1:]:
    if arg in ["-e", "--export", "-el", "--export-all"]:
      steps = ["export"]
      if arg.endswith("l"):
        launch_tests(do_export=True, do_diff=False, slow=tester.slow)
    elif arg in ["-d", "--diff", "-dl", "--diff-all"]:
      steps = ["diff"]
      if arg.endswith("l"):
        launch_tests(do_export=False, do_diff=True, slow=tester.slow)
    elif arg in ["-a", "--all"]:
      steps = ["export", "diff"]
    elif arg in ["-s", "--slow"]:
      tester.slow = True
    else:
      t = time.time()

      for step in steps:
        tester.test(arg, step)

      final_time = time.time() - t
      log(f"Done in {datetime.timedelta(seconds=final_time)}")

if __name__ == "__main__":
  if len(sys.argv) == 1:
    launch_tests()
  else:
    main()
