#!/usr/bin/python

__all__ = ["get_model_comparison_data", "ML_AVAILABLE"]

import json

from collections import OrderedDict

try:
  from cdifflib import CSequenceMatcher as SequenceMatcher # type: ignore
except ImportError:
  from difflib import SequenceMatcher

import diaphora_config as config

try:
  import joblib
  import sklearn
  import pandas as pd

  ML_AVAILABLE = True
except ImportError:
  class pd:
    DataFrame = None

  if config.SHOW_IMPORT_WARNINGS:
    print("WARNING: sklearn, numpy and joblib python libraries are required to use ML models.")
    print("INFO: Alternatively, you can silence this warning by changing the value of SHOW_IMPORT_WARNINGS in diaphora_config.py.")
  ML_AVAILABLE = False

#-------------------------------------------------------------------------------
INVALID_SCORE = -1
INVALID_VALUE = -2

DATA_FRAME_FIELDS = [
  'cpu', 'arch', 'ratio', 'nodes', 'min_nodes', 'max_nodes', 'edges',
  'min_edges', 'max_edges', 'pseudocode_primes', 'strongly_connected',
  'min_strongly_connected', 'max_strongly_connected', 'strongly_connected_spp',
  'loops', 'min_loops', 'max_loops', 'constants', 'source_file'
]

FIELDS = ["nodes", "edges", "indegree", "outdegree", "cc",
  "primes_value", "clean_pseudo", "pseudocode_primes", "strongly_connected",
  "strongly_connected_spp", "loops", "constants", "source_file"
]

NUM_FIELDS = ["nodes", "edges", "indegree", "outdegree", "cc",
  "strongly_connected", "loops"
]

#-------------------------------------------------------------------------------
class COutputRow:
  def __init__(self):
    self.good = 0
    self.name = None
    self.values = OrderedDict()
  
  def __str__(self):
    return f"Good {self.good} Name {self.name} Values {self.values}"

  def __repr__(self):
    return self.__str__()

#-------------------------------------------------------------------------------
def int_compare_ratio(value1 : int, value2 : int) -> float:
  """
  Get a similarity ratio for two integers.
  """
  if value1 + value2 == 0:
    val = 1.0
  else:
    val = 1 - ( abs(value1 - value2) / max(value1, value2) )
  return val

#-------------------------------------------------------------------------------
def quick_ratio(buf1 : str, buf2 : str) -> float:
  """
  Call SequenceMatcher.quick_ratio() to get a comparison ratio.
  """
  if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
    return 0

  if buf1 == buf2:
    return 1.0

  s1 = buf1.lower().split('\n')
  s2 = buf2.lower().split('\n')
  seq = SequenceMatcher(None, s1, s2)
  return seq.ratio()

#-------------------------------------------------------------------------------
def compare_list(value1 : str, value2 : str) -> float:
  s1 = set( json.loads(value1) )
  s2 = set( json.loads(value2) )
  val = 0.0
  if len(s1) == 0 or len(s2) == 0:
    val = INVALID_SCORE
  else:
    inter = len(s1.intersection(s2))
    maxs  = len(max(s1, s2))
    val = (inter * 100) / maxs
    val /= 100
  return val

#-------------------------------------------------------------------------------
def compare_row(d : dict, same_binary : bool) -> COutputRow:

  test_ratio = 0.0
  total_fields = 0

  out = COutputRow()
  out.good = same_binary and d["ea1"] == d["ea2"]
  out.name = f'{d["name1"]} - {d["name2"]}'
  out.values["name"] = int(out.good)
  out.values["ratio"] = 0

  for field in FIELDS:
    if field == "name":
      continue

    val1 = d[f"{field}1"]
    val2 = d[f"{field}2"]

    tmp = 0.0
    if type(val1) is int and type(val2) is int:
      tmp = int_compare_ratio(val1, val2)
    elif type(val1) is str and type(val2) is str:
      if val1.startswith("["):
        tmp = compare_list(val1, val2)
      else:
        tmp = quick_ratio(val1, val2)
    elif val1 is None or val2 is None:
      tmp = INVALID_VALUE
    else:
      raise Exception("wut?")

    total_fields += 1
    test_ratio += tmp

    out.values[field] = tmp
    if field in NUM_FIELDS:
      v1 = val1 if val1 is not None else INVALID_VALUE
      v2 = val2 if val2 is not None else INVALID_VALUE
      out.values[f"min_{field}"] = min(v1, v2)
      out.values[f"max_{field}"] = max(v1, v2)

  out.values["ratio"] = test_ratio / total_fields
  return out

#-------------------------------------------------------------------------------
def get_model_comparison_data(d : dict, same_arch : bool) -> pd.DataFrame:
  ret = compare_row(d, False)
  ret.values["cpu"] = same_arch
  ret.values["arch"] = same_arch

  df = pd.DataFrame([ret.values])
  return df.loc[:,DATA_FRAME_FIELDS]
