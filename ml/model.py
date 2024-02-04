#!/usr/bin/python3

__all__ = ["ML_ENABLED", "ml_model", "train", "predict", "get_model_name"]

import sys
import json
import random

from difflib import SequenceMatcher

#-------------------------------------------------------------------------------
try:
  import numpy as np

  from sklearn.linear_model import RidgeClassifier
  from sklearn.calibration import CalibratedClassifierCV
  
  ML_ENABLED = True
except ImportError:
  print("Both numpy and Scikit Learn are needed to use local models.")
  ML_ENABLED = False

sys.path.append(".")
sys.path.append("..")

from diaphora_heuristics import SELECT_FIELDS
from diaphora_config import ML_MATCHES_MIN_RATIO

#-------------------------------------------------------------------------------
ml_model = None
COLUMNS = [
  "nodes", "edges", "indegree", "outdegree", "instructions",
  "cyclomatic_complexity", "strongly_connected", "loops", "constants_count",
  "md_index", "size"
]

INVALID_SCORE = -1

#-------------------------------------------------------------------------------
def convert2numbers(row : list) -> list:
  for i, item in enumerate(row):
    val = row[i]
    if str(item).find(".") > -1:
      row[i] = float(val)
    else:
      row[i] = int(val)
  return row

#-------------------------------------------------------------------------------
def quick_ratio(buf1 : str, buf2 : str) -> float:
  """
  Call SequenceMatcher.quick_ratio() to get a comparison ratio.
  """
  if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
    return 0
  seq = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
  return seq.quick_ratio()

#-------------------------------------------------------------------------------
def compare_rows(row1 : list, row2 : list) -> list[float]:
  scores = []
  keys = list(row1.keys())
  IGNORE = ["id", "db_name", "export_time"]
  for key in keys:
    if key in IGNORE:
      continue

    value1 = row1[key]
    value2 = row2[key]

    if value1 is None or value2 is None:
      scores.append(INVALID_SCORE)
      continue

    if type(value1) is int:
      if value1 + value2 == 0:
        val = 1.0
      else:
        val = 1 - ( abs(value1 - value2) / max(value1, value2) )
      scores.append(val)
    elif type(value1) is str:
      if value1.startswith('["') and value2.startswith('["'):
        s1 = set( json.loads(value1) )
        s2 = set( json.loads(value2) )
        if len(s1) == 0 or len(s2) == 0:
          val = INVALID_SCORE
        else:
          inter = len(s1.intersection(s2))
          maxs  = len(max(s1, s2))
          val = 1. - (inter / maxs)
        scores.append(val)
      else:
        val = quick_ratio(value1, value2)
        scores.append(val)
    else:
      scores.append(value1 == value2)
  return scores

#-------------------------------------------------------------------------------
class CClassifier:
  def __init__(self, diaphora_obj : object):
    self.diaphora = diaphora_obj
    self.clf = RidgeClassifier()
    self.matches = []
    self.primary = {}
    self.secondary = {}
    self.fitted = False

    self.model = None

  def find_matches(self, matches : list):
    for group in matches:
      if group in ["best", "partial"]:
        for match in matches[group]:
          name1 = match[1]
          name2 = match[3]
          score = match[5]
          if score >= ML_MATCHES_MIN_RATIO:
            self.matches.append([name1, name2])
    self.matches = np.array(self.matches)

  def get_features(self, row : dict) -> list:
    l = []
    for col in COLUMNS:
      l.append(row[col])
    return l

  def db_query_values(self):
    cur = self.diaphora.db_cursor()
    try:
      sql = "create temporary table model_functions(db_name, name)"
      cur.execute(sql)

      vals = [ ["main", 0], ["diff", 1] ]
      for db_name, idx in vals:
        sql = "insert into model_functions values ('{db}', ?)"
        query = sql.format(db=db_name)
        for name in self.matches[:,idx]:
          cur.execute(query, (name,))

      sql = """ select distinct *
                  from {db}.functions f
                 where name in (select name
                                  from model_functions
                                 where db_name = ?) """
      for db_name, idx in vals:
        query = sql.format(db=db_name)
        if db_name == "main":
          d = self.primary
        else:
          d = self.secondary

        cur.execute(query, (db_name,))
        while 1:
          row = cur.fetchone()
          if not row:
            break

          features = self.get_features(row)
          d[row["name"]] = features
    finally:
      cur.close()

  def train_local_model(self) -> float:
    X = []
    Y = []
    total_round = 0
    found_some_good = False
    for match1 in self.matches:
      name1, _ = match1
      total_round = 0
      found_good = False
      for match2 in self.matches:
        total_round += 1
        _, name2 = match2
        if match1[0] == match2[0] and match1[1] == match2[1]:
          found_good = True

        if found_good and total_round >= 10:
          break

        exists, l = self.diaphora.functions_exists(name1, name2)
        if not exists:
          self.diaphora.log("ML: Function does not exist???")
          continue

        row1 = l[0]
        row2 = l[1]
        ratio = self.diaphora.compare_function_rows(row1, row2)
        features1 = self.get_features(row1)
        features2 = self.get_features(row2)
        comparisons = compare_rows(row1, row2)
        final = features1 + features2 + comparisons
        final = convert2numbers(final)

        x = np.array(final)

        # The ratio could be the actual ratio we calculate, but we want to train
        # a classifier, therefore, we will only use "good" (1.0) and "bad" (0).
        if ratio >= ML_MATCHES_MIN_RATIO:
          ratio = 1.
          found_some_good = True
        else:
          ratio = 0.0

        y = [ round(ratio), ]

        X.append(x)
        Y.append(y)

    X = np.array(X)
    Y = np.array(Y)

    if found_some_good:
      self.clf.fit(X, Y)
      calibrator = CalibratedClassifierCV(self.clf, cv='prefit')
      self.model = calibrator.fit(X, Y)
      self.diaphora.log(f"ML model score {self.clf.score(X, Y)}")
    else:
      self.diaphora.log(f"The ML model did not find any good enough match to use for training")

    return found_some_good

  def train(self, matches : list):
    self.find_matches(matches)
    if len(self.matches) > 0:
      self.db_query_values()
      self.diaphora.log_refresh("Training local model...")
      self.fitted = self.train_local_model()
      self.diaphora.log_refresh("Done training local model...")

  def predict(self, row : dict) -> float:
    ret = 0.0
    if self.fitted:
      if 'predict_proba' in dir(self.clf):
        ret = self.clf.predict(row)
        if ret[0] == 1:
          ret = self.model.predict_proba(row)
          return round(ret[0][1], 3)
      else:
        ret = self.clf.predict(row)
    return ret

#-------------------------------------------------------------------------------
def train(diaphora_obj : object, matches : list):
  global ml_model
  ml_model = CClassifier(diaphora_obj)
  ml_model.train(matches)

#-------------------------------------------------------------------------------
def predict(main_row : dict, diff_row : dict, ratio : float) -> float:
  global ml_model
  ratio = 0.0
  if ml_model is not None:
    row = []
    for col in COLUMNS:
      row.append(main_row[col])
    for col in COLUMNS:
      row.append(diff_row[col])
    comparisons = compare_rows(main_row, diff_row)
    row.extend(comparisons)
    row = convert2numbers(row)
    ratio = ml_model.predict([row])
  return ratio

#-------------------------------------------------------------------------------
def get_model_name():
  global ml_model
  if ml_model is None:
    return "None"
  return ml_model.clf.__class__.__name__
