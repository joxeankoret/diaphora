#!/usr/bin/python3

"""
Threads support
Copyright (c) 2023, Joxean Koret

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

__all__ = ["threads_apply"]

import time
import threading

#-------------------------------------------------------------------------------
def threads_apply(threads, targets, wait_time, log_refresh, timeout):
  """
  Run a number of @threads calling a function with arguments from @targets,
  waiting and checking the threads if they finished every @wait_time seconds,
  calling @log_refresh whenever it's required.
  """
  times = 0
  first = True
  threads_list = []
  while first or len(targets) > 0 or len(threads_list) > 0:
    first = False
    times += 1
    if len(targets) > 0 and len(threads_list) < threads:
      item = targets.pop()
      target = item["target"]
      args = item["args"]

      t = threading.Thread(target=target, args=args)
      t.time = time.monotonic()
      t.timeout = False
      
      for key in item.keys():
        if key not in ["target", "args"]:
          setattr(t, key, item[key])

      t.start()
      threads_list.append(t)

    for i, t in enumerate(threads_list):
      if not t.is_alive():
        if log_refresh:
          log_refresh(f"[Parallel] Heuristic '{t.name}' done")
        del threads_list[i]
        break

      if time.monotonic() - t.time > timeout:
        t.timeout = True
      t.join(wait_time)

    if times % 50 == 0:
      names = []
      for x in threads_list:
        names.append(x.name)
      tmp_names = ", ".join(names)
      log_refresh(f"[Parallel] {len(threads_list)} thread(s) still running: {tmp_names}")

