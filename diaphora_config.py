"""
Behold, Diaphora 3.0 configuration options ahead!

NOTES: This configuration file is a normal python script, therefore, you're free
to add your own code here.
"""

################################################################################
# Imports required by the configuration file
import os
from queue import Queue
from typing import Optional, Tuple

CONFIGURATION_FILE_PATH = os.path.realpath(__file__)
CONFIGURATION_DIRECTORY = os.path.dirname(CONFIGURATION_FILE_PATH)

################################################################################
# Default colors related options

# Colors for the call graph viewer nodes.
# NOTE: Colors are specified in the format 0xBGR instead of RGB.
CALLGRAPH_COLOR_TARGET = 0xEEFF00
CALLGRAPH_COLOR_CALLER = 0xFFFFFF
CALLGRAPH_COLOR_CALLEE = 0xFFFFFF

# Colors for displaying differences.
# NOTE: Colors in this case are in the format "#RGB" because they are used for
# the CSS.
DIFF_COLOR_ADDED      = "#aaffaa"
DIFF_COLOR_CHANGED    = "#ffff77"
DIFF_COLOR_SUBTRACTED = "#ffaaaa"
DIFF_COLOR_LINE_NO    = "#e0e0e0"

# Colors for highlighting functions when the appropriate popup menu option is
# selected, in 0xBGR format.
HIGHLIGHT_FUNCTION_BEST       = 0xffff99
HIGHLIGHT_FUNCTION_PARTIAL    = 0x99ff99
HIGHLIGHT_FUNCTION_UNRELIABLE = 0x9999ff

# Colors for displaying control flow graph differences, in 0xBGR format.
GRAPH_BBLOCK_MATCH_PARTIAL = 0xCCFFFF
GRAPH_BBLOCK_MATCH_PERFECT = 0xFFFFFF
GRAPH_BBLOCK_MATCH_NONE    = 0xCCCCFF

################################################################################
# Default export & diffing options

DIFFING_ENABLE_UNRELIABLE = False
DIFFING_ENABLE_RELAXED_RATIO = False
DIFFING_ENABLE_EXPERIMENTAL = True
DIFFING_ENABLE_SLOW_HEURISTICS = False
DIFFING_IGNORE_SUB_FUNCTION_NAMES = True
DIFFING_IGNORE_ALL_FUNCTION_NAMES = False
DIFFING_IGNORE_SMALL_FUNCTIONS = False

EXPORTING_USE_DECOMPILER = True
EXPORTING_EXCLUDE_LIBRARY_THUNK = True
EXPORTING_ONLY_NON_IDA_SUBS = True
EXPORTING_FUNCTION_SUMMARIES_ONLY = False
EXPORTING_USE_MICROCODE = True

# Number of rows that must be inserted to commit the transaction
EXPORTING_FUNCTIONS_TO_COMMIT = 5000

# The minimum number of functions in a database to, by default, disable running
# slow queries.
MIN_FUNCTIONS_TO_DISABLE_SLOW = 2000
# The minimum number of functions to consider it of medium size and disable, for
# example, exporting microcode.
MIN_FUNCTIONS_TO_CONSIDER_MEDIUM = 8000
# The minimum number of functions to consider it of huge size and recommend not
# exporting everything.
MIN_FUNCTIONS_TO_CONSIDER_HUGE = 100000

# Block size to use to generate fuzzy hashes for pseudo-codes with DeepToad
FUZZY_HASHING_BLOCK_SIZE = 512

################################################################################
# Default SQL related configuration options

# Diaphora won't process more than the given value of rows (per heuristic)
SQL_MAX_PROCESSED_ROWS = 1000000
# SQL queries will timeout after the given number of seconds
SQL_TIMEOUT_LIMIT = 60 * 5

################################################################################
# Heuristics related configuration options

# This is a value that we add when we found a match by diffing previous known
# good matches assembly and pseudocode. The problem is that 2 functions can have
# the same assembly or pseudo-code but be different functions. However, as we're
# getting the match from previously known good matches, even if our internal
# function to calculate similarity gives out the same ratio, we know for a fact
# that the match found by diffing matches is *the* match. To prevent such little
# problems, we just add this value to the calculated ratio and that's about it.
#
# Update: Initially, it was only used for matches found by diffing previous good
# known matches. However, it's also used now for matches where the function name
# is the same for both because, believe it or not, there can be another function
# with the very same pseudo-code or assembly, but a different name, but that is
# not the true match, because the true match is the one with that function name.
MATCHES_BONUS_RATIO = 0.01

# Number of decimal digits to use for calculations and displaying ratios in the
# choosers.
DECIMAL_VALUES = "7f"

# The maximum number of functions that could be in a gap of unmatched functions
# for the "Local Affinity" heuristic to be launched.
MAX_FUNCTIONS_PER_GAP = 100

# The default SQL's WHERE clause postfix used to determine when a function is
# small.
SQL_DEFAULT_POSTFIX = " and f.instructions > 5 and df.instructions > 5 "

# Used as a speed up when "relaxed ratio calculations" is enabled, to consider
# structurally equal two functions with the same MD-Index if its value is bigger
# than the specified value.
MINIMUM_RARE_MD_INDEX = 10.0

# The minimum ratio needed to assign some heuristics to the partial matches tab
# instead of dropping the result or putting it in the unreliable matches tab.
DEFAULT_PARTIAL_RATIO = 0.5

# Some heuristics generates much less false positives, if at all, therefore we
# can relax the minimum ratio needed to consider a match good or bad.
DEFAULT_TRUSTED_PARTIAL_RATIO = 0.3

# Regular expressions used to clean-up the pseudo-code and assembly dumps in
# order to get better comparison ratios.
CLEANING_CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_", "flt_", "jpt_"]
CLEANING_CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]

# When diffing the same binary with just symbol names stripped, usually around
# 99% of the functions are matched by address. This value indicates what is that
# percent that Diaphora will use to enable this speed up.
SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT = 99.0

# There are some easy methods to speed up diffing when both databases have names
# (symbols), specially when almost the whole binary matches. This value is used
# to determine what is the minimum percent of matched functions to enable this
# speed up.
SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT = 90.0

# Sometimes functions are just renamed but they are still in the binary, thus,
# the patch diffing speed up could miss such changes. This is the minimum ratio
# used to compare functions that differ in names and were not matched previously
# by function name.
SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO = 0.6

# If the number of basic blocks differ in more than 75% we should ignore that 
# match that was discovered by diffing the assembly or pseudo-code of previous
# matches. This value is a percent, not the number of different basic blocks.
DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT = 25

# Small functions cause a lot of false positives and different heuristics are
# differently affected by what is a small function. This value configures the 
# minimum number of basic blocks a function must have for the heuristic that
# finds new matches by diffing previous matches to consider or drop this match.
DIFFING_MATCHES_MIN_BBLOCKS = 3

# Run default scripts?
RUN_DEFAULT_SCRIPTS = True

# Where is the default patch diffing script?
DEFAULT_SCRIPT_PATCH_DIFF = os.path.join(CONFIGURATION_DIRECTORY, "scripts/patch_diff_vulns.py")

# Parallel Export
PARALLEL_EXPORT: bool = False  # default to sequential export
PARALLEL_JOB_QUEUE: Optional[Queue[Tuple[int, int]]] = None
PARALLEL_REPORT_QUEUE: Optional[Queue[Tuple[int, int]]] = None
WORKER_ID: int = 0  # ID of current worker
NUMBER_OF_WORKERS: int = 1
