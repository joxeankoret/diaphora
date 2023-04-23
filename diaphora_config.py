################################################################################
# Diaphora configuration file
################################################################################

################################################################################
# Default colors related options
################################################################################

# Colors for the call graph viewer nodes.
# NOTE: Colors are specified in the format 0xBGR instead of RGB.
CALLGRAPH_COLOR_TARGET = 0xEEFF00
CALLGRAPH_COLOR_CALLER = 0xFFFFFF
CALLGRAPH_COLOR_CALLEE = 0xFFFFFF

# Colors for displaying differences
# NOTE: Colors in this case are in the format "#RGB" because they are used for
# the CSS.
DIFF_COLOR_ADDED      = "#aaffaa"
DIFF_COLOR_CHANGED    = "#ffff77"
DIFF_COLOR_SUBTRACTED = "#ffaaaa"
DIFF_COLOR_LINE_NO    = "#e0e0e0"

################################################################################
# Default export & diffing options
################################################################################

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

# The minimum number of functions in a database to, by default, disable running
# slow queries.
MIN_FUNCTIONS_TO_DISABLE_SLOW = 2000
MIN_FUNCTIONS_TO_CONSIDER_MEDIUM = 8000
MIN_FUNCTIONS_TO_CONSIDER_HUGE = 100000

################################################################################
# Default SQL related configuration options
################################################################################

# Diaphora won't process more than the given value of rows (per heuristic)
SQL_MAX_PROCESSED_ROWS = 1000000
# SQL queries will timeout after the given number of seconds
SQL_TIMEOUT_LIMIT = 60 * 5
