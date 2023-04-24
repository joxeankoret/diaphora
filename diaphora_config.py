################################################################################
# Diaphora 3.0 configuration options
################################################################################

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

# The minimum number of functions in a database to, by default, disable running
# slow queries.
MIN_FUNCTIONS_TO_DISABLE_SLOW = 2000
# The minimum number of functions to consider it of medium size and disable, for
# example, exporting microcode.
MIN_FUNCTIONS_TO_CONSIDER_MEDIUM = 8000
# The minimum number of functions to consider it of huge size and recommend not
# exporting everything.
MIN_FUNCTIONS_TO_CONSIDER_HUGE = 100000

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
# is the same for both.
MATCHES_BONUS_RATIO = 0.01

# Number of decimal digits to use for calculations and displaying ratios in the
# choosers.
DECIMAL_VALUES = "7f"
