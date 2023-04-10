################################################################################
# Diaphora configuration file
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

# The minimum number of functions in a database to, by default, disable running
# slow queries.
MIN_FUNCTIONS_TO_DISABLE_SLOW = 2000

