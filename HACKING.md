# Diaphora Hacking Guide

## Coding Style Guide

This document describes the current coding conventions used in Diaphora. They
haven't changed in _::Joxean checks the clock::_ 10 years, so please follow these
rules when contributing code.

### Indentation

Diaphora uses 2 spaces, no tabs or 4 spaces.

### Quotes

Prefer double quotes for strings and docstrings.

```python
name = "some_name"
sql = "select * from functions"
```

### Docstrings

Keep docstrings short. Use a single line when possible with the ending """ in the
next line.

```python
def do_something():
  """ Do something useful
  """
  pass

def do_something_complex():
  """
  Do something complex that requires a longer explanation spanning
  multiple lines.
  """
  pass
```

### Naming Conventions

- **Classes**: PascalCase with a `C` prefix: `CChooser`, `CBinDiff`,
  `CKoretFuzzyHashing`.
- **Functions and methods**: `snake_case`: `get_function_names()`,
  `save_callgraph()`.
- **Variables**: `snake_case`: `bytes_hash`, `bb_relations`, `image_base`.
- **Constants**: `UPPER_CASE`: `VERSION_VALUE`, `SQL_MAX_PROCESSED_ROWS`.

### String Formatting

Prefer f-strings for new code. Legacy `%` formatting is acceptable where it
already exists. Do not use `.format()` unless building SQL templates.

```python
log(f"Processing function {name} at 0x{ea:08x}")
```

### Imports

Import standard libraries first, then 3rd party, and local ones last. Using
`try/except` blocks for optional dependencies is OK. Avoid wildcard imports
unless there is really no other option:

```python
# pylint: disable=wildcard-import
from idaapi import *
# pylint: enable=wildcard-import
```

### Comments

Diaphora uses `#` comments for inline explanations. Use dashed separator lines
to delimit major sections:

```python
#-------------------------------------------------------------------------------
# Section name
#-------------------------------------------------------------------------------
```

### Line Length

We are not in the 90s, we have bigger screens, but remember that big lines are
hardly readable. So, soft limit around 100-120 characters. SQL strings may exceed
this for readability.

### Error Handling

Bare `except:` is acceptable for non-critical paths (`__del__`, optional
features). Use specific exceptions when the failure mode matters. Always use
`try/finally` for cleanup *specially* for database cursors (or database locking
problems will happen and you will only have yourself to blame).

```python
cur = self.db_cursor()
try:
  cur.execute(sql)
finally:
  cur.close()
```

Use `KeyError` handling with `try/except` when it makes more sense than using
`.get()`:

```python
try:
  multi_main[ea1].append(item)
except KeyError:
  multi_main[ea1] = [item]
```

### Classes

Diaphora uses explicit inheritance. No implicit `object` base class. Initialize
all attributes in `__init__`:

```python
class CMyClass(CBaseClass):
  def __init__(self):
    self.some_attr = None
    self.items = []
```

### SQL Strings

Use triple-quoted strings with `?` placeholders for parameterized queries:

```python
sql = """select name, address
           from functions
          where id = ?"""
cur.execute(sql, (func_id,))
```

In general, *DO NOT EVER USE CONCATENATED SQL COMMANDS*, unless you really have
a good reason for doing so.

### Logging

Use `log()` for general messages (uses `logging.info()` or `print()` depending
on context).
Use `log_refresh()` for UI progress messages in IDA.
Use `debug_refresh()` for (you won't believe this) debug-level messages.
Use `print()` for direct output, typically for errors during export, and nowhere
else.

### Boolean and None Comparisons

Do not use `== True`, `== False`, or `== None`. Please. Use this:

```python
if not results:
  return

if value is None:
  return

if name is not None:
  process(name)
```

### Return Patterns

Early returns are commonly used to reduce nesting:

```python
def read_function(self, ea):
  if not valid:
    return False

  # main logic here
  return result
```

### Blank Lines

One blank line between methods inside a class. Two blank lines between top-level
definitions. One blank line to separate logical blocks within a function.

### Function Signatures

Split long signatures across multiple lines:

```python
def save_microcode_instructions(
  self, func_id, cur, cur_execute, microcode_bblocks, microcode_bbrelations
):
```

### Pylint Directives

Don't use them anymore, they are subject to be removed very soon.

## Adding heuristics

This is the recommended way of writing new heuristics for Diaphora:

* Write SQL queries (see `diaphora_heuristics.py`).
* Or write pure Python code.

It's recommended to use SQL queries whenever it's possible.

### SQL heuristics

All SQL heuristics are add to `diaphora_heuristics.py` in the global `HEURISTICS`
list. Each item is a dict with the following keys:

| Key        | Description                                           |
|------------|-------------------------------------------------------|
| `name`     | Human-friendly name that will be shown in UI and logs.|
| `category` | One of `"Best"`, `"Partial"`, or `"Unreliable"`.      |
| `ratio`    | How matches are scored (see ratio types below).       |
| `sql`      | The SQL query (see query format below).               |
| `flags`    | List of flags (see flags below), if any.              |
| `min`      | Only required for `HEUR_TYPE_RATIO_MAX` and `HEUR_TYPE_RATIO_MAX_TRUSTED`. Minimum ratio to accept a partial match. |

#### Ratio types

These control how Diaphora handles the results returned by the query:

- `HEUR_TYPE_NO_FPS`: No ratio is checked, nothing is verified, it just adds the
results directly to the best chooser with a 1.0 ratio. Use this *only* for
heuristics where you are completely & absolutely sure both functions are the
same (for example, with exact byte hash match).
- `HEUR_TYPE_RATIO`: Diaphora calculates a similarity ratio for each match. Results
with ratio 1.0 go to the best chooser, 0.5-1.0 to partial, and below 0.5 to unreliable.
- `HEUR_TYPE_RATIO_MAX`: Same as `HEUR_TYPE_RATIO`, but partial results are only
accepted if the ratio is above the `min` value.
- `HEUR_TYPE_RATIO_MAX_TRUSTED`: Same as `HEUR_TYPE_RATIO_MAX`, but results below
the `min` threshold go to the partial chooser instead of to the unreliable one.

#### Flags

- `HEUR_FLAG_NONE`: No flag needed.
- `HEUR_FLAG_UNRELIABLE`: Indicates the heuristic might generate unreliable results.
- `HEUR_FLAG_SLOW`: Only runs when the reverser enables slow heuristics.
- `HEUR_FLAG_SAME_CPU`: Only runs when diffing binaries for the same CPU architecture.

#### Query format

The SQL query joins functions from the main database (`functions f`) against
the diff database (`diff.functions df`). Use `get_query_fields(NAME)` to generate
the standard SELECT fields:

```python
NAME = "My new heuristic"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.some_column = df.some_column
        and f.nodes > 3
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})
```

A few things to keep in mind:

- Always include `%POSTFIX%` in the WHERE clause. Diaphora replaces it at
  runtime with filters for ignoring small functions (when enabled).
- The `get_query_fields(NAME)` call generates all the SELECT columns that the
  matching engine expects. The first argument is the heuristic name, which
  ends up in the `description` column of the results.
- Tables available: `functions` / `diff.functions` for function data,
  `main.constants` / `diff.constants` for constants,
  `main.compilation_units` / `diff.compilation_units` and
  `main.compilation_unit_functions` / `diff.compilation_unit_functions` for
  compilation unit data.
- You can use CTEs (`with ... as`), `union`, `distinct`, etc. Be careful
  with `ORDER BY` on large databases: SQLite may generate huge temporary
  B-TREEs that can cause slowness or even errors.
- Add the new heuristic in the right position in the `HEURISTICS` list.
  Heuristics run in order, and earlier heuristics consume matches before
  later ones see them. Put high-confidence ones first.

#### Example: minimal no-false-positives heuristic

```python
NAME = "Same bytes hash and node count"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.bytes_hash = df.bytes_hash
        and f.nodes = df.nodes
        and f.nodes >= 3
        %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})
```

#### Example: ratio-based heuristic with minimum threshold

```python
NAME = "Same rare constant and node count"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions f,
            diff.functions df
      where mc.constant = dc.constant
        and f.id = mc.func_id
        and df.id = dc.func_id
        and f.nodes = df.nodes
        and f.nodes >= 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[]
})
```
