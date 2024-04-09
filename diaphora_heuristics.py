#!/usr/bin/python3

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015-2024, Joxean Koret

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

#-------------------------------------------------------------------------------
# Only used for the internal tests
import pprint
from collections import Counter

#-------------------------------------------------------------------------------
# Use only for heuristics generating 1.0 ratios, results without false positives
HEUR_TYPE_NO_FPS = 0

# Use it for most heuristics; it will assign 1.0 ratios to the best chooser,
# values between 0.5 and <1.0 to the specific partial chooser and <0.5 results
# to the unreliable chooser, if specified.
HEUR_TYPE_RATIO = 1

# Similar as before, but partial results are only assigned for matches with a
# min specified ratio.
HEUR_TYPE_RATIO_MAX = 2

# Similar as before, but 'unreliable' results are not unreliable, thus, they go
# to the 'partial' tab instead.
HEUR_TYPE_RATIO_MAX_TRUSTED = 3

#-------------------------------------------------------------------------------
HEUR_FLAG_NONE        = 0
HEUR_FLAG_UNRELIABLE  = 1
HEUR_FLAG_SLOW        = 2
# The heuristic should only be launched when diffing the same architecture
HEUR_FLAG_SAME_CPU    = 3

#-------------------------------------------------------------------------------
SELECT_FIELDS = """ f.address ea, f.name name1, df.address ea2, df.name name2,
                  {heur} description,
                  f.pseudocode pseudo1, df.pseudocode pseudo2,
                  f.assembly asm1, df.assembly asm2,
                  f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                  f.nodes nodes1, df.nodes nodes2,
                  cast(f.md_index as real) md1, cast(df.md_index as real) md2,
                  f.clean_assembly clean_assembly1, df.clean_assembly clean_assembly2,
                  f.clean_pseudo clean_pseudo1, df.clean_pseudo clean_pseudo2,
                  f.mangled_function mangled1, df.mangled_function mangled2,
                  f.clean_microcode clean_micro1, df.clean_microcode clean_micro2,
                  f.bytes_hash bytes_hash1, df.bytes_hash bytes_hash2,
                  f.edges edges1, df.edges edges2,
                  f.indegree indegree1, df.indegree indegree2,
                  f.outdegree outdegree1, df.outdegree outdegree2,
                  f.instructions instructions1, df.instructions instructions2,
                  f.cyclomatic_complexity cc1, df.cyclomatic_complexity cc2,
                  f.strongly_connected strongly_connected1,
                  df.strongly_connected strongly_connected2,
                  f.loops loops1, df.loops loops2,
                  f.constants_count constants_count1,
                  df.constants_count constants_count2,
                  f.size size1, df.size size2,
                  f.kgh_hash kgh_hash1, df.kgh_hash kgh_hash2
"""
def get_query_fields(heur, quote=True):
  """
  Get the list of fields used in any and all SQL heuristics queries.
  """
  val = heur
  if quote:
    val = repr(val)
  ret = SELECT_FIELDS.format(heur=val)
  return ret

#-------------------------------------------------------------------------------
HEURISTICS = []

NAME = "Same RVA and hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where (df.rva = f.rva
                 or df.segment_rva = f.segment_rva)
               and df.bytes_hash = f.bytes_hash
               and df.instructions = f.instructions
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               and f.nodes >= 3
               and df.nodes >= 3
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Same order and hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where df.id = f.id
               and df.bytes_hash = f.bytes_hash
               and df.instructions = f.instructions
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               and ((f.nodes > 1 and df.nodes > 1
                 and f.instructions > 5 and df.instructions > 5)
                  or f.instructions > 10 and df.instructions > 10)
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Function Hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where f.function_hash = df.function_hash 
               and ((f.nodes > 1 and df.nodes > 1
                 and f.instructions > 5 and df.instructions > 5)
                  or f.instructions > 10 and df.instructions > 10)
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Bytes hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where f.bytes_hash = df.bytes_hash
               and f.instructions > 5 and df.instructions > 5
               %POSTFIX%""",
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Same address and mnemonics"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where df.address = f.address
               and df.mnemonics = f.mnemonics
               and df.instructions = f.instructions
               and df.instructions > 5
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               %POSTFIX%
             order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Same cleaned assembly"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.clean_assembly = df.clean_assembly
         and f.nodes >= 3 and df.nodes >= 3
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Same cleaned microcode"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.clean_microcode = df.clean_microcode
         and f.instructions > 3 and df.instructions > 3
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Same cleaned pseudo-code"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.clean_pseudo = df.clean_pseudo
         and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Same address, nodes, edges and mnemonics"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.rva = df.rva
        and f.instructions = df.instructions
        and f.nodes = df.nodes
        and f.edges = df.edges
        and f.mnemonics = df.mnemonics
        and f.instructions > 3
        and df.instructions > 3
        and f.nodes > 1
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Same RVA"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
              from functions f,
                   diff.functions df
             where df.rva = f.rva
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_'))
               and  f.nodes >= 3
               and df.nodes >= 3
               %POSTFIX%
             order by f.source_file = df.source_file""",
  "min":0.7,
  "flags":[HEUR_FLAG_SAME_CPU]
})

#
# Seems not to find anything?
#
NAME = "Equal assembly or pseudo-code"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":"""select """ + get_query_fields("Equal pseudo-code") + """
       from functions f,
            diff.functions df
      where f.pseudocode = df.pseudocode
        and df.pseudocode is not null
        and f.pseudocode_lines >= 5
        and f.name not like 'nullsub%'
        and df.name not like 'nullsub%'
        %POSTFIX%
      union
     select """ + get_query_fields("Equal assembly") + """
       from functions f,
            diff.functions df
      where f.assembly = df.assembly
        and df.assembly is not null
        and f.instructions >= 4 and df.instructions >= 4
        and f.name not like 'nullsub%'
        and df.name not like 'nullsub%'
        %POSTFIX% """,
  "flags":[]
})

NAME = "Microcode mnemonics small primes product"
HEURISTICS.append({
  "name":NAME,
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.microcode_spp = df.microcode_spp
         and f.microcode_spp != 1
         and df.microcode_spp != 1
         and f.instructions > 5 and df.instructions > 5
         and f.nodes > 2 and df.nodes > 2
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[]
})

# It seems that SQLite is slowly executing this query due to the following:
#
#   BLOOM FILTER ON main_cu (id=?)
#
# I have seen bugs related to this fixed on February 2023, so I think I'll have
# to take a look to see if bloom filters can be disabled...
NAME = "Same named compilation unit function match"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX_TRUSTED,
  "sql":"""  select """ + get_query_fields(NAME) + """
               from main.compilation_units main_cu,
                    main.compilation_unit_functions mcuf,
                    main.functions f,
                    diff.compilation_units diff_cu,
                    diff.compilation_unit_functions dcuf,
                    diff.functions df
              where main_cu.name != ''
                and diff_cu.name != ''
                and main_cu.name = diff_cu.name
                and f.id = mcuf.func_id
                and df.id = dcuf.func_id
                and mcuf.cu_id = main_cu.id
                and dcuf.cu_id = diff_cu.id
                and df.primes_value = f.primes_value
                and df.nodes = f.nodes
                and f.nodes >= 5
                %POSTFIX% 
                """,
  "min":0.44,
  "flags":[]
})

NAME = "Same anonymous compilation unit function match"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select """ + get_query_fields(NAME) + """
               from main.compilation_units main_cu,
                    main.compilation_unit_functions mcuf,
                    main.functions f,
                    diff.compilation_units diff_cu,
                    diff.compilation_unit_functions dcuf,
                    diff.functions df
              where main_cu.name != ''
                and diff_cu.name != ''
                and main_cu.name = diff_cu.name
                and f.id = mcuf.func_id
                and df.id = dcuf.func_id
                and mcuf.cu_id = main_cu.id
                and dcuf.cu_id = diff_cu.id
                and df.pseudocode_primes = f.pseudocode_primes
                and df.nodes = f.nodes
                and f.nodes >= 5
                %POSTFIX% 
              order by f.source_file = df.source_file""",
  "min":0.449,
  "flags":[]
})

# An ORDER BY clause would be good to have here, but SQLite may generate huge
# B-TREEs that might even cause errors after a long time running when dealing
# with huge databases, therefore, I'm removing it.
#
# Also, it seems that a bloom filter is used here too:
#
# BLOOM FILTER ON df (id=?)
#
# And it might be slowing down our query...
NAME = "Same compilation unit"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
                from main.compilation_units mcu,
                  main.compilation_unit_functions mcuf,
                  main.functions f,
                  diff.compilation_units dcu,
                  diff.compilation_unit_functions dcuf,
                  diff.functions df
              where dcu.pseudocode_primes = mcu.pseudocode_primes
                and mcuf.cu_id = mcu.id
                and dcuf.cu_id = dcu.id
                and f.id = mcuf.func_id
                and df.id = dcuf.func_id
                and f.nodes > 4
                and df.nodes > 4
                and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')
                %POSTFIX% """,
  "flags":[HEUR_FLAG_SLOW]
})

# Adding a DISTINCT and an ORDER BY clause in this query causes SQLite to create
# huge temporary B-TREEs that, depending on the size of the databases, might end
# up triggering an error after a long time running.
NAME = "Same KOKA hash and constants"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and f.kgh_hash = df.kgh_hash
        and f.nodes >= 3
        %POSTFIX% """,
  "flags":[]
})

# The same explained in the previous query happens here: for huge databases the
# SQLite engine can generate huge B-TREEs for the ORDER BY clause. Removed it.
NAME = "Same KOKA hash and MD-Index"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""
     select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.kgh_hash = df.kgh_hash
        and f.md_index = df.md_index
        and f.nodes = df.nodes
        and f.nodes >= 4
        and f.outdegree = df.outdegree
        and f.indegree  = df.indegree
        and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) = 'sub_')
        %POSTFIX%
        """,
  "flags":[]
})

NAME = "Same constants"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.constants = df.constants
        and f.constants_count = df.constants_count
        and f.constants_count > 1
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[]
})

# The ORDER BY clause is removed because it was causing serious slowness problems
# with big and huge databases.
NAME = "Same rare KOKA hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
with shared_hashes as (
 select kgh_hash
   from diff.functions
  where kgh_hash != 0
  group by kgh_hash
 having count(*) <= 2
  union 
 select kgh_hash
   from main.functions
  where kgh_hash != 0
  group by kgh_hash
 having count(*) <= 2
)
select """ + get_query_fields(NAME) + """
  from functions f,
       diff.functions df,
       shared_hashes
 where f.kgh_hash = df.kgh_hash
   and df.kgh_hash = shared_hashes.kgh_hash
   and f.nodes > 5
   and (substr(f.name, 1, 4) = 'sub_'
     or substr(df.name, 1, 4) = 'sub_')
   %POSTFIX%
        """,
  "min":0.45,
  "flags":[]
})

NAME = "Same rare MD Index"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""
     with shared_mds as (
      select md_index
        from diff.functions
       where md_index != 0
       group by md_index
      having count(*) <= 2
      union 
      select md_index
        from main.functions
       where md_index != 0
       group by md_index
      having count(*) <= 2
     )
     select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df,
            shared_mds
      where f.md_index = df.md_index
        and df.md_index = shared_mds.md_index
        and f.nodes > 10
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

#
# Seems not find anything???
#
NAME = "Same address and rare constant"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and df.address = f.address
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[]
})

# The DISTINCT and ORDER BY clause have been removed due to slowness problems
NAME = "Same rare constant"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and f.nodes >= 3 and df.nodes >= 3
        and f.constants_count > 0
        %POSTFIX% """,
  "min":0.2,
  "flags":[HEUR_FLAG_SLOW]
})

NAME = "Same MD Index and constants"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.md_index = df.md_index
         and f.md_index > 0
         and f.nodes >= 3 and df.nodes >= 3
         and ((f.constants = df.constants
         and f.constants_count > 0))
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Import names hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
              from functions f,
                  diff.functions df
            where f.names = df.names
              and f.names != '[]'
              and f.md_index = df.md_index
              and f.instructions = df.instructions
              and f.nodes > 5 and df.nodes > 5
              %POSTFIX%
            order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Mnemonics and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.mnemonics = df.mnemonics
         and f.instructions = df.instructions
         and f.names = df.names
         and f.names != '[]'
         and f.instructions > 5 and df.instructions > 5
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Pseudo-code fuzzy hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash1 = f.pseudocode_hash1
        and df.pseudocode_hash2 = f.pseudocode_hash2
        and df.pseudocode_hash3 = f.pseudocode_hash3
        and df.pseudocode_hash1 is not null
        and df.pseudocode_hash2 is not null
        and df.pseudocode_hash3 is not null
        and f.instructions > 5
        and df.instructions > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Similar pseudo-code and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.pseudocode_lines = df.pseudocode_lines
        and f.names = df.names
        and df.names != '[]'
        and df.pseudocode_lines > 5
        and df.pseudocode is not null 
        and f.pseudocode is not null
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.579,
  "flags":[]
})

NAME = "Mnemonics small-primes-product"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.mnemonics_spp = df.mnemonics_spp
         and f.instructions = df.instructions
         and f.nodes > 1 and df.nodes > 1
         and df.instructions > 5
         %POSTFIX% """,
  "min":0.6,
  "flags":[]
})

# The ORDER BY clause is removed because it was causing serious slowness problems
# with big and huge databases.
NAME = "Same nodes, edges, loops and strongly connected components"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.nodes = df.nodes
        and f.edges = df.edges
        and f.strongly_connected = df.strongly_connected
        and f.loops = df.loops
        and f.nodes > 5 and df.nodes > 5
        and f.loops > 0
        and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')
        %POSTFIX% """,
  "min":0.549,
  "flags":[]
})

# The ORDER BY clause is removed because it was causing serious slowness problems
# with big and huge databases.
NAME = "Same low complexity, prototype and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
       select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where f.names = df.names
          and f.cyclomatic_complexity = df.cyclomatic_complexity
          and f.cyclomatic_complexity < 20
          and f.prototype2 = df.prototype2
          and df.names != '[]'
          %POSTFIX% """,
  "min":0.5,
  "flags":[]
})

NAME = "Same low complexity and names"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.names = df.names
        and f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.cyclomatic_complexity < 15
        and df.names != '[]'
        and (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4) == 'sub_')
        %POSTFIX% """,
  "min":0.5,
  "flags":[]
})

NAME = "Switch structures"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.switches = df.switches
        and df.switches != '[]'
        and f.nodes > 5 and df.nodes > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.5,
  "flags":[]
})

NAME = "Pseudo-code fuzzy (normal)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash1 = f.pseudocode_hash1
        and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.5,
  "flags":[]
})

NAME = "Pseudo-code fuzzy (mixed)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash3 = f.pseudocode_hash3
        and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Pseudo-code fuzzy (reverse)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_hash2 = f.pseudocode_hash2
        and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

NAME = "Pseudo-code fuzzy AST hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where df.pseudocode_primes = f.pseudocode_primes
        and f.pseudocode_lines >= 3
        and length(f.pseudocode_primes) >= 35
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min": 0.35,
  "flags":[]
})

NAME = "Partial pseudo-code fuzzy hash (normal)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
          and f.nodes > 5 and df.nodes > 5
          %POSTFIX%
        order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[HEUR_FLAG_SLOW, HEUR_FLAG_UNRELIABLE]
})

NAME = "Partial pseudo-code fuzzy hash (reverse)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
          and f.nodes > 5 and df.nodes > 5
          %POSTFIX%
        order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[HEUR_FLAG_SLOW, HEUR_FLAG_UNRELIABLE]
})

NAME = "Partial pseudo-code fuzzy hash (mixed)"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct """ + get_query_fields(NAME) + """
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)
          and f.nodes > 5 and df.nodes > 5
          %POSTFIX%
        order by f.source_file = df.source_file""",
  "min":0.5,
  "flags":[HEUR_FLAG_SLOW, HEUR_FLAG_UNRELIABLE]
})

NAME = "Same rare assembly instruction"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
with main_asm as (
  select f.id, f.name, inst.disasm
    from main.instructions inst,
         main.functions f
   where f.id = inst.func_id
     and f.name not like 'nullsub%'
     and inst.disasm is not null
     and inst.disasm != ''
   group by inst.disasm
  having count(0) = 1
),
diff_asm as (
  select f.id, f.name, inst.disasm
    from diff.instructions inst,
         diff.functions f
   where f.id = inst.func_id
     and f.name not like 'nullsub%'
     and inst.disasm is not null
     and inst.disasm != ''
   group by inst.disasm
  having count(0) = 1
),
query1 as (
  select distinct main_asm.id main_func_id, diff_asm.id diff_func_id
    from main_asm,
         diff_asm
   where main_asm.disasm = diff_asm.disasm
)
select """ + get_query_fields(NAME) + """
  from main.functions f,
       diff.functions df,
       query1
 where f.id  = query1.main_func_id
   and df.id = query1.diff_func_id
   and f.name != df.name
   and ((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50
   %POSTFIX%
""",
  "min":0.5,
  "flags":[HEUR_FLAG_SAME_CPU]
})

NAME = "Same rare basic block mnemonics list"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
with main_bblocks as (
select inst.func_id, bb.basic_block_id bb_id, GROUP_CONCAT(inst.mnemonic) as mnemonics_list, count(0) inst_total
  from main.bb_instructions bb,
       main.instructions inst
 where bb.instruction_id = inst.id
 group by bb_id
),
diff_bblocks as (
select inst.func_id, bb.basic_block_id bb_id, GROUP_CONCAT(inst.mnemonic) as mnemonics_list, count(0) inst_total
  from diff.bb_instructions bb,
       diff.instructions inst
 where bb.instruction_id = inst.id
 group by bb_id
),
unique_main_bblocks as (
select func_id, mnemonics_list, count(0) total
  from main_bblocks
 group by mnemonics_list
having count(0) = 1
 order by total asc
)
select """ + get_query_fields(NAME) + """
  from unique_main_bblocks main_query,
       diff_bblocks diff_query,
       main.functions f,
       diff.functions df
 where main_query.mnemonics_list = diff_query.mnemonics_list
   and f.id = main_query.func_id
   and df.id = diff_query.func_id
   and f.nodes > 3
   and df.nodes > 3
   and diff_query.inst_total >= 6
   and ((min(f.nodes, df.nodes) * 100) / max(f.nodes, df.nodes)) < 50
   %POSTFIX%
""",
  "min":0.5,
  "flags":[]
})

NAME = "Loop count"
HEURISTICS.append({
  "name":NAME,
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.loops = df.loops
        and df.loops > 1
        and f.nodes >= 3 and df.nodes >= 3
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.49,
  "flags":[HEUR_FLAG_SLOW]
})

NAME = "Same graph"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes 
         and f.edges = df.edges
         and f.indegree = df.indegree
         and f.outdegree = df.outdegree
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.strongly_connected = df.strongly_connected
         and f.loops = df.loops
         and f.tarjan_topological_sort = df.tarjan_topological_sort
         and f.strongly_connected_spp = df.strongly_connected_spp
         and f.nodes > 5 and df.nodes > 5
         %POSTFIX%
       order by
             case when f.size = df.size then 1 else 0 end +
             case when f.instructions = df.instructions then 1 else 0 end +
             case when f.mnemonics = df.mnemonics then 1 else 0 end +
             case when f.names = df.names then 1 else 0 end +
             case when f.prototype2 = df.prototype2 then 1 else 0 end +
             case when f.primes_value = df.primes_value then 1 else 0 end +
             case when f.bytes_hash = df.bytes_hash then 1 else 0 end +
             case when f.pseudocode_hash1 = df.pseudocode_hash1 then 1 else 0 end +
             case when f.pseudocode_primes = df.pseudocode_primes then 1 else 0 end +
             case when f.pseudocode_hash2 = df.pseudocode_hash2 then 1 else 0 end +
             case when f.pseudocode_hash3 = df.pseudocode_hash3 then 1 else 0 end DESC""",
  "min":0.5,
  "flags":[]
})

#
# Seems not to find anything?
#
NAME = "Strongly connected components"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""
     select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.strongly_connected = df.strongly_connected
        and df.strongly_connected > 1
        and f.nodes > 5 and df.nodes > 5
        and f.strongly_connected_spp > 1
        and df.strongly_connected_spp > 1
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "min":0.8,
  "flags":[HEUR_FLAG_SLOW]
})

#
# Seems not to find anything?
#
NAME = "Nodes, edges, complexity and mnemonics"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.mnemonics = df.mnemonics
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 1 and f.edges > 0
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})

#
# Seems not to find anything?
# Duplicate?
#
NAME = "Nodes, edges, complexity and prototype"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.prototype2 = df.prototype2
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.prototype2 != 'int()'
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})

#
# Seems not to find anything?
#
NAME = "Nodes, edges, complexity, in-degree and out-degree"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes >= 3 and f.edges > 2
         and f.indegree = df.indegree
         and f.outdegree = df.outdegree
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})

#
# Seems not to find anything?
#
NAME = "Nodes, edges and complexity"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct """ + get_query_fields(NAME) + """
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 1 and f.edges > 0
         %POSTFIX%
       order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})

#
# Seems not to find anything?
#
NAME = "Same high complexity"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.cyclomatic_complexity >= 50
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[HEUR_FLAG_SLOW]
})

#
# Seems not to find anything?
#
NAME = "Topological sort hash"
HEURISTICS.append({
  "name":NAME,
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select """ + get_query_fields(NAME) + """
       from functions f,
            diff.functions df
      where f.strongly_connected = df.strongly_connected
        and f.tarjan_topological_sort = df.tarjan_topological_sort
        and f.strongly_connected >= 3
        and f.nodes > 10
        %POSTFIX%
      order by f.source_file = df.source_file""",
  "flags":[]
})

#-------------------------------------------------------------------------------
def check_categories():
  """
  Internal test, get all the internally set categories.
  """
  categories = set()
  for heur in HEURISTICS:
    category = heur["category"]
    categories.add(category)

  print("Categories:")
  pprint.pprint(categories)

#-------------------------------------------------------------------------------
def check_dupes():
  """
  Internal test, check for duplicated heuristics.
  """
  heurs = Counter()
  for heur in HEURISTICS:
    if "name" not in heur:
      print("No 'name' field in heuristic!")
      print(heur)
      assert "name" in dir(heur)

    tmp = heur["name"]
    heurs[tmp] += 1

  dups = []
  for key in heurs:
    if heurs[key] > 1:
      dups.append([key, heurs[key]])

  print("Dups:")
  pprint.pprint(dups)

#-------------------------------------------------------------------------------
def check_heuristic_in_sql():
  """
  Internal test, verify that SQL heuristics look correct.
  """
  heurs = set()
  excluded = ["Equal assembly or pseudo-code", "All or most attributes"]
  for heur in HEURISTICS:
    tmp = heur["name"]
    if tmp in excluded:
      continue

    sql = heur["sql"]
    print(tmp)
    if sql.lower().find(tmp.lower()) == -1:
      print(f"SQL command not correctly associated to ${NAME}")
      print(sql)
      assert sql.find(tmp) != -1

    if sql.find("%POSTFIX%") == -1:
      print("SQL command does not contain the %POSTFIX%")
      print(sql)

    heurs.add(tmp)

  print("Heuristics:")
  pprint.pprint(heurs)

#-------------------------------------------------------------------------------
def check_heuristics_ratio():
  """
  Internal test, verify the heuristics with ratios and count all heuristics for
  each category.
  """
  ratios = Counter()
  for heur in HEURISTICS:
    if "ratio" not in heur:
      print("No 'ratio' in heuristic!")
      print(heur)
      assert "ratio" in heur

    ratio = heur["ratio"]
    ratios[ratio] += 1

  print("Ratios:")
  pprint.pprint(ratios)

  assert ratios == Counter({1: 22, 2: 22, 0: 5, 3: 1})

#-------------------------------------------------------------------------------
def check_mandatory_fields():
  """
  Internal test, verify that the mandatory fields are specified in any and all
  the heuristics.
  """
  mandatory = set(["name", "ratio", "category", "sql", "flags"])
  for heur in HEURISTICS:
    for field in mandatory:
      if field not in list(heur.keys()):
        print(f"Field ${field} not found in heuristic!")
        print(heur)
        assert field in list(heur.keys())

#-------------------------------------------------------------------------------
def check_field_names():
  """
  Internal test, verify that there isn't any unknown field set for any and all
  the heuristics.
  """
  expected = set(["name", "ratio", "category", "min", "sql", "flags"])
  fields = set()
  for heur in HEURISTICS:
    for field in list(heur.keys()):
      if field not in expected:
        print(f"Invalid field ${field} found for heuristic!")
        print(heur)
        assert field in expected

      if heur["ratio"] == HEUR_TYPE_RATIO_MAX:
        if "min" not in heur:
          print("Heuristic of type HEUR_TYPE_RATIO_MAX without a minimum value set!")
          print(heur)
          assert "min" in dir(heur)

      fields.add(field)

  pprint.pprint(fields)

#-------------------------------------------------------------------------------
def run_tests():
  """
  Run the internal tests to verify that the heuristics look correct.
  """
  print("Running tests...\n")
  check_categories()
  print("")
  check_dupes()
  print("")
  check_heuristic_in_sql()
  print("")
  check_heuristics_ratio()
  print("")
  check_field_names()
  print("")
  check_mandatory_fields()
  print("\nAll tests run OK!")

if __name__ == "__main__":
  run_tests()
