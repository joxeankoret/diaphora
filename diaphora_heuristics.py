#!/usr/bin/python3

"""
Diaphora, a diffing plugin for IDA
Copyright (c) 2015-2021, Joxean Koret

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
# Use only for heuristics generating 1.0 ratios, results without false positives
HEUR_TYPE_NO_FPS = 0

# Use it for most heuristics; it will assign 1.0 ratios to the best chooser, 
# values between 0.5 and <1.0 to the specific partial chooser and <0.5 results
# to the unreliable chooser, if specified.
HEUR_TYPE_RATIO = 1

# Similar as before, but partial results are only assigned for matches with a
# min specified ratio.
HEUR_TYPE_RATIO_MAX = 2

#-------------------------------------------------------------------------------
HEUR_FLAG_NONE        = 0
HEUR_FLAG_UNRELIABLE  = 1
HEUR_FLAG_SLOW        = 2

#-------------------------------------------------------------------------------
HEURISTICS = []

HEURISTICS.append({
  "name":"Same RVA and hash",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Same RVA and hash' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where (df.rva = f.rva
                 or df.segment_rva = f.segment_rva)
               and df.bytes_hash = f.bytes_hash
               and df.instructions = f.instructions
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same order and hash",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Same order and hash' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where df.id = f.id
               and df.bytes_hash = f.bytes_hash
               and df.instructions = f.instructions
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))
               and ((f.nodes > 1 and df.nodes > 1
                 and f.instructions > 5 and df.instructions > 5)
                  or f.instructions > 10 and df.instructions > 10)""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Function Hash",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Function Hash' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where f.function_hash = df.function_hash 
               and ((f.nodes > 1 and df.nodes > 1
                 and f.instructions > 5 and df.instructions > 5)
                  or f.instructions > 10 and df.instructions > 10)""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Bytes hash and names",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":"""  select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Bytes hash and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    cast(f.md_index as real) md1, cast(df.md_index as real) md2
                from functions f,
                     diff.functions df
               where f.bytes_hash = df.bytes_hash
                 and f.names = df.names
                 and f.names != '[]'
                 and f.instructions > 5 and df.instructions > 5""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Bytes hash",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Bytes hash' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where f.bytes_hash = df.bytes_hash
               and f.instructions > 5 and df.instructions > 5""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Bytes sum",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Bytes sum' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where f.bytes_sum = df.bytes_sum
               and f.size = df.size
               and f.mnemonics = df.mnemonics
               and f.instructions > 5 and df.instructions > 5""",
  "flags":HEUR_FLAG_UNRELIABLE
})

HEURISTICS.append({
  "name":"Equal assembly or pseudo-code",
  "category":"Best",
  "ratio":HEUR_TYPE_NO_FPS,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal pseudo-code' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.pseudocode = df.pseudocode
        and df.pseudocode is not null
        and f.pseudocode_lines >= 5
        and f.name not like 'nullsub%'
        and df.name not like 'nullsub%'
        %POSTFIX%
      union
     select f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal pseudo-code' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.assembly = df.assembly
        and df.assembly is not null
        and f.instructions >= 4 and df.instructions >= 4
        and f.name not like 'nullsub%'
        and df.name not like 'nullsub%'
        %POSTFIX% """,
  "flags":HEUR_FLAG_NONE|HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Same address and mnemonics",
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Same address and mnemonics' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where df.address = f.address
               and df.mnemonics = f.mnemonics
               and df.instructions = f.instructions
               and df.instructions > 5
               and ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                 or (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same cleaned up assembly",
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Same cleaned up assembly' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.clean_assembly = df.clean_assembly
         and f.nodes > 3 and df.nodes > 3
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%'""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same cleaned pseudo-code",
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Same cleaned pseudo-code' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.clean_pseudo = df.clean_pseudo
         and f.pseudocode_lines > 5 and df.pseudocode_lines > 5
         and f.name not like 'nullsub%'
         and df.name not like 'nullsub%' %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same address, nodes, edges and mnemonics",
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same address, nodes, edges and mnemonics' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.rva = df.rva
        and f.instructions = df.instructions
        and f.nodes = df.nodes
        and f.edges = df.edges
        and f.mnemonics = df.mnemonics
        and f.nodes > 1""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same RVA",
  "category":"Best",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                   'Same RVA' description,
                   f.pseudocode pseudo1, df.pseudocode pseudo2,
                   f.assembly asm1, df.assembly asm2,
                   f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                   f.nodes bb1, df.nodes bb2,
                   cast(f.md_index as real) md1, cast(df.md_index as real) md2
              from functions f,
                   diff.functions df
             where df.rva = f.rva
               %POSTFIX%""",
  "min":0.7,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same constants",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2,
            'Same constants' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.constants = df.constants
        and f.constants_count = df.constants_count
        and f.constants_count > 1 %POSTFIX%""",
  "min":0.5,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same KOKA hash and constants",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Same KOKA hash and constants' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and f.kgh_hash = df.kgh_hash
        and f.nodes > 3 %POSTFIX% """,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same rare KOKA hash",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare KOKA hash' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df,
            (select kgh_hash
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
            ) shared_hashes
      where f.kgh_hash = df.kgh_hash
        and df.kgh_hash = shared_hashes.kgh_hash
        and f.nodes > 5 %POSTFIX% """,
  "min":0.45,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same rare MD Index",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare MD Index' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df,
            (select md_index
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
            ) shared_mds
      where f.md_index = df.md_index
        and df.md_index = shared_mds.md_index
        and f.nodes > 10 %POSTFIX% """,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same address and rare constant",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Same address and rare constant' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and df.address = f.address""",
  "min":0.5,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same rare constant",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare constant' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from main.constants mc,
            diff.constants dc,
            main.functions  f,
            diff.functions df
      where mc.constant = dc.constant
        and  f.id = mc.func_id
        and df.id = dc.func_id
        and f.nodes > 3 and df.nodes > 3
        and f.constants_count > 0""",
  "min":0.2,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same MD Index and constants",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Same MD Index and constants' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2,
             df.tarjan_topological_sort, df.strongly_connected_spp
        from functions f,
             diff.functions df
       where f.md_index = df.md_index
         and f.md_index > 0
         and f.nodes > 3 and df.nodes > 3
         and ((f.constants = df.constants
         and f.constants_count > 0)) %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"All or most attributes",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2,
            'All attributes' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.nodes = df.nodes 
        and f.edges = df.edges
        and f.indegree = df.indegree
        and f.outdegree = df.outdegree
        and f.size = df.size
        and f.instructions = df.instructions
        and f.mnemonics = df.mnemonics
        and f.names = df.names
        and f.prototype2 = df.prototype2
        and f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.primes_value = df.primes_value
        and f.bytes_hash = df.bytes_hash
        and f.pseudocode_hash1 = df.pseudocode_hash1
        and f.pseudocode_primes = df.pseudocode_primes
        and f.pseudocode_hash2 = df.pseudocode_hash2
        and f.pseudocode_hash3 = df.pseudocode_hash3
        and f.strongly_connected = df.strongly_connected
        and f.loops = df.loops
        and f.tarjan_topological_sort = df.tarjan_topological_sort
        and f.strongly_connected_spp = df.strongly_connected_spp %POSTFIX%
      union 
     select f.address ea, f.name name1, df.address ea2, df.name name2,
            'Most attributes' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
       where f.nodes = df.nodes 
         and f.edges = df.edges
         and f.indegree = df.indegree
         and f.outdegree = df.outdegree
         and f.size = df.size
         and f.instructions = df.instructions
         and f.mnemonics = df.mnemonics
         and f.names = df.names
         and f.prototype2 = df.prototype2
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.primes_value = df.primes_value
         and f.bytes_hash = df.bytes_hash
         and f.strongly_connected = df.strongly_connected
         and f.loops = df.loops
         and f.tarjan_topological_sort = df.tarjan_topological_sort
         and f.strongly_connected_spp = df.strongly_connected_spp 
         %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Switch structures",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Switch structures' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.switches = df.switches
        and df.switches != '[]'
        and f.nodes > 5 and df.nodes > 5
        %POSTFIX%""",
  "min": 0.5,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Same address, nodes, edges and primes (re-ordered instructions)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2,
            'Same address, nodes, edges and primes (re-ordered instructions)' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.rva = df.rva
        and f.instructions = df.instructions
        and f.nodes = df.nodes
        and f.edges = df.edges
        and f.primes_value = df.primes_value
        and f.nodes > 3 %POSTFIX%""",
  "min":0.5,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Import names hash",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Import names hash' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.names = df.names
         and f.names != '[]'
         and f.md_index = df.md_index
         and f.instructions = df.instructions
         and f.nodes > 5 and df.nodes > 5 %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Nodes, edges, complexity, mnemonics, names, prototype, in-degree and out-degree",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Nodes, edges, complexity, mnemonics, names, prototype, in-degree and out-degree' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2,
                     cast(f.md_index as real) md1, cast(df.md_index as real) md2
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.names = df.names
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.prototype2 = df.prototype2
                 and f.indegree = df.indegree
                 and f.outdegree = df.outdegree
                 and f.nodes > 3
                 and f.edges > 3
                 and f.names != '[]'
                 %POSTFIX%
               union
              select f.address ea, f.name name1, df.address ea2, df.name name2,
                     'Nodes, edges, complexity, mnemonics, names and prototype' description,
                     f.pseudocode pseudo1, df.pseudocode pseudo2,
                     f.assembly asm1, df.assembly asm2,
                     f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                     f.nodes bb1, df.nodes bb2,
                     cast(f.md_index as real) md1, cast(df.md_index as real) md2
                from functions f,
                     diff.functions df
               where f.nodes = df.nodes
                 and f.edges = df.edges
                 and f.mnemonics = df.mnemonics
                 and f.names = df.names
                 and f.names != '[]'
                 and f.cyclomatic_complexity = df.cyclomatic_complexity
                 and f.prototype2 = df.prototype2
                 %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Mnemonics and names",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select f.address ea, f.name name1, df.address ea2, df.name name2,
             'Mnemonics and names' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.mnemonics = df.mnemonics
         and f.instructions = df.instructions
         and f.names = df.names
         and f.names != '[]'
         and f.instructions > 5 and df.instructions > 5
         %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Pseudo-code fuzzy (normal)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy (normal)' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where df.pseudocode_hash1 = f.pseudocode_hash1
        and f.instructions > 5 and df.instructions > 5 """,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Pseudo-code fuzzy (mixed)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy (mixed)' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where df.pseudocode_hash3 = f.pseudocode_hash3
        and f.instructions > 5 and df.instructions > 5 """,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Pseudo-code fuzzy (reverse)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy (reverse)' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where df.pseudocode_hash2 = f.pseudocode_hash2
        and f.instructions > 5 and df.instructions > 5 """,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Pseudo-code fuzzy hash",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy hash' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where df.pseudocode_hash1 = f.pseudocode_hash1
        and df.pseudocode_hash2 = f.pseudocode_hash2
        and df.pseudocode_hash3 = f.pseudocode_hash3
        and f.instructions > 5
        and df.instructions > 5 """,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Similar pseudo-code and names",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar pseudo-code and names' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.pseudocode_lines = df.pseudocode_lines
        and f.names = df.names
        and df.names != '[]'
        and df.pseudocode_lines > 5
        and df.pseudocode is not null 
        and f.pseudocode is not null
        %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Pseudo-code fuzzy AST hash",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy AST hash' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where df.pseudocode_primes = f.pseudocode_primes
        and f.pseudocode_lines > 3
        and length(f.pseudocode_primes) >= 35
        %POSTFIX%""",
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Partial pseudo-code fuzzy hash (normal)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Partial pseudo-code fuzzy hash (normal)' description,
              f.pseudocode pseudo1, df.pseudocode pseudo2,
              f.assembly asm1, df.assembly asm2,
              f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
              f.nodes bb1, df.nodes bb2,
              cast(f.md_index as real) md1, cast(df.md_index as real) md2
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
          and f.nodes > 5 and df.nodes > 5""",
  "min":0.5,
  "flags":HEUR_FLAG_SLOW
})


HEURISTICS.append({
  "name":"Partial pseudo-code fuzzy hash (reverse)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Partial pseudo-code fuzzy hash (reverse)' description,
              f.pseudocode pseudo1, df.pseudocode pseudo2,
              f.assembly asm1, df.assembly asm2,
              f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
              f.nodes bb1, df.nodes bb2,
              cast(f.md_index as real) md1, cast(df.md_index as real) md2
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
          and f.nodes > 5 and df.nodes > 5""",
  "min":0.5,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Partial pseudo-code fuzzy hash (mixed)",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Partial pseudo-code fuzzy hash (mixed)' description,
              f.pseudocode pseudo1, df.pseudocode pseudo2,
              f.assembly asm1, df.assembly asm2,
              f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
              f.nodes bb1, df.nodes bb2,
              cast(f.md_index as real) md1, cast(df.md_index as real) md2
         from functions f,
              diff.functions df
        where substr(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)
          and f.nodes > 5 and df.nodes > 5""",
  "min":0.5,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Strongly connected components small-primes-product",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components small-primes-product' description,
              f.pseudocode pseudo1, df.pseudocode pseudo2,
              f.assembly asm1, df.assembly asm2,
              f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
              f.nodes bb1, df.nodes bb2,
              cast(f.md_index as real) md1, cast(df.md_index as real) md2
         from functions f,
              diff.functions df
        where f.strongly_connected_spp = df.strongly_connected_spp
          and df.strongly_connected_spp > 1
          and f.nodes > 10 and df.nodes > 10
          %POSTFIX%""",
  "flags":HEUR_FLAG_NONE|HEUR_FLAG_UNRELIABLE
})

HEURISTICS.append({
  "name":"Loop count",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Loop count' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.loops = df.loops
        and df.loops > 1
        and f.nodes > 3 and df.nodes > 3
        %POSTFIX%""",
  "min":0.49,
  "flags":HEUR_FLAG_SLOW
})


HEURISTICS.append({
  "name":"Mnemonics small-primes-product",
  "category":"Partial",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select f.address ea, f.name name1, df.address ea2, df.name name2,
             'Mnemonics small-primes-product' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.mnemonics_spp = df.mnemonics_spp
         and f.instructions = df.instructions
         and f.nodes > 1 and df.nodes > 1
         and df.instructions > 5 %POSTFIX% """,
  "min":0.6,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Similar pseudo-code",
  "category":"Experimental",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar pseudo-code' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.pseudocode_lines = df.pseudocode_lines
        and df.pseudocode_lines > 5
        and df.pseudocode is not null 
        and f.pseudocode is not null
        %POSTFIX%""",
  "min":0.6,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same nodes, edges and strongly connected components",
  "category":"Experimental",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2,
            'Same nodes, edges and strongly connected components' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.nodes = df.nodes
        and f.edges = df.edges
        and f.strongly_connected = df.strongly_connected
        and f.nodes > 5 and df.nodes > 5
        %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Small pseudo-code fuzzy AST hash",
  "category":"Experimental",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Small pseudo-code fuzzy AST hash' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where df.pseudocode_primes = f.pseudocode_primes
        and f.pseudocode_lines <= 5""",
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Same low complexity, prototype and names",
  "category":"Experimental",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""  select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same low complexity, prototype and names' description,
              f.pseudocode pseudo1, df.pseudocode pseudo2,
              f.assembly asm1, df.assembly asm2,
              f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
              f.nodes bb1, df.nodes bb2,
              cast(f.md_index as real) md1, cast(df.md_index as real) md2
         from functions f,
              diff.functions df
        where f.names = df.names
          and f.cyclomatic_complexity = df.cyclomatic_complexity
          and f.cyclomatic_complexity < 20
          and f.prototype2 = df.prototype2
          and df.names != '[]'
          %POSTFIX%""",
  "min":0.5,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same low complexity and names",
  "category":"Experimental",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same low complexity and names' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.names = df.names
        and f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.cyclomatic_complexity < 15
        and df.names != '[]'
        %POSTFIX%""",
  "min":0.5,
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Same graph",
  "category":"Experimental",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select f.address ea, f.name name1, df.address ea2, df.name name2,
             'Same graph' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
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
         %POSTFIX%
         and f.nodes > 5 and df.nodes > 5
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
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Topological sort hash",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2,
            'Topological sort hash' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.strongly_connected = df.strongly_connected
        and f.tarjan_topological_sort = df.tarjan_topological_sort
        and f.strongly_connected > 3
        and f.nodes > 10
        %POSTFIX%""",
  "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
  "name":"Strongly connected components SPP and names",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":""" select f.address ea, f.name name1, df.address ea2, df.name name2,
             'Strongly connected components SPP and names' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.names = df.names
         and f.names != '[]'
         and f.strongly_connected_spp = df.strongly_connected_spp
         and f.strongly_connected_spp > 0
         and f.nodes > 5 and df.nodes > 5 """,
  "min":0.49,
  "flags":HEUR_FLAG_UNRELIABLE
})

HEURISTICS.append({
  "name":"Strongly connected components",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO_MAX,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.strongly_connected = df.strongly_connected
        and df.strongly_connected > 1
        and f.nodes > 5 and df.nodes > 5
        and f.strongly_connected_spp > 1
        and df.strongly_connected_spp > 1
        %POSTFIX%""",
  "min":0.8,
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Nodes, edges, complexity and mnemonics",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Nodes, edges, complexity and mnemonics' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.mnemonics = df.mnemonics
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 1 and f.edges > 0
         %POSTFIX%""",
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Nodes, edges, complexity and prototype",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Nodes, edges, complexity and prototype' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.prototype2 = df.prototype2
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.prototype2 != 'int()'
         %POSTFIX%""",
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Nodes, edges, complexity, in-degree and out-degree",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Nodes, edges, complexity, in-degree and out-degree' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 3 and f.edges > 2
         and f.indegree = df.indegree
         and f.outdegree = df.outdegree
         %POSTFIX%""",
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Nodes, edges and complexity",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":""" select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
             'Nodes, edges and complexity' description,
             f.pseudocode pseudo1, df.pseudocode pseudo2,
             f.assembly asm1, df.assembly asm2,
             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
             f.nodes bb1, df.nodes bb2,
             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        from functions f,
             diff.functions df
       where f.nodes = df.nodes
         and f.edges = df.edges
         and f.cyclomatic_complexity = df.cyclomatic_complexity
         and f.nodes > 1 and f.edges > 0
         %POSTFIX%""",
  "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
  "name":"Same high complexity",
  "category":"Unreliable",
  "ratio":HEUR_TYPE_RATIO,
  "sql":"""select f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity' description,
            f.pseudocode pseudo1, df.pseudocode pseudo2,
            f.assembly asm1, df.assembly asm2,
            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
            f.nodes bb1, df.nodes bb2,
            cast(f.md_index as real) md1, cast(df.md_index as real) md2
       from functions f,
            diff.functions df
      where f.cyclomatic_complexity = df.cyclomatic_complexity
        and f.cyclomatic_complexity >= 50
        %POSTFIX%""",
  "flags":HEUR_FLAG_SLOW
})

#-------------------------------------------------------------------------------
def check_categories():
  categories = set()
  for heur in HEURISTICS:
    category = heur["category"]
    categories.add(category)

  print("Categories:")
  import pprint
  pprint.pprint(categories)

#-------------------------------------------------------------------------------
def check_dupes():
  from collections import Counter
  heurs = Counter()
  for heur in HEURISTICS:
    if "name" not in heur:
      print("No 'name' field in heuristic!")
      print(heur)
      assert(name in heur)

    name = heur["name"]
    heurs[name] += 1

  dups = []
  for key in heurs:
    if heurs[key] > 1:
      dups.append([key, heurs[key]])
  
  print("Dups:")
  import pprint
  pprint.pprint(dups)
  
  
#-------------------------------------------------------------------------------
def check_heuristic_in_sql():
  heurs = set()
  excluded = ["Equal assembly or pseudo-code", "All or most attributes"]
  for heur in HEURISTICS:
    name = heur["name"]
    if name in excluded:
      continue

    sql = heur["sql"]
    if sql.lower().find(name.lower()) == -1:
      print(("SQL command not correctly associated to %s" % repr(name)))
      print(sql)
      assert(sql.find(name) != -1)

    heurs.add(name)

  print("Heuristics:")
  import pprint
  pprint.pprint(heurs)

#-------------------------------------------------------------------------------
def check_heuristics_ratio():
  from collections import Counter
  ratios = Counter()
  for heur in HEURISTICS:
    if "ratio" not in heur:
      print("No 'ratio' in heuristic!")
      print(heur)
      assert("ratio" in heur)

    ratio = heur["ratio"]
    ratios[ratio] += 1
  
  print("Ratios:")
  import pprint
  pprint.pprint(ratios)
  
  assert(ratios == Counter({1: 26, 2: 18, 0: 7}))

#-------------------------------------------------------------------------------
def check_mandatory_fields():
  mandatory = set(["name", "ratio", "category", "sql", "flags"])
  for heur in HEURISTICS:
    for field in mandatory:
      if field not in list(heur.keys()):
        print(("Field '%s' not found in heuristic!" % field))
        print(heur)
        assert(field in list(heur.keys()))

#-------------------------------------------------------------------------------
def check_field_names():
  expected = set(["name", "ratio", "category", "min", "sql", "flags"])
  fields = set()
  for heur in HEURISTICS:
    for field in list(heur.keys()):
      if field not in expected:
        print(("Invalid field '%s' found for heuristic!" % field))
        print(heur)
        assert(field in expected)
      
      if heur["ratio"] == HEUR_TYPE_RATIO_MAX:
        if "min" not in heur:
          print("Heuristic of type HEUR_TYPE_RATIO_MAX without a minimum value set!")
          print(heur)
          assert("min" in heur)

      fields.add(field)

  import pprint
  pprint.pprint(fields)

#-------------------------------------------------------------------------------
def run_tests():
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

