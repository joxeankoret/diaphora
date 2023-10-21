#!/usr/bin/python3

"""
Diaphora database schema support
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

#-------------------------------------------------------------------------------
# List of indices to be created
INDICES = [
  ["functions", "bytes_hash"],
  ["functions", "pseudocode"],
  ["functions", "name"],
  ["functions", "mangled_function"],
  ["functions", "assembly, pseudocode"],
  ["functions", "nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree"],
  ["functions", "instructions, mnemonics, names"],
  ["functions", "nodes, edges, cyclomatic_complexity"],
  ["functions", "cyclomatic_complexity"],
  ["functions", "pseudocode_lines, pseudocode_primes"],
  ["functions", "names, mnemonics"],
  ["functions", "pseudocode_hash2"],
  ["functions", "pseudocode_hash3"],
  ["functions", "pseudocode_hash1, pseudocode_hash2, pseudocode_hash3"],
  ["functions", "strongly_connected"],
  ["functions", "strongly_connected_spp"],
  ["functions", "loops"],
  ["functions", "rva"],
  ["functions", "tarjan_topological_sort"],
  ["functions", "mnemonics_spp"],
  ["functions", "clean_assembly"],
  ["functions", "clean_pseudo"],
  ["functions", "switches"],
  ["functions", "function_hash"],
  ["functions", "md_index"],
  ["functions", "kgh_hash"],
  ["functions", "constants_count, constants"],
  ["functions", "md_index, constants_count, constants"],
  ["functions", "address"],
  ["functions", "microcode_spp"],
  ["functions", "microcode"],
  ["instructions", "address"],
  ["bb_relations", "parent_id, child_id"],
  ["bb_instructions", "basic_block_id, instruction_id"],
  ["function_bblocks", "function_id, basic_block_id"],
  ["constants", "constant, func_id"],
  ["callgraph", "func_id"],
  ["compilation_units", "pseudocode_primes"],
  ["compilation_units", "name"],
  ["compilation_unit_functions", "func_id"],
  ["compilation_unit_functions", "cu_id"]
]

# SQL commands to create the required tables
TABLES = [
  """ create table if not exists functions (
                          id integer primary key,
                          name varchar(255),
                          address text unique,
                          nodes integer,
                          edges integer,
                          indegree integer,
                          outdegree integer,
                          size integer,
                          instructions integer,
                          mnemonics text,
                          names text,
                          prototype text,
                          cyclomatic_complexity integer,
                          primes_value text,
                          comment text,
                          mangled_function text,
                          bytes_hash text,
                          pseudocode text,
                          pseudocode_lines integer,
                          pseudocode_hash1 text,
                          pseudocode_primes text,
                          function_flags integer,
                          assembly text,
                          prototype2 text,
                          pseudocode_hash2 text,
                          pseudocode_hash3 text,
                          strongly_connected integer,
                          loops integer,
                          rva text unique,
                          tarjan_topological_sort text,
                          strongly_connected_spp text,
                          clean_assembly text,
                          clean_pseudo text,
                          mnemonics_spp text,
                          switches text,
                          function_hash text,
                          bytes_sum integer,
                          md_index text,
                          constants text,
                          constants_count integer,
                          segment_rva text,
                          assembly_addrs text,
                          kgh_hash text,
                          source_file text,
                          userdata text,
                          microcode text,
                          clean_microcode text,
                          microcode_spp text,
                          export_time real) """,
  """ create table if not exists program (
                  id integer primary key,
                  callgraph_primes text,
                  callgraph_all_primes text,
                  processor text,
                  md5sum text
                ) """,
  """ create table if not exists program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                )""",
  """ create table if not exists version (value text) """,
  """ create table if not exists instructions (
                  id integer primary key,
                  func_id integer not null,
                  address text,
                  disasm text,
                  mnemonic text,
                  comment1 text,
                  comment2 text,
                  operand_names text,
                  name text,
                  type text,
                  pseudocomment text,
                  pseudoitp integer,
                  asm_type text) """,
  """ create table if not exists basic_blocks (
                  id integer primary key,
                  num integer,
                  address text,
                  asm_type text)""",
  """ create table if not exists bb_relations (
                  id integer primary key,
                  parent_id integer not null references basic_blocks(id) ON DELETE CASCADE,
                  child_id integer not null references basic_blocks(id) ON DELETE CASCADE)""",
  """ create table if not exists bb_instructions (
                  id integer primary key,
                  basic_block_id integer references basic_blocks(id) on delete cascade,
                  instruction_id integer references instructions(id) on delete cascade)""",
  """ create table if not exists function_bblocks (
                  id integer primary key,
                  function_id integer not null references functions(id) on delete cascade,
                  basic_block_id integer not null references basic_blocks(id) on delete cascade,
                  asm_type text)""",
  """create table if not exists callgraph (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  address text not null,
                  type text not null)""",
  """create table if not exists constants (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  constant text not null)""",
  """ create table if not exists compilation_units (
                  id integer primary key,
                  name text,
                  functions int,
                  primes_value text,
                  pseudocode_primes text,
                  start_ea text unique,
                  end_ea text)""",
  """ create table if not exists compilation_unit_functions (
                  id integer primary key,
                  cu_id integer not null references compilation_units(id) on delete cascade,
                  func_id integer not null references functions(id) on delete cascade)"""
]
