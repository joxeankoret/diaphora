from typing import Any, Callable, List

NATIVE = "native"
MICROCODE = "microcode"


class InsertInto:
    """All queries related to the export of information on individual functions
    """
    def __execute(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        table: str,
        column_names: str,
        column_defaults: str,
        column_values: List[Any],
    ) -> None:
        cur_execute(
            f"insert into {table} ({column_names}) values ({column_defaults})",
            column_values,
        )

    def main_instructions(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
        obj_type: str = NATIVE,
    ) -> None:
        table = "main.instructions"
        if obj_type == NATIVE:
            column_names = (
                "address, mnemonic, disasm, comment1, "
                "comment2, operand_names, name, type, "
                "pseudocomment, "
                "pseudoitp, "
                "func_id, asm_type"
            )
            column_defaults = "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'native'"
        elif obj_type == MICROCODE:
            column_names = (
                "address, mnemonic, disasm, comment1, "
                "pseudocomment, "
                "func_id, asm_type"
            )
            column_defaults = "?, ?, ?, ?, ?, ?, 'microcode'"
        else:
            raise ValueError(f"Unknown type '{obj_type}'")
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def main_basic_blocks(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
        obj_type: str = NATIVE,
    ) -> None:
        table = "main.basic_blocks"
        if obj_type in {NATIVE, MICROCODE}:
            column_names = "num, address, asm_type"
            column_defaults = f"?, ?, '{obj_type}'"
        else:
            raise ValueError(f"Unknown type '{obj_type}'")
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def main_bb_instructions(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
        obj_type: str = NATIVE,
    ) -> None:
        table = "main.bb_instructions"
        column_names = "basic_block_id, instruction_id"
        column_defaults = "?, ?"
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def main_bb_relations(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
        obj_type: str = NATIVE,
    ) -> None:
        table = "main.bb_relations"
        column_names = "parent_id, child_id"
        column_defaults = "?, ?"
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def main_function_bblocks(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
        obj_type: str = NATIVE,
    ) -> None:
        table = "main.function_bblocks"
        if obj_type in {NATIVE, MICROCODE}:
            column_names = "function_id, basic_block_id, asm_type"
            column_defaults = f"?, ?, '{obj_type}'"
        else:
            raise ValueError(f"Unknown type '{obj_type}'")
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def main_functions(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
    ) -> None:
        table = "main.functions"
        column_names = (
            "name, nodes, edges, indegree, outdegree, size, "
            "instructions, mnemonics, names, prototype, "
            "cyclomatic_complexity, primes_value, address, "
            "comment, mangled_function, bytes_hash, pseudocode, "
            "pseudocode_lines, pseudocode_hash1, pseudocode_primes, "
            "function_flags, assembly, prototype2, pseudocode_hash2, "
            "pseudocode_hash3, strongly_connected, loops, rva, "
            "tarjan_topological_sort, strongly_connected_spp, "
            "clean_assembly, clean_pseudo, mnemonics_spp, switches, "
            "function_hash, bytes_sum, md_index, constants, "
            "constants_count, segment_rva, assembly_addrs, kgh_hash, "
            "source_file, userdata, microcode, clean_microcode, "
            "microcode_spp"
        )
        column_defaults = (
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
        )
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def callgraph(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
    ) -> None:
        table = "callgraph"
        column_names = "func_id, address, type"
        column_defaults = "?, ?, ?"
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def constants(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
    ) -> None:
        table = "constants"
        column_names = "func_id, constant"
        column_defaults = "?, ?"
        self.__execute(cur_execute, table, column_names, column_defaults, properties)

    def __template(
        self,
        cur_execute: Callable[[str, List[Any]], None],
        properties: List[Any],
        obj_type: str = NATIVE,
    ) -> None:
        table = ""
        if obj_type == NATIVE:
            column_names = ""
            column_defaults = ""
        elif obj_type == MICROCODE:
            column_names = ""
            column_defaults = ""
        else:
            raise ValueError(f"Unknown type '{obj_type}'")
        self.__execute(cur_execute, table, column_names, column_defaults, properties)
