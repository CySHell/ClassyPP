import binaryninja as bn
from typing import List


def detect(bv: bn.binaryview):
    for func in bv.functions:
        for instr in func.hlil.instructions:
            # <HighLevelILOperation.HLIL_ASSIGN: 17>
            if instr.operation == 17:
                # Check if Arg1 is being assigned to.
                func_params = func.hlil.source_function.parameter_vars.vars
                if func_params and instr.vars:
                    if func_params[0] == instr.vars[0]:
                        # <HighLevelILOperation.HLIL_CONST_PTR: 27>
                        if instr.operands[1].operation == 27:
                            # <HighLevelILOperation.HLIL_DEREF: 23> De-referencing the pointer, meaning if this
                            # pointer is to a struct, this is de-referencing offset 0x0.
                            if instr.operands[0].operation == 23:
                                if type(instr.operands[0].operands[0]) == bn.highlevelil.HighLevelILVar:
                                    pointer: int = instr.operands[1].operands[0]
                                    data_refs = list(bv.get_data_refs_from(pointer))
                                    if data_refs:
                                        if len(data_refs) != 1:
                                            # print(f'Error, too many data refs for {pointer}')
                                            pass
                                        else:
                                            # Check if this is a function pointer
                                            if bv.get_function_at(data_refs[0]):
                                                constructor_addr: List[
                                                    bn.function.Function] = bv.get_functions_containing(instr.address)
                                                if len(constructor_addr) == 1:
                                                    print(
                                                        f'Suspected constructor at - {hex(constructor_addr[0].start)},'
                                                        f' vfTable address is - {hex(pointer)}')
                                else:
                                    # print(f'Error in instruction {instr}')
                                    pass
