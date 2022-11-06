import binaryninja as bn
from typing import List
from ... import Config
from ...RttiInfomation.VirtualTableInference import VirtualFunctionTable
import pysnooper


def GetVirtualTableAssignmentInstruction(func: bn.function.Function):
    current_candidate_instr = None
    for instr in func.hlil.instructions:
        # <HighLevelILOperation.HLIL_ASSIGN: 17>
        if instr.operation == 17:
            # Check if Arg1 is being assigned to.
            func_params = func.hlil.source_function.parameter_vars.vars
            if func_params and instr.vars:
                if func_params[0] == instr.vars[0]:
                    # <HighLevelILOperation.HLIL_CONST_PTR: 27>, <HighLevelILOperation.HLIL_CONST: 26>
                    if instr.operands[1].operation == 27 or instr.operands[1].operation == 26:
                        # <HighLevelILOperation.HLIL_DEREF: 23>
                        # <HighLevelILOperation.HLIL_DEREF_FIELD: 24>
                        # De-referencing the pointer, meaning if this
                        # pointer is to a struct, this is de-referencing offset 0x0.
                        if instr.operands[0].operation == 23 or instr.operands[0].operation == 24:
                            if type(instr.operands[0].operands[0]) == bn.highlevelil.HighLevelILVar:
                                current_candidate_instr = instr

    # We are only interested in the last assignment of a vfTable in a function, since the ones before it are
    # base classes.
    # [
    return current_candidate_instr


def GetPotentialConstructors(bv: bn.binaryview, vfTable_addr: int) -> \
        List[bn.function.Function]:
    # Each function that references the vfTable address has the potential to be the constructor function.
    # MSVC does not place the constructor (at least for 99% of use cases) address inside the vfTable, we can
    # infer that if a function references the vfTable but is contained within the table then it is not a constructor
    # and probably is a destructor.
    # TODO: Try to define destructors as well.
    potential_constructors: List[bn.function.Function] = []
    for code_ref in bv.get_code_refs(vfTable_addr):
        func_containing_code_ref = code_ref.function
        if func_containing_code_ref.start not in VirtualFunctionTable.global_functions_contained_in_all_vfTables:
            potential_constructors.append(func_containing_code_ref)
    return potential_constructors


def DetectConstructorForVTable(bv: bn.binaryview, vfTable_addr: int, vfTable_contained_functions: List[int]) -> bool:
    found_constructors = 0
    potential_constructors: List[bn.function.Function] = GetPotentialConstructors(bv, vfTable_addr)
    for potential_constructor in potential_constructors:
        if VerifyConstructor(bv, potential_constructor, found_constructors):
            print(f'ClassyPP: Found constructor - {potential_constructor.name}')
            found_constructors += 1
    return found_constructors != 0


def IsDestructor(bv: bn.binaryview, potential_destructor: bn.function.Function) -> bool:
    # The heuristic for determining a destructor is very primitive - if it contains the delete or ~ operator in
    # one of the function it calls then we determine its a destructor.
    # TODO: Find a better heuristic for finding destructors.
    destructor_name_hints: List[str] = ["delete", "Delete", "~", "destroy", "Destroy"]
    for callee in potential_destructor.callees:
        for destructor_name_hint in destructor_name_hints:
            if destructor_name_hint in callee.name:
                return True
    return False


def VerifyConstructor(bv: bn.binaryview, potential_constructor: bn.function.Function, found_constructors: int) -> bool:
    # The heuristics used here will locate both the constructors and desctructors.
    # It is not easy to automatically distinguish between the two.
    func_type = "Constructor"
    try:
        if instr := GetVirtualTableAssignmentInstruction(potential_constructor):
            pointer: int = instr.operands[1].operands[0]
            data_refs = list(bv.get_data_refs_from(pointer))
            if data_refs:
                if len(data_refs) != 1:
                    # print(f'Error, too many data refs for {pointer}')
                    pass
                else:
                    # Check if this is a function pointer
                    if bv.get_function_at(data_refs[0]):
                        class_name: str = bv.get_data_var_at(pointer).name
                        if class_name.endswith("_vfTable"):
                            # Remove the _vfTable tag from the name
                            class_name = class_name[:-8]
                        if IsDestructor(bv, potential_constructor):
                            func_type = "Destructor"
                        if Config.CONSTRUCTOR_FUNCTION_HANDLING == 0:
                            AddComment(bv, potential_constructor.start, pointer,
                                       class_name, func_type)
                        elif Config.CONSTRUCTOR_FUNCTION_HANDLING == 1:
                            ChangeFuncName(bv, potential_constructor.start, found_constructors,
                                           class_name, func_type)
                        else:
                            # invalid choice
                            return False
                        return True
        else:
            # print(f'Error in instruction {instr}')
            return False
    except Exception as e:
        print(f"Constructor Detection encountered an error in {potential_constructor.start}! Exception: {e}")
        return False


def AddComment(bv: bn.binaryview, constructor_addr: int, vtable_addr: int, class_name: str, func_type: str):
    bv.set_comment_at(constructor_addr, f"Suspected {func_type} function for class {class_name}, virtual table"
                                        f"at {hex(vtable_addr)}")


def ChangeFuncName(bv: bn.binaryview, constructor_addr: int, found_constructors: int, class_name: str,
                   func_type: str):
    bv.get_function_at(constructor_addr).name = f"{class_name}::{func_type}_{found_constructors}"
