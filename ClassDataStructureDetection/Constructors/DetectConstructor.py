from re import I
import binaryninja as bn
from typing import *
from ... import Config
from ...RttiInformation.VirtualTableInference import VirtualFunctionTable
from ...Common import Utils

global_constructor_destructor_list: List = list()


def GetAllAssignmentInstructions(func: bn.function.Function) -> Dict:
    """
    Search the given function for all data references assigned to an offset into the pointer given
    in Arg1 of the function (the "This" pointer).
    :return {offset_into_Arg1: [DataVar address]}
    """
    candidate_instructions: Dict = dict()

    try:
        for instr in func.hlil.instructions:
            # <HighLevelILOperation.HLIL_ASSIGN: 17>
            if instr.operation.name == "HLIL_ASSIGN":
                # Check if Arg1 is being assigned to.
                func_params = func.hlil.source_function.parameter_vars.vars
                if func_params and instr.vars:
                    if func_params[0] == instr.vars[0]:
                        if instr.operands[1].operation.name == "HLIL_CONST_PTR" or \
                                instr.operands[1].operation.name == "HLIL_CONST":
                            # A pointer or a constant is being assigned into an offset within Arg1
                            # Example: <HLIL_ASSIGN: *(arg1 + 0x1a000) = &data_140645958>
                            #        <HLIL_DEREF: *(arg1 + 0x1a000)>  <HLIL_CONST_PTR: &data_140645958>
                            if instr.operands[0].operation.name == "HLIL_DEREF" or \
                                    instr.operands[0].operation.name == "HLIL_DEREF_FIELD":
                                if type(instr.operands[0].operands[0]) == bn.highlevelil.HighLevelILVar:
                                    if instr.operands[0].operation.name == "HLIL_ARRAY_INDEX":
                                        # Arg1 is treated as an array and the assignment is being done into
                                        # an offset within the array.
                                        # Example: <HLIL_ARRAY_INDEX: arg1[0x3400]>
                                        #       <HLIL_VAR: arg1>, <HLIL_CONST: 0x3400>
                                        offset_into_class = instr.operands[0].operands[1].operands[0]
                                    else:
                                        # Directly De-referencing the pointer, meaning if this pointer is to a
                                        # struct, this is de-referencing offset 0x0.
                                        offset_into_class = 0

                                    if candidate_instructions.get(offset_into_class):
                                        candidate_instructions[offset_into_class].append(
                                            instr.operands[1].value.value
                                        )
                                    else:
                                        candidate_instructions.update({0: [instr.operands[1].value.value]})

                                elif type(instr.operands[0].operands[0]) == bn.highlevelil.HighLevelILAdd:
                                    # Referencing an offset within the pointer.
                                    # example: <HLIL_ADD: arg1 + 0x1a000>
                                    #       [<HLIL_VAR: arg1>, <HLIL_CONST: 0x1a000>]
                                    if instr.operands[0].operands[0].operands[1].operation.name == "HLIL_CONST":
                                        offset_into_class = instr.operands[0].operands[0].operands[1].value.value
                                        if candidate_instructions.get(offset_into_class):
                                            candidate_instructions[offset_into_class].append(
                                                instr.operands[1].value.value
                                            )
                                        else:
                                            candidate_instructions.update(
                                                {
                                                    offset_into_class: [
                                                        instr.operands[1].value.value
                                                    ]
                                                }
                                            )
                                else:
                                    Utils.LogToFile(f"GetAllAssignmentInstructions: UNKNOWN assignment type at HLIL "
                                                    f"Address {hex(instr.address)} ! please report this. "
                                                    f"\nInstruction: {instr}")
    except Exception as e:
        print(f"GetAllAssignmentInstructions {hex(func.start)}, Exception: {e}")
    # We are only interested in the last assignment of a vfTable in a function, since the ones before it are
    # base classes.
    return candidate_instructions


def GetThisClassVirtualTableAssignmentInstruction(func: bn.function.Function) -> Optional[int]:
    candidate_instructions = GetAllAssignmentInstructions(func)

    # We are only interested in the last assignment of a vfTable in a function, since the ones before it are
    # base classes.
    if candidate_instructions.get(0):
        return candidate_instructions[0][-1]
    else:
        return None

def GetPotentialConstructors(bv: bn.BinaryView, vfTable_addr: int) -> \
        List[bn.function.Function]:
    # Each function that references the vfTable address has the potential to be the constructor function.
    # MSVC does not place the constructor (at least for 99% of use cases) address inside the vfTable, we can
    # infer that if a function references the vfTable but is contained within the table then it is not a constructor
    # and probably is a destructor.
    # TODO: Try to define destructors as well.
    potential_constructors: List[bn.Function] = []
    for code_ref in bv.get_code_refs(vfTable_addr):
        func_containing_code_ref = code_ref.function
        if func_containing_code_ref.start not in VirtualFunctionTable.global_functions_contained_in_all_vfTables:
            potential_constructors.append(func_containing_code_ref)
            
    return potential_constructors

def DetectConstructorForVTable(bv: bn.binaryview, vfTable_addr: int) -> list[bn.function.Function]:
    potential_constructors: List[bn.function.Function] = list()
    for potential_constructor in GetPotentialConstructors(bv, vfTable_addr):
        if VerifyConstructor(bv, potential_constructor):
            potential_constructors.append(potential_constructor)
            print(f'Found constructor - {potential_constructor.name}')
            global_constructor_destructor_list.append(potential_constructor.start)
    return potential_constructors


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

def DefineConstructor(bv: bn.binaryview, potential_constructors: list[bn.function.Function],
                      vtable_addr: int, class_name=None) -> bool:
    # Since several constructors with the same name (but different signature) may exist, we
    # will attach a postfix index to each of the names.
    constructor_index = 0
    if not class_name:
        class_name: str = bv.get_data_var_at(vtable_addr).name
    if class_name:
        class_name = class_name.replace("::vfTable", "")
        for constructor in potential_constructors:
            func_type = "Constructor"
            if IsDestructor(bv, constructor):
                func_type = "Destructor"
            if Config.CONSTRUCTOR_FUNCTION_HANDLING == 0:
                AddComment(bv, constructor.start, vtable_addr,
                           class_name, func_type)
                constructor_index += 1
            elif Config.CONSTRUCTOR_FUNCTION_HANDLING == 1:
                ChangeFuncName(bv, constructor.start, constructor_index,
                               class_name, func_type)
                constructor_index += 1
            else:
                # invalid choice
                return False
        return True
    else:
        print(f"DefineConstructor: Cannot get class name for vtable at {hex(vtable_addr)}")

def VerifyConstructor(bv: bn.binaryview, potential_constructor: bn.function.Function) -> bool:
    # The heuristics used here will locate both the constructors and destructors.
    # It is not easy to automatically distinguish between the two.

    try:
        if pointer := GetThisClassVirtualTableAssignmentInstruction(potential_constructor):
            data_refs = list(bv.get_data_refs_from(pointer))
            if data_refs:
                if len(data_refs) != 1:
                    # print(f'Error, too many data refs for {pointer}')
                    return False
                else:
                    # Check if this is a function pointer
                    if bv.get_function_at(data_refs[0]) is not None:
                        return True
        else:
            # print(f'Error in instruction {instr}')
            return False
    except Exception as e:
        print(f"Constructor Detection encountered an error in {potential_constructor.start}! Exception: {e}")
        return False


def AddComment(bv: bn.binaryview, constructor_addr: int, vtable_addr: int, class_name: str, func_type: str):
    bv.set_comment_at(constructor_addr, f"Suspected {func_type} function for class {class_name}, virtual table"
                                        f" at {hex(vtable_addr)}")


def ChangeFuncName(bv: bn.binaryview, constructor_addr: int, found_constructors: int, class_name: str,
                   func_type: str):
    func = bv.get_function_at(constructor_addr)
    if not func:
        func = bv.create_user_function(constructor_addr)
        print(f'Defined new constructor at {hex(constructor_addr)}')
        bv.update_analysis_and_wait()
    func.name = f"{class_name}::{func_type}{found_constructors:02}"

def IsThunkTo(bv: bn.BinaryView, thunk: bn.Function, constructor: bn.Function) -> bool:
    mlil = thunk.mlil
    if not isinstance(mlil, bn.MediumLevelILFunction):
        return False
    
    instr = list(mlil.instructions)[0]
    if isinstance(instr, bn.MediumLevelILInstruction) and instr.operation == bn.MediumLevelILOperation.MLIL_TAILCALL and isinstance(instr.dest, bn.MediumLevelILConstPtr) and instr.dest.constant == constructor.start:
        return True
    
    return False

def GetConstructorThunks(bv: bn.BinaryView, constructors: List[int]) -> List[Tuple[bn.Function, bn.Function]]:
    thunks: List[Tuple[bn.Function, bn.Function]] = []
    for constructor in constructors:
        for ref in bv.get_code_refs(constructor):
            constructor_func = bv.get_function_at(constructor)
            func = ref.function
            if IsThunkTo(bv, func, constructor_func):
                print(f"detected thunk at {hex(ref.address)}")
                thunks.append((func, constructor_func))
                
    return thunks

def DefineConstructorThunks(bv: bn.BinaryView, thunks: List[Tuple[bn.Function, bn.Function]]):
        thunk: bn.Function
        constructor: bn.Function
        thunks_defined: dict[bn.Function, int] = {}
        
        for (thunk, constructor) in thunks:
            orig_name = constructor.name
            
            name = orig_name.split('::')[::-1][0]
            
            if Config.CONSTRUCTOR_FUNCTION_HANDLING == 1:
                if thunks_defined.get(constructor) is None:
                    thunks_defined[constructor] = 0
                    
                thunk_index = thunks_defined[constructor]
                
                name = orig_name.replace(name, f"Thunk{thunk_index:02}To{name}")
            
                ChangeThunkName(bv, thunk.start, name)
                
                thunks_defined[constructor] += 1

def ChangeThunkName(bv: bn.binaryview, thunk_addr: int, name: str):
    func = bv.get_function_at(thunk_addr)
    if not func:
        func = bv.create_user_function(thunk_addr)
        print(f'Defined new constructor thunk at {hex(thunk_addr)}')
        bv.update_analysis_and_wait()
    func.name = name
