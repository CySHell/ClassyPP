import binaryninja as bn
from typing import List
from ... import Config
from ...RttiInformation.VirtualTableInference import VirtualFunctionTable
from ..Constructors import DetectConstructor
from ...ClassObjectRepresentation import CppClass


def VerifyNonRttiVtable(bv: bn.binaryview, potential_vtable_addr: int) -> bool:
    if potential_vtable_addr in VirtualFunctionTable.global_vfTables:
        return True
    else:
        verified_vtable = VirtualFunctionTable.VFTABLE(bv,
                                                       potential_vtable_addr,
                                                       f"vtable_{str(potential_vtable_addr)}_nonRtti")
        if verified_vtable.verified:
            return True
    return False


def DetectPotentialCandidates(bv: bn.binaryview):
    """
    The general algorithm of this function is this:
    1. Go over all recognized functions in the binaryView.
    1.1 If the function is already defined as a constructor / destructor by the RTTI information then skip it.
    1.2 If the function is verified as a possible constructor / destructor detection algorithm (but was not mentioned
        by the RTTI information) then check all possible vtable assignments in the function.
    2. First, if we have an assignment of a vTable to offset 0 of Arg1 then we assume this is indeed
        a constructor / destructor - vTable is defined as vtable_vTableAddress_nonRtti, and class is defined
        as class_vTableAddress.
    3. Once we found a constructor / destructor then we add all non 0 offsets of Arg1 assignments found in the
        function for further inspection (This is he deffered_vtable_addr list).
        The logic here is that the class may contain vTable assignments of its base or multiple inherited classes,
        and those vTables should also have their own constructors / destructors somewhere else in the file.
    4. Once we searched all functions in the bv, we now iterate the deffered_vtable_addr list to detect which
        of these addresses was later confirmed as a vtable, and accordingly we can add this information to the
        correct class.
    """
    print("Searching for Non-RTTI vTables...")
    deffered_vtable_addr: list = list()
    for func in bv.functions:
        if func.start not in DetectConstructor.global_constructor_destructor_list:
            if DetectConstructor.VerifyConstructor(bv, func, -1):
                print(hex(func.start))
                assignment_instructions = DetectConstructor.GetAllAssignmentInstructions(func)
                # Check if the last assignment into offset 0 of Arg1 in the constructor func is a vTable.
                suspected_vtable: int = assignment_instructions[0][-1]
                class_name: str = CppClass.GenerateClassNameFromVtableAddr(suspected_vtable)
                if VerifyNonRttiVtable(bv, suspected_vtable):
                    if detected_class := CppClass.global_classes.get(class_name):
                        # If the class was already defined then do nothing (for now)
                        # TODO: merge more info into the class based on this newly found constructor.
                        if func.start not in detected_class.constructors:
                            detected_class.constructors.append(func.start)
                    else:
                        detected_class: CppClass.ClassyClass = CppClass.ClassyClass(name=class_name,
                                                                                    vfTable_addr=suspected_vtable,
                                                                                    constructors=[func.start])

                    for class_offset, potential_table_addresses in assignment_instructions.items():

                        for potential_vtable_addr in potential_table_addresses:
                            if potential_vtable_addr in VirtualFunctionTable.global_vfTables:
                                pass
                            else:
                                if verified_vtable := VirtualFunctionTable.VFTABLE(
                                        bv,
                                        potential_vtable_addr,
                                        f"vtable_{str(potential_vtable_addr)}_nonRtti"):
                                    pass
