from binaryninja.function import Function
from binaryninja.binaryview import BinaryView, DataVariable
import binaryninja as bn
from ... import Config
from ...ClassDataStructureDetection.Constructors import DetectConstructor
from ...ClassObjectRepresentation import CppClass
from ...Common import Utils
from typing import *

# {vfTable_addr: [ContainedFunctions]}
global_vfTables: Dict[int, List[int]] = dict()
global_functions_contained_in_all_vfTables: List[int] = list()


def VerifyNonRttiVtable(bv: BinaryView, potential_vtable_addr: int) -> bool:
    if potential_vtable_addr in global_vfTables.keys():
        return True
    else:
        verified_vtable = VFTABLE(bv,
                                  potential_vtable_addr,
                                  f"vtable_{hex(potential_vtable_addr)}_nonRtti")
        if verified_vtable.verified:
            return True
    return False


def DetectVTables(bv: BinaryView, bt: bn.BackgroundTask):
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
    print("Searching for vTables...")
    
    # First, we go over the known vfTables (As inferred from RTTI info) and locate their constructors.
    for vtable_addr, contained_functions in global_vfTables.items():
        if bt.cancelled:
            raise KeyboardInterrupt()
        if potential_constructors := DetectConstructor.DetectConstructorForVTable(bv, vtable_addr):
            DetectConstructor.DefineConstructor(bv, potential_constructors, vtable_addr)
    for func in bv.functions:
        if func.start not in DetectConstructor.global_constructor_destructor_list and \
                func.start not in global_functions_contained_in_all_vfTables:
            if DetectConstructor.VerifyConstructor(bv, func):
                # VerifyConstructor will check that there is a pointer assignment into offset 0x0
                # in the "This" pointer (Arg1). Now we need to check if this pointer is a vTable.
                assignment_instructions = DetectConstructor.GetAllAssignmentInstructions(func)
                
                # NOTE(unknowntrojan) check all assignments to *this for constructors.
                # NOTE(unknowntrojan) this may be slow, but so is this entire script.
                for suspected_vtable in assignment_instructions[0]:
                    class_name: str = CppClass.GenerateClassNameFromVtableAddr(suspected_vtable)
                    vtable = VFTABLE(bv, suspected_vtable, class_name)
                    if vtable.verified:
                        if potential_constructors := DetectConstructor.DetectConstructorForVTable(bv, suspected_vtable):
                            DetectConstructor.DefineConstructor(bv, potential_constructors, suspected_vtable, class_name)
                
                # Check if the last assignment into offset 0 of Arg1 in the constructor func is a vTable.
                suspected_vtable: int = assignment_instructions[0][-1]
                print(f"Found non RTTI vtable at {hex(suspected_vtable)}")
                if potential_constructors := DetectConstructor.DetectConstructorForVTable(bv, suspected_vtable):
                    class_name: str = CppClass.GenerateClassNameFromVtableAddr(suspected_vtable)
                    vtable = VFTABLE(bv, suspected_vtable, class_name)
                    if vtable.verified:
                        DetectConstructor.DefineConstructor(bv, potential_constructors, suspected_vtable, class_name)

    thunks = DetectConstructor.GetConstructorThunks(bv, DetectConstructor.global_constructor_destructor_list)
    
    DetectConstructor.DefineConstructorThunks(bv, thunks)

    # TODO : add information of base classes according to non 0x0 offset assignments.


void_ptr_type = None

class VFTABLE:

    def __init__(self, bv: BinaryView, base_addr: int, demangled_name: str):
        self.bv: BinaryView = bv
        self.base_addr: int = base_addr
        self.vfTable_length: int = 0
        # Strip the "class " from the start of the demangled name.
        self.demangled_name: str = demangled_name[6:] if demangled_name.startswith("class ") else demangled_name
        self.contained_functions: List[int] = list()
        self.verified = self.VerifyVFT()

    def VerifyVFT(self) -> bool:
        data_refs_from_base_addr = list(self.bv.get_data_refs_from(self.base_addr))
        if len(data_refs_from_base_addr) == 0:
            # This is a situation that occurs due to a bug in binary ninja - if the data var at base_addr
            # is defined as a symbol from a previously loaded PDB file then binja will not recognize any data refs.
            # Since we are positive at this point that this location is a vTable (since we verified the COL for this
            # class) then it is safe to change its type to 'void *' in order to "fix" the binja bug and allow it to
            # recognize data refs.
            vTable_data_var = self.bv.get_data_var_at(self.base_addr)
            if vTable_data_var is not None:
                vTable_data_var.type = self.bv.parse_type_string("void*")[0]
                # Now we should see data refs from this address
                data_refs_from_base_addr = list(self.bv.get_data_refs_from(self.base_addr))
            else:
                print(f"VerifyVFT: unable to get information on data variable at addr {self.base_addr}.")
                return False

        if len(data_refs_from_base_addr) > 0:
            if self.bv.get_function_at(data_refs_from_base_addr[0]):
                if self.DefineVFT():
                    # Update this vfTable in the global table, this will be used later for locating constructor funcs
                    global_vfTables.update({self.base_addr: self.contained_functions})
                    global_functions_contained_in_all_vfTables.extend(self.contained_functions)
                    Utils.LogToFile(f'VFTABLE: verified table at address {hex(self.base_addr)}')
                    return True
        return False

    def DefineVFT(self) -> bool:
        Utils.LogToFile(f'vfTable: Attempt to define data var at {hex(self.base_addr)}')
        current_data_var_addr: int = self.base_addr
        while self.IsPointerToFunction(current_data_var_addr):
            self.vfTable_length += 1
            # NOTE(unknowntrojan) i implemented this, and then noticed it was in ClassyPP all along, just disabled.
            # self.RenameVFunc(current_data_var_addr)
            current_data_var_addr += 0x8 if self.bv.arch.name == "x86_64" else 0x4
        if self.vfTable_length > 0:
            try:
                # Define the Complete object locator
                self.bv.define_user_data_var(self.base_addr,
                                             self.bv.parse_type_string(f'void*[{self.vfTable_length}]')[0],
                                             self.demangled_name)
                Utils.LogToFile(f'vfTable: Defined data var at {hex(self.base_addr)}')
                return True
            except Exception as e:
                Utils.LogToFile(f'vfTable: Failed to Define data var at {hex(self.base_addr)}, \n Exception: {e}')
                return False
        else:
            return False

    def GetBinjaVoidPointerType(self) -> bn.types.PointerType:
        global void_ptr_type
        if void_ptr_type is None:
            void_ptr_type = bn.Type.pointer(self.bv.arch, self.bv.parse_type_string("void")[0])
        return void_ptr_type

    def GetPointer(self, pointer_addr: int) -> Optional[bn.DataVariable]:
        # Sometimes binja parses PDB information incorrectly, and instead of a pointer to a vTable
        # it just defines the struct that the PDB says defines the vTable.
        # If this happens - we dont change the PDB struct, we just say this is a pointer to the PDB struct.
        pointer: bn.DataVariable
        if pointer := self.bv.get_data_var_at(pointer_addr):
            if type(pointer) != bn.types.PointerType:
                try:
                    Utils.LogToFile(f"GetPointer: Overriding original type for Vtable -\n"
                                    f"pointer_addr: {hex(pointer_addr)}\n"
                                    f"current pointer type: {pointer.type}\n"
                                    f"pointer name: {pointer.name}")
                    self.bv.define_user_data_var(pointer_addr,
                                                 self.GetBinjaVoidPointerType(),
                                                 pointer.name)
                    return self.bv.get_data_var_at(pointer_addr)
                except Exception as e:
                    Utils.LogToFile(f"GetPointer: Exception while trying to define pointer at addr {pointer_addr}.\n"
                                    f"Exception: {e}")
                    return None
            return pointer
        return None

    def IsPointerToFunction(self, pointer_addr: int) -> bool:
        try:
            if pointer := self.GetPointer(pointer_addr):
                if segment := self.bv.get_segment_at(pointer.value):
                    if segment.executable:
                        if not self.bv.get_function_at(pointer.value):
                            self.bv.add_function(pointer.value)
                        self.contained_functions.append(pointer.value)
                        return True
        except Exception as e:
            Utils.LogToFile(f"IsPointerToFunction: Failed to determine if pointer to function at {hex(pointer_addr)}.\n"
                            f"Exception: {e}")
            
        return False

    def GetLength(self):
        return self.vfTable_length
