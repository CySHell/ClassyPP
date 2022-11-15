import binaryninja as bn

from ...Common import Utils
from typing import *

# {vfTable_addr: [ContainedFunctions]}
global_vfTables: Dict[int, List[int]] = dict()
global_functions_contained_in_all_vfTables: List[int] = list()


class VFTABLE:

    def __init__(self, bv: bn.binaryview, base_addr: int, demangled_name: str):
        self.bv: bn.binaryview = bv
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
            vTable_data_var.type = self.bv.parse_type_string("void*")[0]
            # Now we should see data refs from this address
            data_refs_from_base_addr = list(self.bv.get_data_refs_from(self.base_addr))

        if len(data_refs_from_base_addr) > 0:
            if self.bv.get_function_at(data_refs_from_base_addr[0]):
                if self.DefineVFT():
                    # Update this vfTable in the global table, this will be used later for locating constructor funcs
                    global_vfTables.update({self.base_addr: self.contained_functions})
                    Utils.LogToFile(f'VFTABLE: verified table at address {hex(self.base_addr)}')
                    return True
        return False

    def DefineVFT(self) -> bool:
        Utils.LogToFile(f'vfTable: Attempt to define data var at {hex(self.base_addr)}')
        current_data_var_addr: int = self.base_addr
        while self.IsPointerToFunction(current_data_var_addr):
            self.vfTable_length += 1
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
        return bn.Type.pointer(self.bv.arch, self.bv.parse_type_string("void")[0])

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
                if self.bv.get_sections_at(pointer.value)[0].semantics is \
                        bn.SectionSemantics.ReadOnlyCodeSectionSemantics:
                    if not self.bv.get_function_at(pointer.value):
                        self.bv.add_function(pointer.value)
                    self.contained_functions.append(pointer.value)
                    return True
        except Exception as e:
            Utils.LogToFile(f"IsPointerToFunction: Failed to determine if pointer to function at {pointer_addr}.\n"
                            f"Exception: {e}")
        return False

    def GetLength(self):
        return self.vfTable_length
