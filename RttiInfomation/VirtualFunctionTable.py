import binaryninja as bn
from ..Common import Utils
from typing import *


class VFTABLE:

    def __init__(self, bv: bn.binaryview, base_addr: int, demangled_name: str):
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr
        self.vfTable_length: int = 0
        self.demangled_name: str = demangled_name
        self.verified: bool = False
        self.contained_functions: List[int] = list()
        if self.VerifyVFT():
            if self.DefineVFT():
                Utils.LogToFile(f'VFTABLE: verified table at address {self.base_addr}')
                self.verified = True

    def VerifyVFT(self) -> bool:
        data_refs_from_base_addr = list(self.bv.get_data_refs_from(self.base_addr))
        if len(data_refs_from_base_addr) > 0:
            if self.bv.get_function_at(data_refs_from_base_addr[0]):
                return True
        return False

    def DefineVFT(self) -> bool:
        Utils.LogToFile(f'vfTable: Attempt to define data var at {hex(self.base_addr)}')
        current_data_var_addr: int = self.base_addr
        while self.IsPointerToFunction(current_data_var_addr):
            self.vfTable_length += 1
            current_data_var_addr += 0x8
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

    def IsPointerToFunction(self, pointer_addr: int):
        pointer: bn.DataVariable = self.bv.get_data_var_at(pointer_addr)
        try:
            if self.bv.get_sections_at(pointer.value)[0].semantics is bn.SectionSemantics.ReadOnlyCodeSectionSemantics:
                if not self.bv.get_function_at(pointer.value):
                    self.bv.add_function(pointer.value)
                self.contained_functions.append(pointer.value)
                return True
        except Exception as e:
            pass

        return False

    def GetLength(self):
        return self.vfTable_length
