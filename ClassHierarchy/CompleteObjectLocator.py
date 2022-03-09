import binaryninja as bn
from .ClassHierarchyDescriptor import ClassHierarchyDescriptor
from . import VirtualFunctionTable
from ..Common import Utils
from .. import Config
from typing import *


class CompleteObjectLocator:

    def __init__(self, bv: bn.binaryview, base_addr: int):
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr
        self.vTable: Optional[VirtualFunctionTable.VFTABLE] = None
        self.class_hierarchy_descriptor_address: int = 0
        # Signature is 0x1 for 64bit binaries, 0x0 for 32bit binaries
        self.signature: int = self.bv.read_int(self.base_addr, 0x4)
        # Offset of vTable within the class
        self.offset: int = self.bv.read_int(self.base_addr + 0x4, 0x4)
        # ????
        self.cdOffset: int = self.bv.read_int(self.base_addr + 0x8, 0x4)

        Utils.LogToFile(f'CompleteObjectLocator: Processing COL at address {hex(self.base_addr)}')

        # Fix up addresses if relative
        self.relative = True
        self.pTypeDescriptor = self.bv.read_int(self.base_addr + 0xC, 0x4) + bv.start
        self.pClassDescriptor = self.bv.read_int(self.base_addr + 0x10, 0x4) + bv.start
        self.pSelf = self.bv.read_int(self.base_addr + 0x14, 0x4) + bv.start
        # Verify All fields and pointers match up to a real Complete Object Locator
        self.verified: bool = False
        if self.VerifyCol():
            self.mangled_class_name: str = self.get_mangled_class_name()
            # Utils.LogToFile(f'CompleteObjectLocator: Processing class {self.mangled_class_name}')
            class_hierarchy_descriptor = ClassHierarchyDescriptor(bv, self.pClassDescriptor, self.mangled_class_name)
            if class_hierarchy_descriptor.verified:
                if self.DefineDataVar():
                    self.class_hierarchy_descriptor_address = class_hierarchy_descriptor.base_addr
                    # Define the vfTable of this class
                    vfTable_address = self.GetVtableAddr()
                    vft: VirtualFunctionTable.VFTABLE = VirtualFunctionTable.VFTABLE(
                        self.bv,
                        vfTable_address,
                        f'{Utils.DemangleName(self.mangled_class_name)}_vfTable'
                    )
                    if vft.verified:
                        self.vTable = vft
                        self.verified = True

    def __repr__(self):
        return f'CompleteObjectLocator {hex(self.base_addr)} \n' \
               f'     signature        = {hex(self.signature)} \n' \
               f'     offset           = {hex(self.offset)} \n' \
               f'     cdOffset         = {hex(self.cdOffset)} \n' \
               f'     pTypeDescriptor  = {hex(self.pTypeDescriptor)} \n' \
               f'     pClassDescriptor = {hex(self.pClassDescriptor)} \n' \
               f'     pSelf            = {hex(self.pSelf)}'

    def DefineDataVar(self):
        Utils.LogToFile(f'CompleteObjectLocator: Attempt to define data var at {hex(self.base_addr)}')
        try:
            # Define the Complete object locator
            self.bv.define_user_data_var(self.base_addr,
                                         self.bv.get_type_by_name('RTTICompleteObjectLocator'),
                                         f'{Utils.DemangleName(self.mangled_class_name)}_CompleteObjectLocator')
            Utils.LogToFile(f'CompleteObjectLocator: Defined data var at {hex(self.base_addr)}')
            return True
        except Exception as e:
            Utils.LogToFile(f'CompleteObjectLocator: Failed to Define data var at {hex(self.base_addr)}')
            return False

    def GetChdAddr(self) -> int:
        """
        Get the address of the Class Hierarchy Desctriptor pointed to by this Col
        :return: address of CHD
        """
        return self.class_hierarchy_descriptor_address

    def VerifyCol(self) -> bool:
        """
        Verify this is really a Complete Object Locator.
        :return: Verification Succeed \ Fail
        """
        Utils.LogToFile(f'VerifyCol: Verifying {self.__repr__()}')
        if len(list(self.bv.get_data_refs(self.base_addr))) == 0x1:
            if self.signature == 0x1:
                if self.pSelf == self.base_addr:
                    return True
                else:
                    Utils.LogToFile(f'VerifyCol: pSelf field does NOT point to self.')
            else:
                Utils.LogToFile(f'VerifyCol: Signature field is NOT 0x1. Signature 0x0 means this is a 32bit executable.')
        return False

    def get_mangled_class_name(self) -> str:
        Utils.LogToFile(f'CompleteObjectLocator: Extracting class name.')

        class_name_addr = self.pTypeDescriptor + Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR
        class_name_string = self.bv.get_ascii_string_at(class_name_addr)
        return class_name_string.value

    def GetVtableAddr(self) -> int:
        if self.vTable:
            return self.vTable.base_addr
        else:
            return list(self.bv.get_data_refs(self.base_addr))[0] + Config.INT_SIZE

    def GetVtableLength(self):
        return self.vTable.GetLength()

    def GetvTableFunctions(self) -> List[int]:
        return self.vTable.contained_functions
