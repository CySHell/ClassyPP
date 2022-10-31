import binaryninja as bn
from .ClassHierarchyDescriptor import ClassHierarchyDescriptor
from .VirtualTableInference import VirtualFunctionTable
from ..Common import Utils
from .. import Config
from typing import *


class CompleteObjectLocator:

    def __init__(self, bv: bn.binaryview, base_addr: int):
        self.mangled_class_name = None
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

        # Fix up information for 64 \ 32 bit
        self.pTypeDescriptor = self.GetTypeDescriptorAddress()
        self.pClassDescriptor = self.GetClassDescriptorAddress()
        self.pSelf = self.GetSelfPointer()
        self.name_string_offset_inside_typedescriptor = self.GetNameStringOffset()
        self.pointer_size = self.GetPointerSize()

        # Verify All fields and pointers match up to a real Complete Object Locator
        self.verified: bool = False

        self.verified = self.VerifyCol()

    def GetPointerSize(self):
        if self.bv.arch.name == "x86":
            return Config.PTR_SIZE_X32
        else:
            return Config.PTR_SIZE_X64

    def GetNameStringOffset(self):
        if self.bv.arch.name == "x86_64":
            return Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X64
        else:
            return Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X32

    def GetTypeDescriptorAddress(self):
        BaseAddressOfFile: int = 0
        if self.bv.arch.name == "x86_64":
            # We are dealing with 64 bit, Meaning a relative address. We get the base address of the file
            # and add it to the relative address given.
            BaseAddressOfFile: int = Utils.GetBaseOfFileContainingAddress(self.bv, self.base_addr)
        return self.bv.read_int(self.base_addr + 0xC, 0x4) + BaseAddressOfFile

    def GetClassDescriptorAddress(self):
        BaseAddressOfFile: int = 0
        if self.bv.arch.name == "x86_64":
            # We are dealing with 64 bit, Meaning a relative address. We get the base address of the file
            # and add it to the relative address given.
            BaseAddressOfFile: int = Utils.GetBaseOfFileContainingAddress(self.bv, self.base_addr)
        return self.bv.read_int(self.base_addr + 0x10, 0x4) + BaseAddressOfFile

    def GetSelfPointer(self):
        base_address_of_file: int = 0
        if self.bv.arch.name == "x86_64":
            base_address_of_file: int = Utils.GetBaseOfFileContainingAddress(self.bv, self.base_addr)
        return self.bv.read_int(self.base_addr + 0x14, 0x4) + base_address_of_file

    def __repr__(self):
        return f'CompleteObjectLocator {hex(self.base_addr)} \n' \
               f'     signature        = {hex(self.signature)} \n' \
               f'     offset           = {hex(self.offset)} \n' \
               f'     cdOffset         = {hex(self.cdOffset)} \n' \
               f'     pTypeDescriptor  = {hex(self.pTypeDescriptor)} \n' \
               f'     pClassDescriptor = {hex(self.pClassDescriptor)} \n' \
               f'     pSelf            = {hex(self.pSelf)}'

    def DefineDataVarForCol(self):
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

    def VerifyColSignature(self) -> bool:
        if self.bv.arch.name == "x86_64":
            if self.signature == 0x1:
                # 64 bit executable signature is 0x1
                return True
            else:
                Utils.LogToFile(f'VerifyColSignature: Signature field is NOT 0x1.')
                return False
        else:
            if self.signature == 0x0:
                # 32 bit executables signature is 0x0.
                return True
            else:
                Utils.LogToFile(f'VerifyColSignature: Signature field is NOT 0x0.')
                return False

    def VerifySelfPointer(self) -> bool:
        if self.bv.arch.name == "x86_64":
            if self.pSelf == self.base_addr:
                return True
            else:
                Utils.LogToFile(f'VerifySelfPointer: pSelf field does NOT point to self.')
                return False
        else:
            if self.pSelf == 0x0:
                # 32 bit executables pSelf field is 0x0.
                # Note that in some instances observed MSVC actually places the ClassHierarchyDescriptor struct
                # start in this location - This means that in 32 bit this field might actually be the "Signature"
                # field of the ClassHierarchyDescriptor struct (Which is always 0).
                return True
            else:
                Utils.LogToFile(f'VerifySelfPointer: pSelf field is not 0x0.')
                return False

    def VerifyClassHierarchyDescriptor(self) -> bool:
        self.mangled_class_name: str = self.get_mangled_class_name()
        if self.mangled_class_name:
            class_hierarchy_descriptor = ClassHierarchyDescriptor(self.bv, self.pClassDescriptor,
                                                                  self.mangled_class_name)
            if class_hierarchy_descriptor.verified:
                self.class_hierarchy_descriptor_address = class_hierarchy_descriptor.base_addr
                Utils.LogToFile(
                    f'VerifyClassHierarchyDescriptor: Succesfully defined CHD at - {hex(class_hierarchy_descriptor.base_addr)}.')
                return True
            else:
                Utils.LogToFile(
                    f'VerifyClassHierarchyDescriptor: FAILED to defined CHD at - {hex(class_hierarchy_descriptor.base_addr)}.')
        return False

    def DefineVirtualFuncTable(self) -> bool:
        # Define the vfTable of this class
        vfTable_address = self.GetVtableAddr()
        Utils.LogToFile(f'CompleteObjectLocator: Processing vfTable at: {vfTable_address}')
        vft: VirtualFunctionTable.VFTABLE = VirtualFunctionTable.VFTABLE(
            self.bv,
            vfTable_address,
            f'{Utils.DemangleName(self.mangled_class_name)}_vfTable'
        )
        if vft.verified:
            self.vTable = vft
            return True
        else:
            return False

    def get_mangled_class_name(self) -> Union[str, None]:
        Utils.LogToFile(f'CompleteObjectLocator: Extracting class name.')
        class_name_addr = self.pTypeDescriptor + self.name_string_offset_inside_typedescriptor
        class_name_string = self.bv.get_ascii_string_at(class_name_addr)
        if class_name_string:
            Utils.LogToFile(f'CompleteObjectLocator: Found Class name - {class_name_string.value}.')
            return class_name_string.value
        else:
            Utils.LogToFile(f'CompleteObjectLocator: NO Class name found for COL- {hex(self.base_addr)}.')
            return None

    def GetVtableAddr(self) -> int:
        if self.vTable:
            return self.vTable.base_addr
        else:
            return list(self.bv.get_data_refs(self.base_addr))[0] + self.pointer_size

    def GetVtableLength(self):
        return self.vTable.GetLength()

    def GetvTableFunctions(self) -> List[int]:
        return self.vTable.contained_functions

    def VerifyCol(self) -> bool:
        """
        Verify this is really a Complete Object Locator.
        :return: Verification Succeed \ Fail
        """
        Utils.LogToFile(f'VerifyCol: Verifying {self.__repr__()}')

        if len(list(self.bv.get_data_refs(self.base_addr))) == 0x1:
            if self.VerifyColSignature():
                if self.VerifySelfPointer():
                    if self.VerifyClassHierarchyDescriptor():
                        if self.DefineDataVarForCol():
                            if self.DefineVirtualFuncTable():
                                Utils.LogToFile(f'VerifyCol: Successfully verified COL at {hex(self.base_addr)}')
                                return True
        Utils.LogToFile(f'VerifyCol: No COL found at {hex(self.base_addr)}')
        return False
