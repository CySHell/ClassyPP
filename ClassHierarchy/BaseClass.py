import binaryninja as bn
from typing import *
import logging
log = logging.getLogger(__name__)

# TODO: implement for non relative addressing

STRING_OFFSET_INSIDE_TYPEDESCRIPTOR = 0x10


class BaseClassDescriptor:

    def __init__(self, bv: bn.binaryview, base_addr: int, relative: bool):
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr
        self.class_name = ""

        self.relative = relative
        if self.relative:
            # Type descriptor of the base class.
            self.pTypeDescriptor = self.bv.read_int(self.base_addr, 0x4) + self.bv.start
            # Number of direct bases of this base class.
            self.numContainedBases: int = self.bv.read_int(self.base_addr + 0x4, 0x4)
            # vfTable offset (only if pdisp = -1)
            self.pmd_mdisp: int = self.bv.read_int(self.base_addr + 0x8, 0x4)
            # vbTable (virtual base class table) offset ( if = -1 then vfTable is at
            # displacement mdisp inside the class).
            # A vbTable is generated for multiple virtual inheritance.
            # because it is necessary to upclass (casting to base classes), the exact location of
            # the base class needs to be determined.
            # A vbTable contains a displacement of each base class' vfTable which is effectively the
            # beginning of the base class within the derived class.
            self.pmd_pdisp: int = self.bv.read_int(self.base_addr + 0xC, 0x4)
            # Displacement of the base class vfTable pointer inside the vbTable
            self.pmd_vdisp: int = self.bv.read_int(self.base_addr + 0x10, 0x4)
            # ???
            self.attributes: int = self.bv.read_int(self.base_addr + 0x14, 0x4)
            # RTTIClassHierarchyDescriptor of this base class
            self.pClassDescriptor: int = self.bv.read_int(self.base_addr + 0x18, 0x4) + self.bv.start
        else:
            Utils.LogToFile(f'BaseClassDescriptor: non-relative addressing not implemented yet.')

        self.DefineDataVar()
        Utils.LogToFile(f'BaseClassDescriptor: Defined - {self.__repr__()}')

    def __repr__(self):
        return f'BaseClassDescriptor {hex(self.base_addr)} \n' \
               f'     pTypeDescriptor = {hex(self.pTypeDescriptor)} \n' \
               f'     numContainedBases = {hex(self.numContainedBases)} \n' \
               f'     pmd_mdisp = {hex(self.pmd_mdisp)} \n' \
               f'     pmd_pdisp = {hex(self.pmd_pdisp)} \n' \
               f'     pmd_vdisp = {hex(self.pmd_vdisp)} \n' \
               f'     attributes = {hex(self.attributes)} \n' \
               f'     pClassDescriptor = {hex(self.pClassDescriptor)} \n'

    def DefineDataVar(self):
        Utils.LogToFile(f'BaseClassDescriptor: Defining at {hex(self.base_addr)}')
        self.bv.define_data_var(self.base_addr,
                                self.bv.get_type_by_name(f'_RTTIBaseClassDescriptor_relative'))

        self.bv.define_data_var(self.pTypeDescriptor, self.bv.get_type_by_name(f'TypeDescriptor'))
        class_name_addr = self.pTypeDescriptor + STRING_OFFSET_INSIDE_TYPEDESCRIPTOR
        class_name_string = self.bv.get_ascii_string_at(class_name_addr)
        self.class_name = class_name_string.value
        class_name_type = self.bv.parse_type_string(f'char[{class_name_string.length}]')[0]
        self.bv.define_data_var(class_name_addr, class_name_type)


class BaseClassArray:

    def __init__(self, bv: bn.binaryview, base_addr: int, entry_count: int, relative: bool):
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr
        self.entry_count = entry_count
        self.relative = relative
        self.DefineDataVar()
        self.base_class_descriptor_array: List[BaseClassDescriptor] = list()
        for entry in range(self.entry_count):
            current_class_descriptor_addr: int = self.bv.read_int(self.base_addr + 0x4 * entry, 4) + bv.start
            self.base_class_descriptor_array.append(
                BaseClassDescriptor(self.bv, current_class_descriptor_addr, relative)
            )

    def DefineDataVar(self):
        Utils.LogToFile(f'BaseClassArray: Defining at {hex(self.base_addr)}')
        self.bv.define_data_var(self.base_addr,
                                self.bv.parse_type_string(f'int[{self.entry_count}]')[0])
