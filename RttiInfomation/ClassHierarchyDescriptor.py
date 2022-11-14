import binaryninja as bn
from .BaseClassArray import BaseClassArray
from . import ClassContext
from ..Common import Utils


class ClassHierarchyDescriptor:

    def __init__(self, bv: bn.binaryview, base_addr: int, mangled_class_name: str):
        Utils.LogToFile(f'Attempt to define {mangled_class_name} CHD at base_addr {base_addr}')
        self.base_class_array = None
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr
        self.mangled_class_name: str = mangled_class_name
        self.demangled_class_name: str = Utils.DemangleName(self.mangled_class_name)
        # Always 0 ?
        self.signature: int = self.bv.read_int(self.base_addr, 0x4)
        # attributes = 0 - normal inheritance
        # attributes = 1 - multiple inheritance
        # attributes = 2 - virtual inheritance
        # attributes = 3 - multiple and virtual inheritance
        self.attributes: int = self.bv.read_int(self.base_addr + 0x4, 0x4)
        # Number of base classes. This count includes the class itself.
        self.numBaseClasses: int = self.bv.read_int(self.base_addr + 0x8, 0x4)

        self.pBaseClassArray: int = self.GetBaseClassArrayAddress()

        self.verified = self.VerifyChd()

    def GetBaseClassArrayAddress(self):
        base_of_file: int = 0
        if self.bv.arch.name == "x86_64":
            base_of_file = Utils.GetBaseOfFileContainingAddress(self.bv, self.base_addr)
        return self.bv.read_int(self.base_addr + 0xC, 0x4) + base_of_file

    def __repr__(self):
        return f'ClassHierarchyDescriptor {hex(self.base_addr)} \n' \
               f'     signature = {hex(self.signature)} \n' \
               f'     attributes = {hex(self.attributes)} \n' \
               f'     numBaseClasses = {hex(self.numBaseClasses)} \n' \
               f'     pBaseClassArray = {hex(self.pBaseClassArray)} \n'

    def VerifyChdSignature(self):
        if self.signature == 0x0:
            return True
        else:
            Utils.LogToFile(f'VerifyChdSignature: signature field is NOT 0x0. ')
            return False

    def VerifyChdAttributes(self) -> bool:
        # attributes = 0 - normal inheritance
        # attributes = 1 - multiple inheritance
        # attributes = 2 - virtual inheritance
        # attributes = 3 - multiple and virtual inheritance
        if self.attributes == 0x0 or self.attributes == 0x1:
            # TODO: Add a better verification system
            return True
        elif self.attributes == 0x2 or self.attributes == 0x3:
            Utils.LogToFile(f'VerifyChdAttributes: Attributes indicate Virtual inheritance is present, not currently '
                            f'supported')
            return False
        else:
            Utils.LogToFile(f'VerifyChdAttributes: attributes field is not valid - Attribute = {self.attributes}. ')
            return False

    def VerifyBaseClassArray(self) -> bool:
        base_class_array: BaseClassArray = BaseClassArray(self.bv, self.pBaseClassArray,
                                                          self.numBaseClasses, self.mangled_class_name)
        if base_class_array.verified:
            self.base_class_array = base_class_array
            return True
        else:
            return False

    def VerifyChd(self) -> bool:
        Utils.LogToFile(f'VerifyChd: Verifying {self.__repr__()}')
        if ClassContext.class_hierarchy_descriptors.get(self.base_addr):
            # This Chd was already defined
            return True
        else:
            if self.VerifyChdSignature():
                # Only handle single and multiple inheritance
                # TODO : Add Virtual and Multiple Virtual inheritance support
                if self.VerifyChdAttributes():
                    if self.VerifyBaseClassArray():
                        Utils.LogToFile(f'VerifyChd: sig, attributes and base class array verified for  {self.__repr__()}')
                        ClassContext.class_hierarchy_descriptors.update({self.base_addr: ("", list())})
                        if self.DefineDataVar():
                            ClassContext.class_hierarchy_descriptors.pop(self.base_addr)
                            self.MapBaseClassArray()
                            return True
        return False

    def DefineDataVar(self) -> bool:
        Utils.LogToFile(f'ClassHierarchyDescriptor: Attempt to define data var at {hex(self.base_addr)}')
        try:
            self.bv.define_user_data_var(self.base_addr,
                                         self.bv.get_type_by_name('RTTIClassHierarchyDescriptor'),
                                         f'{self.demangled_class_name}_ClassHierarchyDescriptor')
            Utils.LogToFile(f'ClassHierarchyDescriptor: Defined data var at {hex(self.base_addr)}')
            return True
        except Exception as e:
            Utils.LogToFile(f'ClassHierarchyDescriptor: Failed to Define data var at {hex(self.base_addr)}')
            return False

    def MapBaseClassArray(self):
        """
        Add a pointer from this Class Hierarchy Descriptor to an array of base class descriptor addresses
        :return:
        """
        if ClassContext.class_hierarchy_descriptors.get(self.base_addr):
            Utils.LogToFile(f'ClassHierarchyDescriptor: Multiple class hierarchy descriptors pointed '
                            f'to at {hex(self.base_addr)}')
        else:
            ClassContext.class_hierarchy_descriptors.update(
                {
                    self.base_addr: (self.demangled_class_name, self.base_class_array.base_class_descriptor_array)
                }
            )
