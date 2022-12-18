import binaryninja as bn
from . import ClassContext, ClassHierarchyDescriptor
from ..Common import Utils
from .. import Config


# TODO: implement for non relative addressing


class BaseClassDescriptor:

    def __init__(self, bv: bn.binaryview, base_addr: int):
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr

        # Type descriptor of the base class.
        self.pTypeDescriptor = self.GetTypeDescriptorAddress()
        # Number of direct bases of this base class.
        self.numContainedBases: int = self.GetNumContainedBases()
        # vfTable offset (only if pdisp = -1)
        self.pmd_mdisp: int = self.GetMdisp()
        # vbTable (virtual base class table) offset ( if = -1 then vfTable is at
        # displacement mdisp inside the class).
        # A vbTable is generated for multiple virtual inheritance.
        # because it is necessary to upclass (casting to base classes), the exact location of
        # the base class needs to be determined.
        # A vbTable contains a displacement of each base class' vfTable which is effectively the
        # beginning of the base class within the derived class.
        self.pmd_pdisp: int = self.GetPdisp()
        # Displacement of the base class vfTable pointer inside the vbTable
        self.pmd_vdisp: int = self.GetVdisp()
        # ???
        self.attributes: int = self.GetAttributes()
        # RTTIClassHierarchyDescriptor of this base class
        self.pClassDescriptor: int = self.GetClassDescriptor()

        self.mangled_class_name = self.get_mangled_class_name()
        self.demangled_class_name = Utils.DemangleName(self.mangled_class_name)

        self.verified = self.VerifyBaseClassDescriptor()

    def VerifyBaseClassDescriptor(self) -> bool:
        if self.IsInheritenceTypeSupported():
            if ClassContext.base_class_descriptors.get(self.base_addr):
                return True
            else:
                if self.DefineDataVar():
                    ClassContext.base_class_descriptors.update({self.base_addr: self.GetInstanceAsDict()})
                    if self.DefineRecursiveChd():
                        Utils.LogToFile(f'BaseClassDescriptor: Defined - {self.__repr__()}')
                        return True
        return False

    def GetTypeDescriptorAddress(self):
        base_of_file = 0
        if self.bv.arch.name == "x86_64":
            base_of_file = Utils.GetBaseOfFileContainingAddress(self.bv, self.base_addr)
        return self.bv.read_int(self.base_addr, 0x4) + base_of_file

    def GetNumContainedBases(self):
        return self.bv.read_int(self.base_addr + 0x4, 0x4)

    def GetPdisp(self):
        return self.bv.read_int(self.base_addr + 0xC, 0x4)

    def GetVdisp(self):
        return self.bv.read_int(self.base_addr + 0x10, 0x4)

    def GetMdisp(self):
        return self.bv.read_int(self.base_addr + 0x8, 0x4)

    def GetAttributes(self):
        return self.bv.read_int(self.base_addr + 0x14, 0x4)

    def GetClassDescriptor(self):
        base_of_file = 0
        if self.bv.arch.name == "x86_64":
            base_of_file = Utils.GetBaseOfFileContainingAddress(self.bv, self.base_addr)
        return self.bv.read_int(self.base_addr + 0x18, 0x4) + base_of_file

    def IsInheritenceTypeSupported(self):
        # if the pDisp field is -1 then we are dealing with normal inheritance, otherwise
        # we have multiple virtual inheritance which is not supported at the moment:
        # TODO: Support multiple virtual inheritance
        # For now we return True no matter what, in order to keep the processing of further base classes.
        # return self.pmd_pdisp == -1
        return True

    def __repr__(self):
        return f'BaseClassDescriptor {hex(self.base_addr)} \n' \
               f'     class_name = {self.demangled_class_name} \n' \
               f'     numContainedBases = {hex(self.numContainedBases)} \n' \
               f'     pmd_mdisp = {hex(self.pmd_mdisp)} \n' \
               f'     pmd_pdisp = {hex(self.pmd_pdisp)} \n' \
               f'     pmd_vdisp = {hex(self.pmd_vdisp)} \n' \
               f'     attributes = {hex(self.attributes)} \n' \
               f'     pClassDescriptor = {hex(self.pClassDescriptor)} \n'

    def GetInstanceAsDict(self) -> dict:
        return {"BaseClassDescriptor": hex(self.base_addr),
                "class_name": self.demangled_class_name,
                "numContainedBases": hex(self.numContainedBases),
                "pmd_mdisp": hex(self.pmd_mdisp),
                "pmd_pdisp": hex(self.pmd_pdisp),
                "pmd_vdisp": hex(self.pmd_vdisp),
                "attributes": hex(self.attributes),
                "pClassDescriptor": hex(self.pClassDescriptor)
                }

    def DefineDataVar(self):
        Utils.LogToFile(f'BaseClassDescriptor: Attempt to define data var at {hex(self.base_addr)}')
        try:
            self.bv.define_user_data_var(self.base_addr,
                                         self.bv.get_type_by_name(f'RTTIBaseClassDescriptor'),
                                         f'{self.demangled_class_name}_BaseClassDescriptor')

            self.bv.define_user_data_var(self.pTypeDescriptor,
                                         self.bv.get_type_by_name(f'TypeDescriptor'),
                                         )
            return True
        except Exception as e:
            Utils.LogToFile(f'BaseClassDescriptor: Exception while trying to define data var at {hex(self.base_addr)}')
            return False

    def DefineRecursiveChd(self) -> bool:
        """
        Recursively define the Class Hierarchy Descriptor pointed to by this base class.
        :return:
        """
        Utils.LogToFile(f'DefineRecursiveChd: Attempt to recursively define CHD at {hex(self.pClassDescriptor)} '
                        f'with mangled name {self.mangled_class_name}')
        class_hierarchy_descriptor = ClassHierarchyDescriptor.ClassHierarchyDescriptor(self.bv, self.pClassDescriptor,
                                                                                       self.mangled_class_name)
        if class_hierarchy_descriptor.verified:
            Utils.LogToFile(f'BaseClassDescriptor: Fully recursively defined CHD at '
                            f'{hex(class_hierarchy_descriptor.base_addr)}')
            return True
        else:
            Utils.LogToFile(f'BaseClassDescriptor: Failed to recursively define CHD at '
                            f'{hex(class_hierarchy_descriptor.base_addr)}')
            return False

    def get_mangled_class_name(self) -> str:
        if self.bv.arch.name == "x86_64":
            name_offset_in_type_descriptor = Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X64
        else:
            name_offset_in_type_descriptor = Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X32
        class_name_addr = self.pTypeDescriptor + name_offset_in_type_descriptor
        class_name_string = self.bv.get_ascii_string_at(class_name_addr)
        return class_name_string.value
