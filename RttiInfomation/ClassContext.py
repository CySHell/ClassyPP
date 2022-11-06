import binaryninja as bn
from typing import *
import json
from .CompleteObjectLocator import CompleteObjectLocator
from .ClassHierarchyInference import ClassHierarchyDeduction
from ..Common import Utils
from .. import Config
from .ClassMemoryLayout import ClassStructCreation
import pysnooper


###############################################################################################
#                GLOBAL STRUCTS
#
#       complete_object_locator -> class_hierarchy_descriptor -> base_class_array -> base_class_descriptor
#                                     Contains class name                               points to a chd

# {Col_addr: [Chd_addr, vTable_addr, vTable_length, vTableFunctions]}
complete_object_locators: Dict[int, Tuple[int, int, int, List[int]]] = dict()
# {Chd_addr: (mangled_type_name((base_class_addr_a, base_class_addr_b, ...))}
class_hierarchy_descriptors: Dict[int, Tuple[str, List[int]]] = dict()
# {Bcd_addr: Bcd_obj}
base_class_descriptors: Dict[int, dict] = dict()


def UpdateCompleteObjectLocatorsList(Col: CompleteObjectLocator, current_address):
    complete_object_locators.update({current_address: (
        Col.GetChdAddr(),
        Col.GetVtableAddr(),
        Col.GetVtableLength(),
        Col.GetvTableFunctions()
    )
    }
    )


def RecordAllInformationToFile():
    Utils.LogToFile(f'Recording to file {Config.BASE_CLASS_DESCRIPTORS_RECORD_FILE}')
    with open(Config.COMPLETE_OBJECT_LOCATOR_RECORD_FILE, 'w') as col_file:
        col_file.write(json.dumps(complete_object_locators, indent=4))
    with open(Config.CLASS_HIERARCHY_DESCRIPTORS_RECORD_FILE, 'w') as chd_file:
        chd_file.write(json.dumps(class_hierarchy_descriptors, indent=4))
    with open(Config.BASE_CLASS_DESCRIPTORS_RECORD_FILE, 'w') as bcd_file:
        bcd_file.write(json.dumps(base_class_descriptors, indent=4))


def IsSectionCompatibleToRTTI(section: bn.binaryview.Section) -> bn.binaryview.SectionSemantics:
    return section.semantics is bn.SectionSemantics.ReadWriteDataSectionSemantics or \
           section.semantics is bn.SectionSemantics.ReadOnlyDataSectionSemantics


class GlobalClassContextManager:
    """
    Holds global data regarding all RTTI structs found, and is responsible to correlate
    and attempt to accurately define the different classes found.
    """

    def __init__(self, bv: bn.binaryview):
        self.pointer_size = None
        self.int_size = None
        self.rtti_complete_object_locator_size = None
        self.name_string_offset_inside_typedescriptor = None
        self.bv: bn.binaryview = bv

        self.Define32or64BitConstants()

    def Define32or64BitConstants(self):
        if self.bv.arch.name == 'x86':
            self.name_string_offset_inside_typedescriptor = Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X32
            self.rtti_complete_object_locator_size = Config.RTTI_COMPLETE_OBJECT_LOCATOR_SIZE_X32
            self.int_size = Config.INT_SIZE_X32
            self.pointer_size = Config.PTR_SIZE_X32
        else:
            self.name_string_offset_inside_typedescriptor = Config.NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X64
            self.rtti_complete_object_locator_size = Config.RTTI_COMPLETE_OBJECT_LOCATOR_SIZE_X64
            self.int_size = Config.INT_SIZE_X64
            self.pointer_size = Config.PTR_SIZE_X64

    def GetCompleteObjectLocator(self, current_address) -> Union[CompleteObjectLocator, None]:
        Col: CompleteObjectLocator = CompleteObjectLocator(self.bv, current_address)
        if Col.verified:
            return Col
        else:
            return None

    def DebugPrintCol(self, Col: CompleteObjectLocator, current_address):
        std_class_name = ClassStructCreation.CreateClass(
            self.bv, Utils.DemangleName(Col.mangled_class_name)
        )
        print(f'Completed Processing - Class {Col.mangled_class_name} ')
        if std_class_name:
            Utils.LogToFile(f'DefineRTTI: Successfully defined {std_class_name} type in BinaryView.')
            print(f'Completed Processing - Class {std_class_name} ')
        if complete_object_locators.get(current_address):
            Utils.LogToFile(f'DefineRTTI: multiple col in single address - {hex(current_address)}')
        else:
            Utils.LogToFile(f'DefineRTTI: Adding CHD for Col at address {current_address}')
            UpdateCompleteObjectLocatorsList(Col, current_address)

        Utils.LogToFile(f'DefineRTTI: defined at current address {hex(current_address)}, increasing to '
                        f'addr {hex(current_address + self.rtti_complete_object_locator_size)}')

    def DeduceClassHierarchies(self):
        ClassHierarchyDeduction.DefineClassHierarchy(self.bv)

    def DefineRTTI(self) -> bool:
        for sect in self.bv.sections.values():
            if IsSectionCompatibleToRTTI(sect):
                current_address = sect.start
                while current_address < sect.end - self.rtti_complete_object_locator_size:
                    if Col := self.GetCompleteObjectLocator(current_address):
                        Utils.LogToFile(f'DefineRTTI: Defined {Col.__repr__()} \n')
                        print(f"Defined Class: {Utils.DemangleName(Col.mangled_class_name)}")
                        if Config.ENABLE_DEBUG_LOGGING:
                            self.DebugPrintCol(Col, current_address)

                        current_address += self.rtti_complete_object_locator_size
                    else:
                        # A Col will be 4 bytes aligned
                        current_address += 4
        # TODO: Define condition for this function to fail.

        self.DeduceClassHierarchies()

        if Config.ENABLE_LOGGING:
            RecordAllInformationToFile()

        return True
