import binaryninja as bn
from typing import *

from Common.Utils import RecordAllInformation
from .CompleteObjectLocator import CompleteObjectLocator
from . import ClassHierarchyDeduction
from ..Common import Utils
from .. import Config
from ..ClassMemoryLayout import ClassStructCreation

###############################################################################################
#                GLOBAL STRUCTS
#
#       complete_object_locator -> class_hierarchy_descriptor -> base_class_array -> base_class_descriptor
#                                     Contains class name                               points to a chd

# {Col_addr: [Chd_addr, vTable_addr, vTable_length, vTableFunctions]}
complete_object_locators: Dict[int, Tuple[int, int, int, List[int]]] = dict()
# {Chd_addr: (mangled_type_name((base_class_addr_a, base_class_addr_b, ...))}
class_hierarchy_desctiptors: Dict[int, Tuple[str, List[int]]] = dict()
# {Bcd_addr: Bcd_obj}
base_class_descriptors: Dict[int, dict] = dict()


class GlobalClassContextManager:
    """
    Holds global data regarding all RTTI structs found, and is responsible to correlate
    and attempt to accurately define the different classes found.
    """

    def __init__(self, bv: bn.binaryview):
        self.bv: bn.binaryview = bv

    def DefineRTTI(self) -> bool:
        for sect in self.bv.sections.values():
            if sect.semantics is bn.SectionSemantics.ReadWriteDataSectionSemantics or \
                    sect.semantics is bn.SectionSemantics.ReadOnlyDataSectionSemantics:
                current_address = sect.start
                while current_address < sect.end - Config.RTTI_COMPLETE_OBJECT_LOCATOR_SIZE:
                    Col: CompleteObjectLocator = CompleteObjectLocator(self.bv, current_address)
                    if Col.verified:
                        Utils.LogToFile(f'DefineRTTI: Defined {Col.__repr__()} \n')
                        std_class_name = ClassStructCreation.CreateClass(
                            self.bv, Utils.DemangleName(Col.mangled_class_name)
                        )
                        if std_class_name:
                            print(f'DefineRTTI: Successfully defined {std_class_name} type in BinaryView.')
                        if complete_object_locators.get(current_address):
                            Utils.LogToFile(f'DefineRTTI: multiple col in single address - {hex(current_address)}')
                        else:
                            Utils.LogToFile(f'DefineRTTI: Adding CHD for Col at address {current_address}')
                            complete_object_locators.update({current_address: (
                                Col.GetChdAddr(),
                                Col.GetVtableAddr(),
                                Col.GetVtableLength(),
                                Col.GetvTableFunctions()
                            )
                            }
                            )

                        Utils.LogToFile(f'DefineRTTI: defined at current address {hex(current_address)}, increasing to '
                                        f'addr {hex(current_address + Config.RTTI_COMPLETE_OBJECT_LOCATOR_SIZE)}')
                        current_address += Config.RTTI_COMPLETE_OBJECT_LOCATOR_SIZE
                    else:
                        # A Col will be 4 bytes aligned
                        current_address += 4
        # TODO: Define condition for this function to fail.

        ClassHierarchyDeduction.DefineClassHierarchy(self.bv)
        RecordAllInformation()
        print('DONE')
        return True
