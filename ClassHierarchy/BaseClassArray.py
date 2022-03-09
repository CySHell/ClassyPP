import binaryninja as bn
from typing import *
from .BaseClassDescriptor import BaseClassDescriptor
from ..Common import Utils
import logging

log = logging.getLogger(__name__)


class BaseClassArray:

    def __init__(self, bv: bn.binaryview, base_addr: int, entry_count: int, mangled_class_name: str):
        self.bv: bn.binaryview = bv
        self.base_addr: int = base_addr
        self.mangled_class_name: str = mangled_class_name
        self.entry_count = entry_count
        self.base_class_descriptor_array: List[int] = list()
        self.verified: bool = True

        for entry in range(self.entry_count):
            current_class_descriptor_addr: int = self.bv.read_int(self.base_addr + 0x4 * entry, 4) + bv.start
            base_class_descriptor = BaseClassDescriptor(self.bv, current_class_descriptor_addr)
            if base_class_descriptor.verified:
                self.base_class_descriptor_array.append(current_class_descriptor_addr)
            else:
                # If a single base class descriptor is not verified the whole complete object locator is failed
                self.verified = False
                break

        if self.verified and self.DefineDataVar():
            pass
        else:
            self.verified = False

    def DefineDataVar(self) -> bool:
        Utils.LogToFile(f'BaseClassArray: Attempt to define data var at {hex(self.base_addr)}')
        try:
            self.bv.define_user_data_var(self.base_addr,
                                         self.bv.parse_type_string(f'int[{self.entry_count}]')[0],
                                         f'{Utils.DemangleName(self.mangled_class_name)}_BaseClassArray')
            Utils.LogToFile(f'BaseClassArray: Defined data var at {hex(self.base_addr)}')
            return True
        except Exception as e:
            log.error(f'BaseClassArray: Failed to define data var at {hex(self.base_addr)}, reason: {e}')
            return False
