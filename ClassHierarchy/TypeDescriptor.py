import binaryninja as bn
import logging
log = logging.getLogger(__name__)


class TypeDescriptor:

    def __init__(self, bv: bn.binaryview, addr: int):
        self.bv: bn.binaryview = bv
        # Base address of the type descriptor
        self.base_addr: int = addr
        # Always points to type_info's vfTable
        self.pVFTable: int = 0
        # Spare
        self.spare: int = 0
        # Class name
        self.name = ""

    def DefineDataVar(self) -> bool:
        """
        Define the type descriptor data var in the bv.
        :return: Success or failure in definition
        """
        try:
            self.bv.define_user_data_var(self.base_addr, self.bv.get_type_by_name('TypeDescriptor')[0])
            return True
        except Exception as e:
            Utils.LogToFile(f'TypeDescriptor.DefineDataVar: Failed to define data var at {self.base_addr}')
            return False
