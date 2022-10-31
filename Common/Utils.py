import json
import subprocess

import binaryninja.binaryview

from .. import Config


def GetBaseOfFileContainingAddress(bv: binaryninja.binaryview.BinaryView, addr: int) -> int:
    # When loading other files, such as dlls, into the memory space of the current bv we need
    # to determine the base of the file in order to calculate relative addresses.
    section_name: str = bv.get_sections_at(addr)[0].name
    base_file_name_array = section_name.split(".")
    base_file_name = base_file_name_array[0]

    if base_file_name and len(base_file_name_array) != 1:
        # This function assumes the bv contains the base address of the file in a metadata
        # variable named after the file.
        return bv.query_metadata(base_file_name)
    else:
        return bv.start


def DemangleName(mangled_name: str) -> str:
    demangled_name: str = subprocess.getoutput([Config.DEMANGLER_FULL_PATH, mangled_name])
    # Sometimes classes that use lambda functions cannot be parsed correctly and we get this error msg.
    if demangled_name.startswith('The system cannot find the file specified'):
        return mangled_name
    else:
        return demangled_name.split(" `RTTI")[0]


if Config.ENABLE_LOGGING or Config.ENABLE_DEBUG_LOGGING:
    try:
        log_file = open(Config.LOGFILE_FULL_PATH, 'w')
    except FileNotFoundError:
        log_file = open(Config.LOGFILE_FULL_PATH, 'w+')
        if log_file:
            log_file.close()
        log_file = open(Config.LOGFILE_FULL_PATH, 'w')


def LogToFile(log_str: str):
    if Config.ENABLE_LOGGING or Config.ENABLE_DEBUG_LOGGING:
        log_file.write(f'\n {log_str} \n')
