import subprocess
from os.path import exists
import os
from .. import Config
from binaryninja.binaryview import BinaryView
import binaryninja as bn


def GetBaseOfFileContainingAddress(bv: BinaryView, addr: int) -> int:
    # When loading other files, such as dlls, into the memory space of the current bv we need
    # to determine the base of the file in order to calculate relative addresses.
    sections = bv.get_sections_at(addr) 
    
    if len(sections) < 1:
        return bv.start
    
    section_name: str = sections[0].name
    base_file_name_array = section_name.split(".")
    base_file_name = base_file_name_array[0]

    if base_file_name and len(base_file_name_array) != 1:
        # This function assumes the bv contains the base address of the file in a metadata
        # variable named after the file.
        return bv.query_metadata(base_file_name)
    else:
        return bv.start

cached_mangle_dict = {}

def DemangleName(mangled_name: str) -> str:
    if mangled_name in cached_mangle_dict.keys():
        return cached_mangle_dict[mangled_name]
    else:
        if os.name == 'nt':
            CREATE_NO_WINDOW = 0x08000000
            demangled_name = subprocess.check_output(
                [Config.DEMANGLER_FULL_PATH, mangled_name], creationflags=CREATE_NO_WINDOW)
        else:
            demangled_name = subprocess.check_output(
                [Config.DEMANGLER_FULL_PATH, mangled_name])

        # Linux returns demangled_name as a bytes object, need to convert to string.
        if type(demangled_name) != str:
            demangled_name = demangled_name.decode()

        # Sometimes classes that use lambda functions cannot be parsed correctly and we get this error msg.
        if demangled_name.startswith('The system cannot find the file specified'):
            cached_mangle_dict[mangled_name] = mangled_name
            return mangled_name
        else:
            demangled_name = demangled_name.split(" `RTTI")[0]
            cached_mangle_dict[mangled_name] = demangled_name
            return demangled_name


############################################################################################
#                   LOGGING
############################################################################################
def GetLogfileHandle():
    if Config.LOG_FILES_DETERMINED_BY_USER:
        LoggingDirectory: str = bn.interaction.get_directory_name_input(
            f"Please select a directory to store the log files")
    else:
        LoggingDirectory: str = Config.LOGFILE_FULL_PATH

    log_file_path = os.path.join(LoggingDirectory, 'log_debug.txt')
    try:
        if exists(LoggingDirectory):
            log_file = open(log_file_path, 'w')
        else:
            log_file = open(log_file_path, 'x')
    except Exception as e:
        print(f"Can't open logfile {log_file_path} for writing -\n {e}")
        return None
    return log_file


def LogToFile(log_str: str):
    if Config.ENABLE_LOGGING or Config.ENABLE_DEBUG_LOGGING:
        logging_file.write(f'\n {log_str} \n')
