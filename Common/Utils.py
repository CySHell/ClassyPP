import subprocess
from os.path import exists
import os
import binaryninja as bn
from .. import Config


def GetBaseOfFileContainingAddress(bv: bn.binaryninja.binaryview.BinaryView, addr: int) -> int:
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
    try:
        demangled_name: str = subprocess.check_output(
            [Config.DEMANGLER_FULL_PATH, mangled_name]).decode()
    except subprocess.CalledProcessError:
        return mangled_name

    # Sometimes classes that use lambda functions cannot be parsed correctly and we get this error msg.
    if demangled_name.startswith('The system cannot find the file specified'):
        return mangled_name
    else:
        return demangled_name.split(" `RTTI")[0]


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
