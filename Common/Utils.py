import json
import subprocess
from .. import Config


def DemangleName(mangled_name: str) -> str:
    demangled_name: str = subprocess.getoutput([Config.DEMANGLER_FULL_PATH, mangled_name])

    # Sometimes classes that use lambda functions cannot be parsed correctly and we get this error msg.
    if demangled_name.startswith('The system cannot find the file specified'):
        return demangled_name
    else:
        return demangled_name.split(" `RTTI")[0]


log_file = open(Config.LOGFILE_FULL_PATH, 'w')


def LogToFile(log_str: str):
    if Config.ENABLE_LOGGING:
        log_file.write(f'\n {log_str} \n')



