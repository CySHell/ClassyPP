import json
import subprocess

import Config
from ClassHierarchy.ClassContext import complete_object_locators, class_hierarchy_desctiptors, base_class_descriptors
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
    log_file.write(f'\n {log_str} \n')


def RecordAllInformation():
    Utils.LogToFile(f'Recording to file {Config.BASE_CLASS_DESCRIPTORS_RECORD_FILE}')
    with open(Config.COMPLETE_OBJECT_LOCATOR_RECORD_FILE, 'w') as col_file:
        col_file.write(json.dumps(complete_object_locators, indent=4))
    with open(Config.CLASS_HIERARCHY_DESCRIPTORS_RECORD_FILE, 'w') as chd_file:
        chd_file.write(json.dumps(class_hierarchy_desctiptors, indent=4))
    with open(Config.BASE_CLASS_DESCRIPTORS_RECORD_FILE, 'w') as bcd_file:
        bcd_file.write(json.dumps(base_class_descriptors, indent=4))