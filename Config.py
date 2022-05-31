import os


######################################################
#   32bit \ 64bit constants
######################################################
NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR = 0x10
RTTI_COMPLETE_OBJECT_LOCATOR_SIZE = 0x18
INT_SIZE = 0x8
PTR_SIZE = INT_SIZE

######################################################
#   Logging
######################################################
ENABLE_LOGGING = True

COMPLETE_OBJECT_LOCATOR_RECORD_FILE = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\Logs\\ColRecord.txt')
CLASS_HIERARCHY_DESCRIPTORS_RECORD_FILE = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\Logs\\ChdRecord.txt')
BASE_CLASS_DESCRIPTORS_RECORD_FILE = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\Logs\\BcdRecord.txt')

LOGFILE_FULL_PATH = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\Logs\\log_debug.txt')
DEMANGLER_FULL_PATH = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\Common\\demumble.exe')

GRAPH_FILE_FULL_PATH = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\')


PATH_TO_LAYOUT_FOLDER = os.path.expandvars(
    '%CLASS_LAYOUT_FOLDER%')

PATH_TO_CLASS_LAYOUTS_FILE = os.path.expandvars(
    '%USERPROFILE%\\AppData\\Roaming\\Binary Ninja\\plugins\\CppInspector\\class_layouts.layout')
