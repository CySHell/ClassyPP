import os
import sys

######################################################
#   General
######################################################

if sys.platform == 'win32':
    BINARY_SUFFIX = '.exe'
elif sys.platform == 'linux':
    BINARY_SUFFIX = '_linux'
elif sys.platform == 'darwin':
    BINARY_SUFFIX = '_mac_universal'
else:
    raise RuntimeError('Unsupported OS')

PLUGIN_FOLDER = os.path.dirname(__file__)

######################################################
#   64bit constants
######################################################
NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X64 = 0x10
RTTI_COMPLETE_OBJECT_LOCATOR_SIZE_X64 = 0x18
INT64_T = 0x8
INT32_T = 0x4
INT_SIZE_X64 = INT32_T
PTR_SIZE_X64 = INT64_T


######################################################
#   32bit constants
######################################################
NAME_STRING_OFFSET_INSIDE_TYPEDESCRIPTOR_X32 = 0x8
RTTI_COMPLETE_OBJECT_LOCATOR_SIZE_X32 = 0x18
INT64_T = 0x8
INT32_T = 0x4
INT_SIZE_X32 = INT32_T
PTR_SIZE_X32 = INT32_T


######################################################
#   User choices
######################################################
# 0 - Add comment for constructor function
# 1 - Change name of constructor function
# 2 - Do not detect constructors
CONSTRUCTOR_FUNCTION_HANDLING = 1


######################################################
#   Logging
######################################################
ENABLE_LOGGING = False
ENABLE_DEBUG_LOGGING = False

# If set to True the user will get a prompt to choose the logging directory
LOG_FILES_DETERMINED_BY_USER = True

COMPLETE_OBJECT_LOCATOR_RECORD_FILE = os.path.join(
    PLUGIN_FOLDER, "Logs/ColRecord.txt")
CLASS_HIERARCHY_DESCRIPTORS_RECORD_FILE = os.path.join(
    PLUGIN_FOLDER, "Logs/ChdRecord.txt")
BASE_CLASS_DESCRIPTORS_RECORD_FILE = os.path.join(
    PLUGIN_FOLDER, "Logs/BcdRecord.txt")

LOGFILE_FULL_PATH = os.path.join(
    PLUGIN_FOLDER, "Logs")

######################################################
#   Class info extraction utilities
######################################################

DEMANGLER_FULL_PATH = os.path.join(
    PLUGIN_FOLDER, "Common/demumble" + BINARY_SUFFIX)

GRAPH_FILE_FULL_PATH = PLUGIN_FOLDER

# This folder contains files produced by the output of the MSVC CL compiler with the flag /d1reportAllClassLayout.
# Each file should start with "layout_" .
# Define the folder as a Windows environment variable named "CLASS_LAYOUT_FOLDER".
# This is only used by the LayoutParser.py module, not during normal plugin operation.
PATH_TO_LAYOUT_FOLDER = os.path.expandvars(
    '%CLASS_LAYOUT_FOLDER%')

# This file contains the JSON format for all the classes that were parsed from MSVC output in %PATH_TO_LAYOUT_FOLDER%
PATH_TO_CLASS_LAYOUTS_FILE = os.path.join(
    PLUGIN_FOLDER, "RttiInformation/ClassMemoryLayout/class_layouts.layout")
