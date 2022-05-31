import os

######################################################
#   General
######################################################

BINARYNINJA_PLUGIN_FOLDER = f'AppData\\Roaming\\Binary Ninja\\plugins'

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
#   Logging
######################################################
ENABLE_LOGGING = False

COMPLETE_OBJECT_LOCATOR_RECORD_FILE = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\Logs\\ColRecord.txt')
CLASS_HIERARCHY_DESCRIPTORS_RECORD_FILE = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\Logs\\ChdRecord.txt')
BASE_CLASS_DESCRIPTORS_RECORD_FILE = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\Logs\\BcdRecord.txt')

LOGFILE_FULL_PATH = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\Logs\\log_debug.txt')

######################################################
#   Class info extraction utilities
######################################################

DEMANGLER_FULL_PATH = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\Common\\demumble.exe')

GRAPH_FILE_FULL_PATH = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\')

# This folder contains files produced by the output of the MSVC CL compiler with the flag /d1reportAllClassLayout.
# Each file should start with "layout_" .
# Define the folder as a Windows environment variable named "CLASS_LAYOUT_FOLDER".
PATH_TO_LAYOUT_FOLDER = os.path.expandvars(
    '%CLASS_LAYOUT_FOLDER%')

# This file contains the JSON format for all the classes that were parsed from MSVC output in %PATH_TO_LAYOUT_FOLDER%
PATH_TO_CLASS_LAYOUTS_FILE = os.path.expandvars(
    f'%USERPROFILE%\\{BINARYNINJA_PLUGIN_FOLDER}\\CppInspector\\RttiInfomation\\ClassMemoryLayout\\class_layouts.layout')
