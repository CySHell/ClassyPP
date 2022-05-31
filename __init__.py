"""
from .RttiInfomation import TypeCreation
from .RttiInfomation import BaseClassDescriptor, ClassContext, \
    ClassHierarchyDescriptor, CompleteObjectLocator, TypeDescriptor, \
    BaseClassArray, VirtualFunctionTable, ClassHierarchyDeduction
from .Common import Utils
from . import Config
from .RttiInfomation.ClassMemoryLayout import ClassStructCreation, LayoutParser, LayoutLoader
import importlib

importlib.reload(StartInspection)
importlib.reload(BaseClassDescriptor)
importlib.reload(BaseClassArray)
importlib.reload(ClassContext)
importlib.reload(ClassHierarchyDescriptor)
importlib.reload(CompleteObjectLocator)
importlib.reload(TypeDescriptor)
importlib.reload(TypeCreation)
importlib.reload(VirtualFunctionTable)
importlib.reload(Utils)
importlib.reload(Config)
importlib.reload(ClassHierarchyDeduction)
importlib.reload(LayoutLoader)
importlib.reload(LayoutParser)
importlib.reload(ClassStructCreation)
"""

import binaryninja as bn
from . import StartInspection

bn.PluginCommand.register("ClassyPP",
                          "Parse and extract class information from MSVC x64 C++ binaries",
                          StartInspection.inspect,
                          StartInspection.is_bv_valid_for_plugin)
