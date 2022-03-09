"""
import CppInspector
import importlib
importlib.reload(CppInspector);
CppInspector.StartInspection.inspect(bv)
"""

import binaryninja as bn
from .ClassHierarchy.ClassContext import GlobalClassContextManager
from .Common import Utils
from . import Config
from . import TypeCreation


def internal_inspect(bv: bn.binaryview):
    Utils.LogToFile(f'Logging filename: {Config.LOGFILE_FULL_PATH}')
    Utils.LogToFile(f'inspect: Starting Scan.')
    if bv.arch.address_size != 0x8:
        print(f'ClassyPP: Detected non 64bit executable - Unsupported.')
        return
    if TypeCreation.CreateTypes(bv):
        GCM: GlobalClassContextManager = GlobalClassContextManager(bv)
        if GCM.DefineRTTI():
            Utils.LogToFile(f'ClassyPP: Successfully created types.')
        else:
            Utils.LogToFile(f'ClassyPP: Failed to create RTTI classes.')
    else:
        Utils.LogToFile(f'ClassyPP: Failed to create types.')


def inspect(bv: bn.binaryview):
    if bv.analysis_info.state != 2:
        print(f'ClassyPP: Binja analysis still ongoing, please run this plugin only after analysis completes.')
    else:
        internal_inspect(bv)
