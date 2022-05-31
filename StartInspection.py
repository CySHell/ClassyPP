"""
import CppInspector
import importlib
importlib.reload(CppInspector);
CppInspector.StartInspection.inspect(bv)
"""

import binaryninja as bn
from .RttiInfomation.ClassContext import GlobalClassContextManager
from .Common import Utils
from . import Config
from .RttiInfomation import TypeCreation

def is_bv_valid_for_plugin(bv: bn.binaryview) -> bool:
    if bv.arch.name != "x86_64":
        print(f'ClassyPP: Detected non 64bit executable - Unsupported.')
        return False
    return True

class InspectInBackground(bn.BackgroundTaskThread):

    def __init__(self, bv: bn.binaryview):
        bn.BackgroundTaskThread.__init__(self, "ClassyPP - Performing inspection and extraction...", True)
        self.bv = bv

    def run(self):
        self.RTTI_inspection()

    def RTTI_inspection(self):
        Utils.LogToFile(f'Logging filename: {Config.LOGFILE_FULL_PATH}')
        Utils.LogToFile(f'inspect: Starting Scan.')
        if TypeCreation.CreateTypes(self.bv):
            GCM: GlobalClassContextManager = GlobalClassContextManager(self.bv)
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
        background_thread = InspectInBackground(bv)
        background_thread.start()

