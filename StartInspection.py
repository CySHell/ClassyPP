import cProfile
import pprint
import binaryninja as bn
from .RttiInformation.ClassContext import GlobalClassContextManager
from .Common import Utils
from . import Config
from .RttiInformation import TypeCreation
from .ClassDataStructureDetection.Constructors import DetectConstructor
from .RttiInformation.VirtualTableInference import VirtualFunctionTable


def is_bv_valid_for_plugin(bv: bn.binaryview) -> bool:
    if bv.arch.name == "x86_64" or bv.arch.name == "x86":
        return True
    else:
        print(f'ClassyPP: Executable CPU Arch is: {bv.arch.name}. This plugin supports only x86 32/64 bit executables.')
        return False


def GetUserInputs() -> bool:
    if Config.ENABLE_LOGGING or Config.ENABLE_DEBUG_LOGGING:
        Utils.logging_file = Utils.GetLogfileHandle()

    choice = bn.interaction.ChoiceField("",
                                        ["Add comment for function", "Change name of function",
                                         "Do not detect constructors"])
    bn.interaction.get_form_input([choice], "Constructor functions handling mode")
    Config.CONSTRUCTOR_FUNCTION_HANDLING = choice.result
    return True


def CleanupPlugin():
    if Config.ENABLE_LOGGING or Config.ENABLE_DEBUG_LOGGING:
        Utils.logging_file.close()


class InspectInBackground(bn.BackgroundTaskThread):

    def __init__(self, bv: bn.binaryview):
        bn.BackgroundTaskThread.__init__(
            self, "ClassyPP - Performing inspection and extraction...", True)
        self.bv = bv

    def run(self):
        cProfile.runctx('self.run_stub()', globals(), locals(), "C:\\xd.txt")
        
    def run_stub(self):
        try:
            # if GetUserInputs():
            if Config.ENABLE_LOGGING or Config.ENABLE_DEBUG_LOGGING:
                Utils.logging_file = Utils.GetLogfileHandle()
            self.RTTI_inspection()
            self.DetectAndVerifyConstructor()
            self.bv.update_analysis_and_wait()
        except KeyboardInterrupt:
            Utils.LogToFile('Cancelled by user request')
            print('Cancelled by user request')
        CleanupPlugin()

    def DetectAndVerifyConstructor(self):
        if Config.CONSTRUCTOR_FUNCTION_HANDLING != 2:
            # Iterate over all found vfTables and detect their constructors
            print(f'ClassyPP: Constructor Detection process started...')
            Utils.LogToFile(str(VirtualFunctionTable.global_vfTables))
            VirtualFunctionTable.DetectVTables(self.bv, self)

    def RTTI_inspection(self) -> bool:
        Utils.LogToFile(f'inspect: Starting Scan.')
        if TypeCreation.CreateTypes(self.bv):
            GCM: GlobalClassContextManager = GlobalClassContextManager(
                self.bv, self)
            if GCM.DetectAndDefineAllInformation():
                Utils.LogToFile(f'ClassyPP: Successfully created types.')
                print(f'ClassyPP: Successfully defined RTTI Information.')
                return True
            else:
                Utils.LogToFile(f'ClassyPP: Failed to create RTTI classes.')
        else:
            Utils.LogToFile(f'ClassyPP: Failed to create types.')
        return False


def inspect(bv: bn.binaryview):
    if bv.analysis_info.state != 2:
        print(f'ClassyPP: Binja analysis still ongoing, please run this plugin only after analysis completes.')
    else:
        background_thread = InspectInBackground(bv)
        background_thread.start()
