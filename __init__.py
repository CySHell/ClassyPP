import binaryninja as bn
from . import StartInspection

bn.PluginCommand.register("ClassyPP",
                          "Parse and extract class information from MSVC x64 C++ binaries",
                          StartInspection.inspect,
                          StartInspection.is_bv_valid_for_plugin)
