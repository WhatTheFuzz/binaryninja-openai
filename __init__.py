from binaryninja import PluginCommand
from . src.settings import OpenAISettings
from . src.entry import check_function, rename_variable, rename_all_variables_in_function

# Register the settings group in Binary Ninja to store the API key and model.
OpenAISettings()

PluginCommand.register_for_high_level_il_function(r"OpenAI\What Does this Function Do (HLIL)?",
                            "Checks OpenAI to see what this HLIL function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY or modify the path in entry.py.",
                            check_function)

PluginCommand.register_for_function(r"OpenAI\What Does this Function Do (Pseudo-C)?",
                            "Checks OpenAI to see what this pseudo-C function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY or modify the path in entry.py.",
                            check_function)

PluginCommand.register_for_high_level_il_instruction(r"OpenAI\Rename Variable (HLIL)",
                            "If the current expression is a HLIL Initialization " \
                            "(HighLevelILVarInit), then query OpenAI to rename the " \
                            "variable to what it believes is correct. If the expression" \
                            "is not an HighLevelILVarInit, then do nothing. Requires " \
                            "an internet connection and an API key. ",
                            rename_variable)

PluginCommand.register_for_high_level_il_function(r"OpenAI\Rename All Variables (HLIL)",
                            "If the current expression is a HLIL Initialization " \
                            "(HighLevelILVarInit), then query OpenAI to rename all the " \
                            "variables to what it believes is correct. Requires " \
                            "an internet connection and an API key. ",
                            rename_all_variables_in_function)