from binaryninja import PluginCommand
from . src.settings import OpenAISettings
from . src.entry import check_function

# Register the settings group in Binary Ninja to store the API key and model.
OpenAISettings()

PluginCommand.register_for_high_level_il_function("OpenAI\What Does this Function Do (HLIL)?",
                            "Checks OpenAI to see what this HLIL function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY or modify the path in entry.py.",
                            check_function)

PluginCommand.register_for_function("OpenAI\What Does this Function Do (Pseudo-C)?",
                            "Checks OpenAI to see what this pseudo-C function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY or modify the path in entry.py.",
                            check_function)
