from binaryninja import PluginCommand
from . src.entry import check_function

PluginCommand.register_for_high_level_il_function("OpenAI\What Does this Function Do (HLIL)?",
                            "Checks OpenAI to see what this HLIL function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY or modify the path in entry.py.",
                            check_function)
