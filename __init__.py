from binaryninja import PluginCommand
from . src.entry import check_function

PluginCommand.register_for_high_level_il_function("What Does this Function Do?",
                            "Checks OpenAI to see what this function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY",
                            check_function)
