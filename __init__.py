from binaryninja import PluginCommand

PluginCommand.register_for_address("What Does this Function Do?",
                            "Checks OpenAI to see what this function does." \
                            "Requires an internet connection and an API key "
                            "saved under the environment variable "
                            "OPENAI_API_KEY",
                            TODO)