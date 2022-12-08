from pathlib import Path
from binaryninja import BinaryView, Function
from . agent import Agent

API_KEY_PATH = Path.home() / Path('.openai/api_key.txt')

# We don't use the bv argument, but it gets passed in by the PluginCommand.
# pylint: disable=unused-argument
def check_function(bv: BinaryView, func: Function) -> bool:
    agent: Agent = Agent(
        function=func,
        path_to_api_key=API_KEY_PATH
    )
    query: str = agent.generate_query(func)
    response: str = agent.send_query(query)
    print(response)
