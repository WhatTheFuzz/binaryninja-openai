from pathlib import Path
from binaryninja import BinaryView, Function
from . agent import Agent

API_KEY_PATH = Path.home() / Path('.openai/api_key.txt')

def check_function(bv: BinaryView, func: Function) -> bool:
    agent: Agent = Agent(
        bv=bv,
        function=func,
        path_to_api_key=API_KEY_PATH
    )
    query: str = agent.generate_query(func)
    agent.send_query(query)
