from binaryninja import BinaryView, Function
from . agent import Agent

def check_function(bv: BinaryView, func: Function) -> bool:
    agent = Agent(function=func, engine='code-davinci-002')
    print(agent.generate_query(func))
