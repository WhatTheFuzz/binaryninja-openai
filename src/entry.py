from pathlib import Path
from binaryninja import BinaryView, Function
from binaryninja.highlevelil import HighLevelILInstruction, HighLevelILVarInit
from binaryninja.log import log_error
from . agent import Agent

API_KEY_PATH = Path.home() / Path('.openai/api_key.txt')

def check_function(bv: BinaryView, func: Function) -> None:
    agent: Agent = Agent(
        bv=bv,
        path_to_api_key=API_KEY_PATH
    )
    query: str = agent.generate_query(func)
    agent.send_query(query)

def rename_variable(bv: BinaryView, instruction: HighLevelILInstruction) -> None:

    if not isinstance(instruction, HighLevelILVarInit):
        log_error(f'Instruction must be of type HighLevelILVarInit, got type: ' \
                  f'{type(instruction)}')
        return

    agent: Agent = Agent(
        bv=bv,
        path_to_api_key=API_KEY_PATH
    )
    query: str = agent.generate_rename_variable_query(instruction)
    agent.send_query(query=query, callback=agent.rename_variable)

# Difficult to test without a payment method added, given that the rate limits
# are so low. This should also probably take place in a background task of its
# own.
# def rename_all_variables_in_function(bv: BinaryView, func: HighLevelILFunction) -> None:
#     # Get each instruction in the High Level IL Function.
#     for instruction in func.instructions:
#         match instruction:
#             # Rename the variable if it is a HighLevelILVarInit.
#             case HighLevelILVarInit():
#                 rename_variable(bv, instruction)
#             # Explicit pass for all other cases.
#             case _ :
#                 pass

