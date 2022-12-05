import os

import openai
from openai.api_resources.engine import Engine
from openai.error import APIError

from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from binaryninja.highlevelil import HighLevelILFunction

from .exceptions import InvalidEngineException


class Agent:

    def ___init__(self, function: LowLevelILFunction | MediumLevelILFunction |
                                  HighLevelILFunction, engine: str) -> None:

        # Read the API key from the environment variable.
        openai.api_key = os.getenv('OPENAI_API_KEY')
        if openai.api_key is None:
            raise APIError('No API key found. Please set the environment '
                           'variable OPENAI_API_KEY to your API key.')

        # Ensure that a function type was passed in.
        if not isinstance(
                function,
            (LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction)):
            raise TypeError(f'Expected a BNIL function of type '
                            f'LowLevelILFunction, MediumLevelILFunction, or '
                            f'HighLevelILFunction, got {type(function)}.')

        # Get the list of available engines.
        engines: list[Engine] = openai.Engine.list().data
        # Ensure the user's selected engine is available.
        # pylint: disable=unnecessary-comprehension
        if engine not in [i.id for i in engines]:
            InvalidEngineException(f'Invalid engine: {engine}. Valid engines '
                                   f'are: {[id for id in engines.id]}')

        # Set instance attributes.
        self.function = function
        self.engine = engine

    def instruction_list(self, function: LowLevelILFunction |
                                         MediumLevelILFunction |
                                         HighLevelILFunction) -> list[str]:
        '''Generates a list of instructions in string representation given a
        BNIL function.
        '''
        instructions: list[str] = []
        for instruction in function.instructions:
            instructions.append(str(instruction))
        return instructions
