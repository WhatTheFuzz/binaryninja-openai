import os
from typing import Optional, Union
from pathlib import Path

import openai
from openai.api_resources.engine import Engine
from openai.error import APIError

from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja import log

from .exceptions import InvalidEngineException


class Agent:

    question: str = '''
    This is a function that was decompiled with Binary Ninja.
    It is in Binary Ninja's IL_FORM. What does this function do?
    '''

    # A mapping of IL forms to their names.
    il_name: dict[type, str] = {
        LowLevelILFunction: 'Low Level Intermediate Language',
        MediumLevelILFunction: 'Medium Level Intermediate Language',
        HighLevelILFunction: 'High Level Intermediate Language'
    }

    def __init__(self,
                function: Union[LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction],
                engine: str,
                path_to_api_key: Optional[Path]=None) -> None:

        # Read the API key from the environment variable.
        openai.api_key = self.read_api_key(path_to_api_key)

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
        if engine not in [e.id for e in engines]:
            InvalidEngineException(f'Invalid engine: {engine}. Valid engines '
                                   f'are: {[e.id for e in engines]}')

        # Set instance attributes.
        self.function = function
        self.engine = engine

    def read_api_key(self, filename: Optional[Path]=None) -> str:
        if os.getenv('OPENAI_API_KEY'):
            return os.getenv('OPENAI_API_KEY')
        if filename:
            log.log_info(f'No API key detected under the environment variable '
                         f'OPENAI_API_KEY. Reading API key from {filename}')
            try:
                with open(filename, mode='r', encoding='ascii') as api_key_file:
                    return api_key_file.read()
            except FileNotFoundError as error:
                log.log_error(f'Could not find API key file at {filename}.')

        raise APIError('No API key found. Please set the environment '
                        'variable OPENAI_API_KEY to your API key, or write '
                        'it to ~/openai/api_key.txt.')


    def instruction_list(self, function: Union[LowLevelILFunction,
                                         MediumLevelILFunction,
                                         HighLevelILFunction]) -> list[str]:
        '''Generates a list of instructions in string representation given a
        BNIL function.
        '''
        instructions: list[str] = []
        for instruction in function.instructions:
            instructions.append(str(instruction))
        return instructions

    def generate_query(self, function: Union[LowLevelILFunction,
                                       MediumLevelILFunction,
                                       HighLevelILFunction]) -> str:
        '''Generates a query string given a BNIL function. Reads the file
        prompt.txt and replaces the IL form with the name of the IL form.
        '''
        prompt: str = self.question
        # Read the prompt from the text file.
        prompt = self.question.replace('IL_FORM', self.il_name[type(function)])
        # Add some new lines. Maybe not necessary.
        prompt += '\n\n'
        # Add the instructions to the prompt.
        prompt += '\n'.join(self.instruction_list(function))
        return prompt

    def send_query(self, query: str) -> str:
        '''Sends a query to the engine and returns the response.'''
        response: str = openai.Completion.create(
            model=self.engine,
            prompt=query,
            max_tokens=2_048
        )
        return response.choices[0].text

