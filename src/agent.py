import os
from typing import Optional, Union
from pathlib import Path

import openai
from openai.api_resources.model import Model
from openai.error import APIError

from binaryninja.function import Function
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.settings import Settings
from binaryninja import log, BinaryView

from . query import Query
from . c import Pseudo_C


class Agent:

    question: str = '''
    This is a function that was decompiled with Binary Ninja.
    It is in IL_FORM. What does this function do?
    '''

    # A mapping of IL forms to their names.
    il_name: dict[type, str] = {
        LowLevelILFunction: 'Low Level Intermediate Language',
        MediumLevelILFunction: 'Medium Level Intermediate Language',
        HighLevelILFunction: 'High Level Intermediate Language',
        Function: 'decompiled C code'
    }

    def __init__(self,
                bv: BinaryView,
                path_to_api_key: Optional[Path]=None) -> None:

        # Read the API key from the environment variable.
        openai.api_key = self.read_api_key(path_to_api_key)

        assert bv is not None, 'BinaryView is None. Check how you called this function.'
        # Set instance attributes.
        self.bv = bv
        self.model = self.get_model()

    def read_api_key(self, filename: Optional[Path]=None) -> str:
        '''Checks for the API key in three locations.

        First, it checks the openai.api_key key:value in Binary Ninja
        preferences. This is accessed in Binary Ninja by going to Edit >
        Preferences > Settings > OpenAI.
        Second, it checks the OPENAI_API_KEY environment variable.
        Finally, it checks the file specified by the filename argument.
        Defaults to ~/.openai/api_key.txt.
        '''

        # First, check the Binary Ninja settings.
        settings: Settings = Settings()
        if settings.contains('openai.api_key'):
            if key := settings.get_string('openai.api_key'):
                return key

        # If the settings don't exist, contain the key, or the key is empty,
        # check the environment variable.
        if key := os.getenv('OPENAI_API_KEY'):
            return key

        # Finally, if the environment variable doesn't exist, check the default
        # file.
        if filename:
            log.log_info(f'No API key detected under the environment variable '
                         f'OPENAI_API_KEY. Reading API key from {filename}')
            try:
                with open(filename, mode='r', encoding='ascii') as api_key_file:
                    return api_key_file.read()
            except FileNotFoundError:
                log.log_error(f'Could not find API key file at {filename}.')

        raise APIError('No API key found. Refer to the documentation to add the '
                       'API key.')

    def is_valid_model(self, model: str) -> bool:
        '''Checks if the model is valid by querying the OpenAI API.'''
        models: list[Model] = openai.Model.list().data
        return model in [m.id for m in models]

    def get_model(self) -> str:
        '''Returns the model that the user has selected from Binary Ninja's
        preferences. The default value is set by the OpenAISettings class. If
        for some reason the user selected a model that doesn't exist, this
        function defaults to 'text-davinci-003'.
        '''
        settings: Settings = Settings()
        # Check that the key exists.
        if settings.contains('openai.model'):
            # Check that the key is not empty and get the user's selection.
            if model := settings.get_string('openai.model'):
                # Check that is a valid model by querying the OpenAI API.
                if self.is_valid_model(model):
                    return model
        # Return a valid, default model.
        assert self.is_valid_model('text-davinci-003')
        return 'text-davinci-003'

    def get_token_count(self) -> int:
        '''Returns the maximum token count specified by the user. If no value is
        set, for whatever reason, returns 1,024.'''
        settings: Settings = Settings()
        # Check that the key exists.
        if settings.contains('openai.max_tokens'):
            # Check that the value is not None.
            if (max_tokens := settings.get_integer('openai.max_tokens')) is not None:
                return max_tokens
        return 1_024

    def instruction_list(self, function: Union[LowLevelILFunction,
                                         MediumLevelILFunction,
                                         HighLevelILFunction]) -> list[str]:
        '''Generates a list of instructions in string representation given a
        BNIL function.
        '''

        # Ensure that a function type was passed in.
        if not isinstance(function, (Function, LowLevelILFunction,
                            MediumLevelILFunction, HighLevelILFunction)):
            raise TypeError(f'Expected a BNIL function of type '
                            f'Function, LowLevelILFunction, '
                            f'MediumLevelILFunction, or HighLevelILFunction, '
                            f'got {type(function)}.')

        if isinstance(function, Function):
            return Pseudo_C(self.bv, function).get_c_source()
        instructions: list[str] = []
        for instruction in function.instructions:
            instructions.append(str(instruction))
        return instructions

    def generate_query(self, function: Union[Function,
                                            LowLevelILFunction,
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

    def send_query(self, query: str) -> None:
        '''Sends a query to the engine and prints the response.'''
        query = Query(query_string=query,
                      model=self.model,
                      max_token_count=self.get_token_count())
        query.start()
