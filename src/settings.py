import json
from binaryninja.settings import Settings
from . exceptions import RegisterSettingsGroupException, \
                         RegisterSettingsKeyException

class OpenAISettings(Settings):

    def __init__(self) -> None:
        # Initialize the settings with the default instance ID.
        super().__init__(instance_id='default')
        # Register the OpenAI group.
        if not self.register_group('openai', 'OpenAI'):
            raise RegisterSettingsGroupException('Failed to register OpenAI '
                                                 'settings group.')
        # Register the setting for the API key.
        if not self.register_api_key_settings():
            raise RegisterSettingsKeyException('Failed to register OpenAI API '
                                               'key settings.')

        # Register the setting for the model used to query.
        if not self.register_model_settings():
            raise RegisterSettingsKeyException('Failed to register OpenAI '
                                               'model settings.')

    def register_api_key_settings(self) -> bool:
        '''Register the OpenAI API key settings in Binary Ninja.'''
        # Set the attributes of the settings. Refer to:
        # https://api.binary.ninja/binaryninja.settings-module.html
        properties = {
            'title': 'OpenAI API Key',
            'type': 'string',
            'description': 'The user\'s OpenAI API key used to make requests '
            'the server.'
        }
        return self.register_setting('openai.api_key', json.dumps(properties))

    def register_model_settings(self) -> bool:
        '''Register the OpenAI model settings in Binary Ninja.
        Defaults to text-davinci-003.
        '''
        # Set the attributes of the settings. Refer to:
        # https://api.binary.ninja/binaryninja.settings-module.html
        properties = {
            'title': 'OpenAI Model',
            'type': 'string',
            'description': 'The OpenAI model used to generate the response.',
            'default': 'text-davinci-003'
        }
        return self.register_setting('openai.model', json.dumps(properties))
