from openai.error import OpenAIError

class InvalidEngineException(OpenAIError):
    pass

class RegisterSettingsGroupException(Exception):
    pass

class RegisterSettingsKeyException(Exception):
    pass
