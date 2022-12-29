import openai
from typing import Callable
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.highlevelil import HighLevelILInstruction
from binaryninja.log import log_info

class Query(BackgroundTaskThread):

    def __init__(self, query_string: str, model: str,
                 max_token_count: int, callback_function: Callable=None) -> None:
        BackgroundTaskThread.__init__(self,
                                      initial_progress_text="",
                                      can_cancel=False)
        self.query_string: str = query_string
        self.model: str = model
        self.max_token_count: int = max_token_count
        self.callback = callback_function

    def run(self) -> None:
        self.progress = "Submitting query to OpenAI."

        response: str = openai.Completion.create(
            model=self.model,
            prompt=self.query_string,
            max_tokens=self.max_token_count,
        )
        # Get the response text.
        response: str = response.choices[0].text
        # If there is a callback, do something with it.
        if self.callback:
            self.callback(response)
        # Otherwise, assume we just want to log it.
        else:
            log_info(response)