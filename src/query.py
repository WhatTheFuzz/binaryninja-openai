from __future__ import annotations
from collections.abc import Callable
from typing import Optional
import openai
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.log import log_debug, log_info

class Query(BackgroundTaskThread):

    def __init__(self, query_string: str, model: str,
                 max_token_count: int, callback_function: Optional[Callable]=None) -> None:
        BackgroundTaskThread.__init__(self,
                                      initial_progress_text="",
                                      can_cancel=False)
        self.query_string: str = query_string
        self.model: str = model
        self.max_token_count: int = max_token_count
        self.callback = callback_function

    def run(self) -> None:
        self.progress = "Submitting query to OpenAI."
        if self.model in ["gpt-3.5-turbo","gpt-4","gpt-4-32k"]:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role":"user","content":self.query_string}],
                max_tokens=self.max_token_count,
            )
            # Get the response text.
            result: str = response.choices[0].message.content
        else:
            response = openai.Completion.create(
                model=self.model,
                prompt=self.query_string,
                max_tokens=self.max_token_count,
            )
            # Get the response text.
            result: str = response.choices[0].text
        # If there is a callback, do something with it.
        if self.callback:
            self.callback(result)
        # Otherwise, assume we just want to log it.
        else:
            log_info(result)
