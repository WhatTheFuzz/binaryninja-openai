import openai
from binaryninja.plugin import BackgroundTaskThread


class Query(BackgroundTaskThread):

    def __init__(self, query_string: str, model: str,
                 max_token_count: int) -> None:
        BackgroundTaskThread.__init__(self,
                                      initial_progress_text="",
                                      can_cancel=False)
        self.query_string: str = query_string
        self.model: str = model
        self.max_token_count: int = max_token_count

    def run(self) -> None:
        self.progress = "Submitting query to OpenAI."

        response: str = openai.Completion.create(
            model=self.model,
            prompt=self.query_string,
            max_tokens=self.max_token_count,
        )
        # Notify the user.
        print(response.choices[0].text)
