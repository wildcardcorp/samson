from IPython.terminal.prompts import Prompts
from pygments.token import Token
from datetime import datetime
import os

import os
import pwd
import platform

def get_username():
    return pwd.getpwuid(os.getuid())[0]

class SamsonPrompt(Prompts):
    def __init__(self, shell):
        super().__init__(shell)
        self.last_time = None
        self.last_time_diff = 0
        self.shell.events.register('pre_execute', self.pre_execute)
        self.shell.events.register('post_execute', self.post_execute)
        self.user_machine_sep = '@'

    def in_prompt_tokens(self, cli=None):
        return [
            (Token.Prompt, '┌──('),
            (Token.PromptNum, "samson"),
            (Token.Prompt, ')─['),
            (Token.PromptNum, str(self.shell.execution_count)),
            (Token.Prompt, ']─['),
            (Token.PromptNum, f'{datetime.now().strftime("%H:%M:%S")}'),
            (Token.Prompt, ']─['),
            (Token.PromptNum, f'{self.last_time_diff}'),
            (Token.Prompt, ']─['),
            (Token.PromptNum, f'{get_username()}{self.user_machine_sep}{platform.node()}'),
            (Token.Prompt, ']─['),
            (Token.PromptNum, f'{os.getcwd()}'),
            (Token.Prompt, ']\n└─$ '),
        ]

    def out_prompt_tokens(self, cli=None):
        return []


    def continuation_prompt_tokens(self, width=None):
        if width is None:
            width = self._width()
        return [
            (Token.Prompt, (' ' * (width - 5)) + '..: '),
        ]
    

    def pre_execute(self):
        self.last_time = datetime.now()

    def post_execute(self):
        self.last_time_diff = datetime.now() - self.last_time
