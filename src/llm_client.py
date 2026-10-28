# This module uses D3 to detect vulnerabilities and Qwen to explain them.

import ollama
from src.prompts import questions, EXPLAIN_PROMPT
from pydantic import BaseModel
import time


class Explanation(BaseModel):
    vulnerable_line: str
    is_vulnerable: bool
    Explaination: str
    fixed_code: str

# Use D3 to score the supplied code against each requested CWE, and time the request.
def detect(cwes, code):
    start = time.perf_counter()
    response = ollama.systemone(
        model='d3',
        state=code,
        questions={c: questions[c] for c in cwes},
    )
    seconds = time.perf_counter() - start
    scores = {c: response.answers[c].noul for c in cwes}
    return scores, seconds

# Use Qwen to explain detected issues and return the explanation as structured JSON.
def explain(code, cwes):
    start = time.perf_counter()
    response = ollama.chat(
        model='qwen2.5-coder:7b',
        messages=[{'role': 'user',
                   'content': EXPLAIN_PROMPT.format(cwes=cwes, code=code)}],
        format=Explanation.model_json_schema(),
    )
    seconds = time.perf_counter() - start
    return Explanation.model_validate_json(response.message.content), seconds