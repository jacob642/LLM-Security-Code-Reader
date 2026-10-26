## this file will  detect the vulnabiltiy,, explain whats happening, models together so D3 sends the vulnability if true to Qwen,
#imports
import ollama
from src.prompts import questions, EXPLAIN_PROMPT
from pydantic import BaseModel

class Explanation(BaseModel):
    vulnerable_line: str
    is_vulnerable: bool
    Explaination: str
    fixed_code: str

def detect(cwes,code):
    response = ollama.systemone(
        model = 'd3',
        state=code,
        questions={c: questions[c] for c in cwes} 
    )
    return {c: response.answers[c].noul for c in cwes}

def explain(code, cwes):
    response = ollama.chat(
        model='qwen2.5-coder:7b',
        messages=[{'role': 'user',
                   'content': EXPLAIN_PROMPT.format(cwes=cwes, code=code)}],
        format=Explanation.model_json_schema(),
    )
    return Explanation.model_validate_json(response.message.content)