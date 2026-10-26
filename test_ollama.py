import ollama

code = '''
def get_user(db, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
'''

# d3 decides whether the vulnerability is present
detect = ollama.systemone(
    model='d3',
    state=code,
    questions={
        'sql_injection': {
            'type': 'noul',
            'instructions': 'Does this code contain a SQL injection vulnerability?',
            'criteria': {
                'true': 'User input is concatenated into a SQL query.',
                'false': 'Queries are parameterised or no user input reaches a query.',
            },
        },
    },
)
print(detect)

# qwen explains what is wrong and how to fix it
explain = ollama.chat(
    model='qwen2.5-coder:7b',
    messages=[{
        'role': 'user',
        'content': 'This Python function may have a SQL injection vulnerability. '
                   'Explain what is wrong and show a fixed version.\n\n' + code,
    }],
)
print(explain.message.content)