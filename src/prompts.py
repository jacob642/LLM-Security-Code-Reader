#

questions={
        'SQL injection (CWE-89)': {
            'type': 'noul',
            'instructions': 'does code contain any sign of SQL-specific criteria that can be seen in CWE 89',
            'criteria': {
                'true': 'User input is concatenated into a SQL query.',
                'false': 'Queries are parameterised or no user input reaches a query.',
            },
        },
    }

# this needs to be tested with different vulnabilitites.

# qwen explains what is wrong and how to fix it

EXPLAIN_PROMPT = (
    "A scanner suspects this Python code has {cwes}. Decide whether it is really "
    "vulnerable. If it is not, set is_vulnerable to false and explain why. If it is, "
    "quote the vulnerable line, explain the root cause, and give a fixed version of "
    "the whole function without changing what it does.\n\nCode:\n{code}"
)
