"""A deliberately vulnerable LLM application.

This file contains multiple security anti-patterns that AegisRT's
static audit scanner (``aegisrt audit``) should detect.  It exists
purely as a teaching aid -- DO NOT use patterns like these in production.

Expected findings when scanned:
  AUD001  - f-string prompt construction from user input
  AUD002  - LLM response used without validation
  AUD004  - Hardcoded API key
  AUD007  - No moderation / safety check
  AUD008  - exec() on model output
"""

import openai

# AUD004 -- hardcoded API key in source code
client = openai.OpenAI(api_key="sk-proj-FAKE0000000000000000000000000000000000000000KEY1")


def handle_user_request(user_input: str) -> str:
    # AUD001 -- f-string builds the prompt directly from user input,
    # making it trivial to inject instructions.
    prompt = f"Answer the following user question: {user_input}"

    # AUD006 would fire here too if the messages list lacked a system
    # role, but we include one to keep the example focused.
    # AUD002 -- response is used without any validation or parsing.
    # AUD007 -- no moderation or safety check anywhere in this module.
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt},
        ],
    )

    result = response.choices[0].message.content

    # AUD008 -- model output passed directly to exec().
    # An attacker who controls the prompt can get arbitrary
    # code execution on the server.
    if result.startswith("```python"):
        code = result.strip("```python").strip("```").strip()
        exec(code)

    return result
