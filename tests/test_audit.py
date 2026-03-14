from __future__ import annotations

import ast

from aegisrt.audit.rules import (
    PromptConcatenationRule,
    DangerousExecRule,
    HardcodedSecretsInPromptsRule,
)
from aegisrt.audit.discover import DiscoveryScanner

def _parse(source: str) -> ast.Module:
    return ast.parse(source, filename="<test>")

def test_prompt_concatenation_rule(tmp_path):
    code = '''\
import openai

def ask(user_input: str):
    prompt = f"Answer this: {user_input}"
    openai.chat.completions.create(messages=[{"role": "user", "content": prompt}])
'''
    src_file = tmp_path / "app.py"
    src_file.write_text(code, encoding="utf-8")

    tree = _parse(code)
    rule = PromptConcatenationRule()
    findings = rule.match(tree, str(src_file))

    assert len(findings) > 0
    assert findings[0].rule_id == "AUD001"
    assert findings[0].severity == "high"

def test_dangerous_exec_rule(tmp_path):
    code = '''\
import openai

response = openai.chat.completions.create(messages=[])
code = response.choices[0].message.content
exec(code)
'''
    src_file = tmp_path / "danger.py"
    src_file.write_text(code, encoding="utf-8")

    tree = _parse(code)
    rule = DangerousExecRule()
    findings = rule.match(tree, str(src_file))

    assert len(findings) > 0
    assert findings[0].rule_id == "AUD008"
    assert findings[0].severity == "critical"

def test_hardcoded_secrets_rule(tmp_path):
    code = '''\
import openai

prompt = "Use api_key='sk-abcdefghijklmnopqrstuvwxyz1234' for auth"
'''
    src_file = tmp_path / "secrets.py"
    src_file.write_text(code, encoding="utf-8")

    tree = _parse(code)
    rule = HardcodedSecretsInPromptsRule()
    findings = rule.match(tree, str(src_file))

    assert len(findings) > 0
    assert findings[0].rule_id == "AUD004"
    assert findings[0].severity == "critical"

def test_clean_code_passes(tmp_path):
    code = '''\
import openai
from pydantic import BaseModel

class Response(BaseModel):
    answer: str

def ask(user_input: str):
    result = openai.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input},
        ]
    )
    text = result.choices[0].message.content
    parsed = Response.model_validate({"answer": text})
    return parsed.answer
'''
    src_file = tmp_path / "clean.py"
    src_file.write_text(code, encoding="utf-8")
    tree = _parse(code)

    concat_rule = PromptConcatenationRule()
    assert len(concat_rule.match(tree, str(src_file))) == 0

    secrets_rule = HardcodedSecretsInPromptsRule()
    assert len(secrets_rule.match(tree, str(src_file))) == 0

    exec_rule = DangerousExecRule()
    assert len(exec_rule.match(tree, str(src_file))) == 0

def test_discovery_scanner_finds_openai_import(tmp_path):
    code = "import openai\n"
    (tmp_path / "llm_app.py").write_text(code, encoding="utf-8")

    scanner = DiscoveryScanner()
    report = scanner.scan(tmp_path)

    assert len(report.findings) >= 1
    assert any(f.module_name == "openai" for f in report.findings)
    assert any(f.integration_type == "llm" for f in report.findings)

def test_discovery_scanner_finds_langchain(tmp_path):
    code = "from langchain.chains import LLMChain\n"
    (tmp_path / "chain_app.py").write_text(code, encoding="utf-8")

    scanner = DiscoveryScanner()
    report = scanner.scan(tmp_path)

    assert len(report.findings) >= 1
    assert any("langchain" in f.module_name for f in report.findings)
    assert any(f.integration_type == "framework" for f in report.findings)

def test_discovery_scanner_empty_dir(tmp_path):
    scanner = DiscoveryScanner()
    report = scanner.scan(tmp_path)
    assert len(report.findings) == 0

def test_discovery_scanner_non_llm_code(tmp_path):
    code = "import os\nimport json\nprint('hello')\n"
    (tmp_path / "plain.py").write_text(code, encoding="utf-8")

    scanner = DiscoveryScanner()
    report = scanner.scan(tmp_path)
    assert len(report.findings) == 0
