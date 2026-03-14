from __future__ import annotations

from aegisrt.utils.hashing import hash_case, hash_config
from aegisrt.utils.redact import redact_secrets
from aegisrt.utils.concurrency import run_concurrent

def test_hash_case_deterministic():
    h1 = hash_case("hello world")
    h2 = hash_case("hello world")
    assert h1 == h2
    assert len(h1) == 16

def test_hash_case_different_inputs():
    h1 = hash_case("alpha")
    h2 = hash_case("beta")
    assert h1 != h2

def test_hash_config_deterministic():
    cfg = {"model": "gpt-4", "temperature": 0.7}
    h1 = hash_config(cfg)
    h2 = hash_config(cfg)
    assert h1 == h2
    assert len(h1) == 64

def test_hash_config_key_order_insensitive():
    a = hash_config({"a": 1, "b": 2})
    b = hash_config({"b": 2, "a": 1})
    assert a == b

def test_redact_secrets_masks_api_key():
    text = "My key is sk-abcdefghijklmnopqrstuvwxyz1234567890"
    result = redact_secrets(text)
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in result
    assert "REDACTED" in result

def test_redact_secrets_masks_aws_key():
    text = "Key is AKIAIOSFODNN7EXAMPLE"
    result = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "REDACTED" in result

def test_redact_secrets_preserves_normal_text():
    text = "The quick brown fox jumps over the lazy dog."
    result = redact_secrets(text)
    assert result == text

def test_redact_secrets_masks_github_token():
    text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    result = redact_secrets(text)
    assert "ghp_" not in result or "REDACTED" in result

def test_redact_secrets_masks_password():
    text = "password='super_secret_password_123'"
    result = redact_secrets(text)
    assert "super_secret_password_123" not in result
    assert "REDACTED" in result

def test_run_concurrent_preserves_order():
    items = [1, 2, 3, 4, 5]
    results = run_concurrent(lambda x: x * 10, items, max_workers=2)
    assert results == [10, 20, 30, 40, 50]

def test_run_concurrent_empty_list():
    results = run_concurrent(lambda x: x, [], max_workers=2)
    assert results == []

def test_run_concurrent_propagates_exception():
    import pytest

    def fail(x):
        if x == 3:
            raise ValueError("boom")
        return x

    with pytest.raises(ValueError, match="boom"):
        run_concurrent(fail, [1, 2, 3, 4], max_workers=2)
