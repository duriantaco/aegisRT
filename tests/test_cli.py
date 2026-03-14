
from __future__ import annotations

import warnings

from click.testing import CliRunner

from aegisrt.cli import main

def test_doctor_does_not_emit_deprecation_warnings():
    runner = CliRunner()

    with runner.isolated_filesystem():
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = runner.invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert not any(issubclass(w.category, DeprecationWarning) for w in caught)
