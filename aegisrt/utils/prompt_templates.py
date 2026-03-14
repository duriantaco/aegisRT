from __future__ import annotations

import re
from string import Template

_BRACE_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render_prompt_template(template: str, **values: object) -> str:
    rendered_values = {
        key: "" if value is None else str(value)
        for key, value in values.items()
    }
    rendered = Template(template).safe_substitute(rendered_values)

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in rendered_values:
            return match.group(0)
        return rendered_values[key]

    return _BRACE_PLACEHOLDER_RE.sub(_replace, rendered)
