"""The Claude Code ``SessionStart`` hook that runs ``verify`` and its output shapes.

The settings shape is the one the hooks reference documents (and cc-hooks uses): an event
name mapping to matcher groups, each with a ``hooks`` list of handlers; the handler is in
exec form (``command`` plus ``args``) so paths with spaces stay one argument.

``SessionStart`` cannot block with exit code 2 (stderr is shown to the user only), so the
gate uses the universal JSON field ``continue: false`` with a ``stopReason``, printed on
exit code 0. Below the blocking threshold the hook prints a ``systemMessage`` warning.
"""

from __future__ import annotations

import json
from typing import Any

DEFAULT_MATCHER = "startup|resume"
DEFAULT_TIMEOUT = 30
STATUS_MESSAGE = "cc-plugin-lock: verifying installed plugins against the lock"


def settings_snippet(
    lock: str,
    *,
    exe: str = "cc-plugin-lock",
    root: str | None = None,
    fail_on: str = "high",
    matcher: str = DEFAULT_MATCHER,
    timeout: int = DEFAULT_TIMEOUT,
    strict: bool = True,
) -> dict[str, Any]:
    """A ``{"hooks": {"SessionStart": [...]}}`` block ready to merge into settings.json."""
    words = exe.split()
    args = [*words[1:], "verify"]
    if strict:
        args.append("--strict")
    args += ["--format", "hook", "--fail-on", fail_on, "--lock", lock]
    if root:
        args += ["--root", root]
    handler: dict[str, Any] = {
        "type": "command",
        "command": words[0],
        "args": args,
        "timeout": timeout,
        "statusMessage": STATUS_MESSAGE,
    }
    group: dict[str, Any] = {"hooks": [handler]}
    if matcher:
        group = {"matcher": matcher, **group}
    return {"hooks": {"SessionStart": [group]}}


def render_snippet(snippet: dict[str, Any]) -> str:
    return json.dumps(snippet, indent=2) + "\n"


def block(reason: str) -> dict[str, Any]:
    """Stop the session: ``continue: false`` with the reason shown to the user."""
    return {"continue": False, "stopReason": reason}


def warn(message: str) -> dict[str, Any]:
    return {"systemMessage": message}
