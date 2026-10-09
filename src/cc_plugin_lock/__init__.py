"""cc-plugin-lock: a lock file for Claude Code plugins.

Pins every installed Claude Code marketplace plugin to a content hash, verifies the
installed files against the lock before a session uses them, shows what changed, and
statically scans a plugin folder before it is installed.
"""

from __future__ import annotations

__version__ = "0.2.0"

__all__ = ["__version__"]
