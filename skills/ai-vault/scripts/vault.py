#!/usr/bin/env python3
"""Compatibility launcher; all credential behavior belongs to the installed repository CLI."""
import os
from pathlib import Path
import shutil
import sys

command = shutil.which('ai-vault')
if command is None:
    candidate = Path.home() / '.local/bin/ai-vault'
    if candidate.is_file() and os.access(candidate, os.X_OK):
        command = str(candidate)
if command is None:
    print('Install the repository CLI first: uv tool install /path/to/ai-vault', file=sys.stderr)
    raise SystemExit(1)
os.execv(command, [command, *sys.argv[1:]])
