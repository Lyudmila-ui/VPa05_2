"""Папка данных: рядом с .exe или с исходниками."""

import os
import sys
from pathlib import Path


def app_dir() -> Path:
    override = os.environ.get("VAULT_HOME")
    if override:
        path = Path(override)
        path.mkdir(parents=True, exist_ok=True)
        return path
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent
