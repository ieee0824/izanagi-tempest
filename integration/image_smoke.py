#!/usr/bin/env python3
"""Boot the M3 image through pinned Izanagi and collect private VM evidence."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import select
import secrets
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'image'))
from transport import Mailbox
from trace_evidence import trace_probe_evidence
from artifact_evidence import PATHS as ARTIFACT_PATHS, validate_offline, validate_actor
from exec_evidence import ExecEvidence, MarkerLeak
from proc_evidence import CONTROL_KEY, CONTROL_VALUE
import proc_paging
import sidecar_evidence
import network_evidence


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--izanagi', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--build-inputs', type=Path, help='prepare.py inputs.json; defaults to the standard build layout')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--offline-artifacts', type=Path, help='read-only image inspection report bound to this exact image')
    parser.add_argument('--network-evidence', action='store_true',
                        help='dedicated host-endpoint TCP controls; requires fixed Linux observer and --exec-evidence')
