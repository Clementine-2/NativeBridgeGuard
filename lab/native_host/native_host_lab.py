"""Harmless NativeBridgeGuard lab host.

Reads framed Native Messaging JSON on stdin and replies with a framed `pong`
object. It performs NO command execution, credential access, persistence,
remote contact, or any exploit logic. The `role` / `marker` / `version` fields
exist only so a lab scenario can prove *which* registered host the browser
actually talked to, and so a replaced lab binary can be told apart by content.

Behaviour is controlled by environment variables set by the launcher .bat:
  NBG_LAB_ROLE    - "machine" or "user" (which registration answered)
  NBG_LAB_MARKER  - an arbitrary marker string (e.g. "A" / "B")
"""
from __future__ import annotations

import json
import os
import struct
import sys

ROLE = os.environ.get("NBG_LAB_ROLE", "unknown")
MARKER = os.environ.get("NBG_LAB_MARKER", "")
VERSION = "0.1.5"


def read_message():
    raw = sys.stdin.buffer.read(4)
    if not raw:
        return None
    length = struct.unpack("=I", raw)[0]
    payload = sys.stdin.buffer.read(length)
    return json.loads(payload.decode("utf-8"))


def send_message(obj):
    data = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


while True:
    msg = read_message()
    if msg is None:
        break
    send_message({
        "type": "pong",
        "role": ROLE,
        "version": VERSION,
        "marker": MARKER,
        "received": msg,
    })
