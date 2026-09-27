"""Harmless Native Messaging lab host: reads framed JSON and replies with a pong object."""
from __future__ import annotations

import json
import struct
import sys


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
    send_message({"type":"pong","received":msg})
