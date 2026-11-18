#!/usr/bin/env python3
"""Fixture for losing one actual OpenSSH hardlink acknowledgment."""

import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys


MAX_FRAME = 256 << 10
STATUS = 101
EXTENDED = 200
HARDLINK = b'hardlink@openssh.com'


def frame(stream):
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise ValueError('partial SFTP frame header')
    size = struct.unpack('>I', header)[0]
    if not 1 <= size <= MAX_FRAME:
        raise ValueError('SFTP frame outside fixture bound')
    packet = stream.read(size)
    if len(packet) != size:
        raise ValueError('partial SFTP frame')
    return header, packet


def publication_ack(request, response):
    prefix = bytes([EXTENDED]) + request[1:5] + struct.pack('>I', len(HARDLINK)) + HARDLINK
    return (len(request) > len(prefix) and request.startswith(prefix) and len(response) >= 9
            and response[:9] == bytes([STATUS]) + request[1:5] + b'\0' * 4)


def main(server, directory, marker):
    os.umask(0o077)
    marker = Path(marker)
    code = 0
    # Once the real daemon has accepted the hardlink, subsequent sessions use
    # the stock server's read-only mode. No change to SSH authentication or pins.
    with subprocess.Popen([server, '-d', directory, *(['-R'] if marker.exists() else [])],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
        try:
            while request := frame(sys.stdin.buffer):
                child.stdin.write(request[0] + request[1])
                child.stdin.flush()
                response = frame(child.stdout)
                if response is None:
                    raise ValueError('stock SFTP exited before its reply')
                if publication_ack(request[1], response[1]):
                    # Only a real success for this exact request can trigger a
                    # lost reply. Preserve its digest and close the channel.
                    with marker.open('x') as witness:
                        witness.write(hashlib.sha256(response[0] + response[1]).hexdigest() + '\n')
                        witness.flush()
                        os.fsync(witness.fileno())
                    break
                sys.stdout.buffer.write(response[0] + response[1])
                sys.stdout.buffer.flush()
        finally:
            child.stdin.close()
            try:
                code = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                raise
    return code


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
