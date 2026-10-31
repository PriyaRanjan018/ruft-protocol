"""RUFT receiver: python3 server.py --out received"""
import argparse
import hashlib
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path

from protocol import ACK, DATA, FIN, MAX_DATA, SYN, Channel

IDLE_SECONDS = 10
MAX_NAME_BYTES = 200


def parse_syn(data):
    """Return (safe file name, size, sha256), or None if the SYN is invalid."""
    try:
        meta = json.loads(data)
        name, size, sha256 = meta["name"], meta["size"], meta["sha256"]
    except (ValueError, KeyError, TypeError):
        return None
    if not (isinstance(name, str) and isinstance(sha256, str) and type(size) is int):
        return None
    # The name comes from the network: keep only its last component so a
    # client can't write outside the output folder.
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    if name in ("", ".", "..") or "\0" in name or len(name.encode()) > MAX_NAME_BYTES:
        return None
    return (name, size, sha256) if size >= 0 else None


class Session:
    """One incoming file. Written to a .part file until its hash is verified."""

    def __init__(self, addr, syn, name, size, sha256, out):
        self.addr, self.syn, self.sha256 = addr, syn, sha256
        self.total = (size + MAX_DATA - 1) // MAX_DATA
        self.expected = 0
        self.result = None
        self.hash = hashlib.sha256()
        self.path = out / name
        self.part = out / (name + ".part")
        self.file = open(self.part, "wb")
        self.touched = time.monotonic()

    def write(self, data):
        self.file.write(data)
        self.hash.update(data)
        self.expected += 1

    def finish(self):
        self.file.close()
        if self.hash.hexdigest() == self.sha256:
            os.replace(self.part, self.path)
            self.result = b"OK"
        else:
            self.part.unlink()
            self.result = b"HASH_MISMATCH"

    def abandon(self):
        self.file.close()
        self.part.unlink()


def handle_transfer(chan, s, ptype, seq, data):
    if ptype == DATA:
        if seq == s.expected and seq < s.total:
            s.write(data)
            chan.send(ACK, seq, b"", s.addr)
        elif s.expected > 0:  # duplicate or out of order: repeat the last good ACK
            chan.send(ACK, s.expected - 1, b"", s.addr, "RE-ACK")
    elif ptype == FIN and seq == s.total and s.expected == s.total:
        if s.result is None:
            s.finish()
            chan.log.info("%s from %s:%d: %s", s.path.name, *s.addr, s.result.decode())
        chan.send(ACK, seq, s.result, s.addr)


def serve(chan, out, idle=IDLE_SECONDS):
    out.mkdir(parents=True, exist_ok=True)
    session = None
    while True:
        packet = chan.recv()
        if packet is None:
            continue
        ptype, seq, data, addr = packet
        now = time.monotonic()
        if ptype == SYN:
            meta = parse_syn(data)
            if meta is None:
                chan.log.info("invalid SYN from %s:%d ignored", *addr)
            elif session and session.addr == addr and session.syn == data:
                session.touched = now
                chan.send(ACK, seq, b"", addr)  # our first ACK was lost
            elif session is None or session.result or now - session.touched > idle:
                if session and not session.result:
                    chan.log.info("abandoned transfer of %s removed", session.path.name)
                    session.abandon()
                session = Session(addr, data, *meta, out)
                chan.log.info("receiving %s (%d bytes) from %s:%d", meta[0], meta[1], *addr)
                chan.send(ACK, seq, b"", addr)
            else:
                chan.log.info("busy: SYN from %s:%d ignored", *addr)
        elif session and session.addr == addr:
            session.touched = now
            handle_transfer(chan, session, ptype, seq, data)


def start_background(out, host="127.0.0.1", idle=IDLE_SECONDS, **channel_options):
    """Run a server on a free port in a daemon thread and return the port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    chan = Channel(sock, "server", **channel_options)
    threading.Thread(target=serve, args=(chan, Path(out), idle), daemon=True).start()
    return sock.getsockname()[1]


def main():
    p = argparse.ArgumentParser(description="Receive files over RUFT")
    p.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to accept other machines")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--out", type=Path, default=Path("received"))
    p.add_argument("--loss", type=float, default=0.0, help="chance of dropping an outgoing ACK")
    p.add_argument("--corrupt", type=float, default=0.0, help="chance of damaging an outgoing ACK")
    p.add_argument("--seed", type=int)
    p.add_argument("-v", "--verbose", action="store_true", help="log every packet")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(name)s] %(message)s")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(f"RUFT server on {args.host}:{args.port}, saving to {args.out}/")
    try:
        serve(Channel(sock, "server", args.loss, args.corrupt, args.seed), args.out)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
