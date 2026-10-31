"""RUFT sender: python3 client.py myfile.pdf --window 8"""
import argparse
import hashlib
import json
import logging
import socket
import sys
import time
from pathlib import Path

from protocol import ACK, DATA, FIN, HANDSHAKE_SEQ, MAX_DATA, SYN, Channel

MAX_RETRIES = 20


class TransferError(Exception):
    pass


def recv_ack(chan, addr, timeout):
    """Return (seq, data) of an ACK from addr, or None."""
    packet = chan.recv(timeout)
    if packet and packet[0] == ACK and packet[3] == addr:
        return packet[1], packet[2]
    return None


def request(chan, addr, ptype, seq, data, timeout):
    """Send one control packet until its ACK arrives; return the ACK's data."""
    for attempt in range(MAX_RETRIES):
        chan.send(ptype, seq, data, addr, "RETRANSMIT" if attempt else "SEND")
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            ack = recv_ack(chan, addr, left)
            if ack and ack[0] == seq:
                return ack[1]
        chan.log.debug("TIMEOUT waiting for ACK %d", seq)
    raise TransferError(f"no reply from {addr[0]}:{addr[1]} after {MAX_RETRIES} tries")


def send_window(chan, addr, f, total, window, timeout):
    """Go-Back-N: keep up to `window` packets in flight, resend all on timeout.

    Returns (retransmits, timeouts). window=1 is stop-and-wait.
    """
    base = next_seq = highest = 0  # oldest unACKed, next to send, next never-sent
    retransmits = timeouts = tries = 0
    deadline = time.monotonic() + timeout
    while base < total:
        while next_seq < min(base + window, total):
            f.seek(next_seq * MAX_DATA)
            resend = next_seq < highest
            retransmits += resend
            chan.send(DATA, next_seq, f.read(MAX_DATA), addr, "RETRANSMIT" if resend else "SEND")
            next_seq += 1
            highest = max(highest, next_seq)

        ack = recv_ack(chan, addr, max(deadline - time.monotonic(), 0.0001))
        if ack and base <= ack[0] < next_seq:  # cumulative: everything up to ack[0] arrived
            base = ack[0] + 1
            tries = 0
            deadline = time.monotonic() + timeout
        elif time.monotonic() >= deadline:
            tries += 1
            timeouts += 1
            if tries >= MAX_RETRIES:
                raise TransferError(f"connection lost at packet {base}")
            chan.log.debug("TIMEOUT: going back to seq=%d", base)
            next_seq = base
            deadline = time.monotonic() + timeout
    return retransmits, timeouts


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def send_file(path, host, port, window=8, timeout=0.1, loss=0.0, corrupt=0.0, seed=None):
    """Deliver the file, or raise TransferError. Returns transfer statistics."""
    if window < 1 or timeout <= 0:
        raise ValueError("window must be at least 1 and timeout above 0")
    path = Path(path)
    size = path.stat().st_size
    total = (size + MAX_DATA - 1) // MAX_DATA
    syn = json.dumps({"name": path.name, "size": size, "sha256": sha256_of(path)}).encode()
    addr = (socket.gethostbyname(host), port)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, open(path, "rb") as f:
        chan = Channel(sock, "client", loss, corrupt, seed)
        start = time.perf_counter()
        request(chan, addr, SYN, HANDSHAKE_SEQ, syn, timeout)
        retransmits, timeouts = send_window(chan, addr, f, total, window, timeout)
        result = request(chan, addr, FIN, total, b"", timeout)
        seconds = time.perf_counter() - start

    if result != b"OK":
        raise TransferError(f"server rejected the file: {result.decode(errors='replace')}")
    return {"bytes": size, "packets": total, "seconds": seconds, "sent": chan.sent,
            "dropped": chan.dropped, "corrupted": chan.corrupted,
            "retransmits": retransmits, "timeouts": timeouts}


def main():
    p = argparse.ArgumentParser(description="Send a file over RUFT")
    p.add_argument("file", type=Path)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--window", type=int, default=8, help="1 means stop-and-wait")
    p.add_argument("--timeout", type=float, default=0.1, help="seconds")
    p.add_argument("--loss", type=float, default=0.0, help="chance of dropping an outgoing packet")
    p.add_argument("--corrupt", type=float, default=0.0, help="chance of damaging an outgoing packet")
    p.add_argument("--seed", type=int)
    p.add_argument("-v", "--verbose", action="store_true", help="log every packet")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(name)s] %(message)s")
    try:
        stats = send_file(args.file, args.host, args.port, args.window, args.timeout,
                          args.loss, args.corrupt, args.seed)
    except (TransferError, OSError, ValueError) as e:
        sys.exit(f"Transfer failed: {e}")
    print(f"Delivered and verified {stats['bytes']} bytes in {stats['seconds']:.3f} s\n"
          f"  data packets {stats['packets']}, total sent {stats['sent']}, "
          f"retransmits {stats['retransmits']}, timeouts {stats['timeouts']}, "
          f"simulated lost {stats['dropped']}, corrupted {stats['corrupted']}")


if __name__ == "__main__":
    main()
