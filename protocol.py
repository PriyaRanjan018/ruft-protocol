"""RUFT wire format and the (optionally unreliable) channel both sides use."""
import logging
import random
import socket
import struct
import zlib

# type, sequence number, data length, CRC-32 (network byte order)
HEADER = struct.Struct("!BIHI")
MAX_DATA = 1024

SYN, ACK, DATA, FIN = 1, 2, 3, 4
NAMES = {SYN: "SYN", ACK: "ACK", DATA: "DATA", FIN: "FIN"}

# Outside the range of data sequence numbers, so an ACK of the SYN that
# arrives late can never be mistaken for an ACK of DATA 0.
HANDSHAKE_SEQ = 0xFFFFFFFF


def pack(ptype, seq, data=b""):
    if len(data) > MAX_DATA:
        raise ValueError(f"payload of {len(data)} bytes exceeds {MAX_DATA}")
    crc = zlib.crc32(HEADER.pack(ptype, seq, len(data), 0) + data)
    return HEADER.pack(ptype, seq, len(data), crc) + data


def unpack(raw):
    """Return (type, seq, data), or None if the packet is damaged."""
    if len(raw) < HEADER.size:
        return None
    ptype, seq, length, crc = HEADER.unpack_from(raw)
    data = raw[HEADER.size:]
    if ptype not in NAMES or length != len(data):
        return None
    if zlib.crc32(HEADER.pack(ptype, seq, length, 0) + data) != crc:
        return None
    return ptype, seq, data


class Channel:
    """A UDP socket that can deliberately lose or damage what it sends."""

    def __init__(self, sock, name, loss=0.0, corrupt=0.0, seed=None):
        if not (0 <= loss < 1 and 0 <= corrupt < 1):
            raise ValueError("loss and corrupt must be in the range 0 to 0.99")
        self.sock = sock
        self.log = logging.getLogger(name)
        self.loss = loss
        self.corrupt = corrupt
        self.rng = random.Random(seed)
        self.sent = self.dropped = self.corrupted = 0

    def send(self, ptype, seq, data, addr, label="SEND"):
        raw = bytearray(pack(ptype, seq, data))
        self.sent += 1
        if self.rng.random() < self.loss:
            self.dropped += 1
            self.log.debug("%s %s seq=%d -> LOST (simulated)", label, NAMES[ptype], seq)
            return
        if self.rng.random() < self.corrupt:
            self.corrupted += 1
            raw[self.rng.randrange(len(raw))] ^= 0xFF
            self.log.debug("%s %s seq=%d -> CORRUPTED (simulated)", label, NAMES[ptype], seq)
        else:
            self.log.debug("%s %s seq=%d", label, NAMES[ptype], seq)
        self.sock.sendto(raw, addr)

    def recv(self, timeout=None):
        """Return (type, seq, data, addr), or None on timeout or damaged packet."""
        self.sock.settimeout(timeout)
        try:
            raw, addr = self.sock.recvfrom(HEADER.size + MAX_DATA)
        except (socket.timeout, ConnectionError):
            return None
        packet = unpack(raw)
        if packet is None:
            self.log.debug("RECV bad checksum -> discarded")
            return None
        self.log.debug("RECV %s seq=%d", NAMES[packet[0]], packet[1])
        return (*packet, addr)
