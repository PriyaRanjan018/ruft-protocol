"""Run with: python3 -m unittest -v"""
import hashlib
import json
import os
import random
import socket
import tempfile
import time
import unittest
from pathlib import Path

from client import TransferError, send_file
from protocol import ACK, DATA, FIN, HANDSHAKE_SEQ, HEADER, MAX_DATA, SYN, pack, unpack
from server import start_background


class PacketFormat(unittest.TestCase):
    def test_header_is_11_bytes(self):
        self.assertEqual(HEADER.size, 11)

    def test_round_trip(self):
        self.assertEqual(unpack(pack(DATA, 7, b"hello")), (DATA, 7, b"hello"))

    def test_any_flipped_byte_is_rejected(self):
        raw = pack(DATA, 7, b"hello")
        for i in range(len(raw)):
            bad = bytearray(raw)
            bad[i] ^= 0xFF
            self.assertIsNone(unpack(bytes(bad)), f"byte {i}")

    def test_truncated_packet_is_rejected(self):
        self.assertIsNone(unpack(b"\x01\x02"))
        self.assertIsNone(unpack(pack(DATA, 1, b"hello")[:-1]))

    def test_oversized_payload_cannot_be_built(self):
        with self.assertRaises(ValueError):
            pack(DATA, 0, b"x" * (MAX_DATA + 1))


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.out = self.dir / "received"

    def make_file(self, size, name="input.bin"):
        path = self.dir / name
        path.write_bytes(random.Random(size).randbytes(size))
        return path

    def assert_delivered(self, path):
        self.assertEqual((self.out / path.name).read_bytes(), path.read_bytes())


class Transfers(Base):
    def transfer(self, size, server=None, **client):
        path = self.make_file(size)
        port = start_background(self.out, **(server or {}))
        stats = send_file(path, "127.0.0.1", port, timeout=0.02, **client)
        self.assert_delivered(path)
        return stats

    def test_clean_network_needs_no_retransmits(self):
        self.assertEqual(self.transfer(20_000, window=8)["retransmits"], 0)

    def test_stop_and_wait(self):
        self.transfer(5_000, window=1)

    def test_empty_file(self):
        self.transfer(0)

    def test_size_exactly_on_packet_boundary(self):
        self.transfer(MAX_DATA * 3)

    def test_survives_loss_in_both_directions(self):
        stats = self.transfer(20_000, window=8, loss=0.3, seed=1,
                              server={"loss": 0.3, "seed": 2})
        self.assertGreater(stats["retransmits"], 0)

    def test_stop_and_wait_survives_lost_acks(self):
        self.transfer(10_000, window=1, server={"loss": 0.4, "seed": 3})

    def test_survives_corruption_in_both_directions(self):
        self.transfer(20_000, window=8, corrupt=0.2, seed=4,
                      server={"corrupt": 0.2, "seed": 5})

    def test_small_timeout_does_not_duplicate_data(self):
        # Spurious retransmits must be discarded by sequence number.
        path = self.make_file(30_000)
        port = start_background(self.out)
        send_file(path, "127.0.0.1", port, window=32, timeout=0.0005)
        self.assert_delivered(path)


class Failures(Base):
    def test_gives_up_when_no_server_answers(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            with self.assertRaises(TransferError):
                send_file(self.make_file(10), "127.0.0.1", port, timeout=0.005)


class RawClient(Base):
    """Speaks the protocol by hand to send what a good client never would."""

    def setUp(self):
        super().setUp()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.sock.close)
        self.sock.settimeout(0.3)
        self.port = start_background(self.out)

    def ask(self, ptype, seq, data=b"", sock=None):
        sock = sock or self.sock
        sock.sendto(pack(ptype, seq, data), ("127.0.0.1", self.port))
        return unpack(sock.recv(2048))

    @staticmethod
    def syn(name, content, digest=None):
        return json.dumps({"name": name, "size": len(content),
                           "sha256": digest or hashlib.sha256(content).hexdigest()}).encode()

    def test_path_traversal_stays_inside_output_folder(self):
        self.ask(SYN, HANDSHAKE_SEQ, self.syn("../../evil.txt", b"x"))
        self.ask(DATA, 0, b"x")
        self.ask(FIN, 1)
        self.assertEqual(os.listdir(self.out), ["evil.txt"])

    def test_invalid_syn_is_ignored_and_server_survives(self):
        for bad in (b"not json", b"[]", b'{"name": 1}', self.syn("..", b"x"),
                    self.syn("a\0b", b"x"), self.syn("", b"x"), self.syn("x" * 300, b"")):
            self.sock.sendto(pack(SYN, HANDSHAKE_SEQ, bad), ("127.0.0.1", self.port))
        self.assertEqual(self.ask(SYN, HANDSHAKE_SEQ, self.syn("ok", b""))[0], ACK)

    def test_negative_size_is_ignored(self):
        bad = json.dumps({"name": "a", "size": -1, "sha256": "0" * 64}).encode()
        self.sock.sendto(pack(SYN, HANDSHAKE_SEQ, bad), ("127.0.0.1", self.port))
        self.assertEqual(self.ask(SYN, HANDSHAKE_SEQ, self.syn("ok", b""))[0], ACK)

    def test_wrong_hash_is_reported_and_file_is_not_kept(self):
        self.ask(SYN, HANDSHAKE_SEQ, self.syn("f", b"x", digest="0" * 64))
        self.ask(DATA, 0, b"x")
        self.assertEqual(self.ask(FIN, 1), (ACK, 1, b"HASH_MISMATCH"))
        self.assertEqual(os.listdir(self.out), [])

    def test_repeated_fin_gets_same_answer(self):
        self.ask(SYN, HANDSHAKE_SEQ, self.syn("f", b"x"))
        self.ask(DATA, 0, b"x")
        self.assertEqual(self.ask(FIN, 1), (ACK, 1, b"OK"))
        self.assertEqual(self.ask(FIN, 1), (ACK, 1, b"OK"))

    def test_out_of_order_data_is_not_written(self):
        self.ask(SYN, HANDSHAKE_SEQ, self.syn("f", b"x" * (MAX_DATA + 1)))
        self.sock.sendto(pack(DATA, 1, b"x"), ("127.0.0.1", self.port))
        with self.assertRaises(TimeoutError):  # nothing received yet, nothing to ACK
            self.sock.recv(2048)
        self.assertEqual(self.ask(DATA, 0, b"x" * MAX_DATA), (ACK, 0, b""))
        self.assertEqual(self.ask(DATA, 5, b"x"), (ACK, 0, b""))  # re-ACK last good

    def test_second_client_is_refused_during_a_transfer(self):
        self.ask(SYN, HANDSHAKE_SEQ, self.syn("f", b"x"))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.settimeout(0.05)
            with self.assertRaises(TimeoutError):
                self.ask(SYN, HANDSHAKE_SEQ, self.syn("g", b"y"), sock=other)

    def test_abandoned_transfer_is_replaced_and_cleaned_up(self):
        self.port = start_background(self.out, idle=0.05)
        self.ask(SYN, HANDSHAKE_SEQ, self.syn("old", b"x"))
        time.sleep(0.1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.settimeout(0.3)
            self.assertEqual(self.ask(SYN, HANDSHAKE_SEQ, self.syn("new", b"y"), sock=other)[0], ACK)
        self.assertNotIn("old.part", os.listdir(self.out))
