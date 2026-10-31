# RUFT: Reliable UDP File Transfer

RUFT is an application-layer protocol that delivers a complete, correct file over
UDP, which by itself can lose, damage, duplicate and reorder packets. It uses
sequence numbers, cumulative ACKs, timeouts, a Go-Back-N sliding window, CRC-32
packet checksums and a SHA-256 whole-file check.

Written in Python 3.9+ with the standard library only, so there is nothing to install.

## Run it

```bash
# Terminal 1: start the receiver
python3 server.py --out received

# Terminal 2: send a file
head -c 20000 /dev/urandom > sample.bin
python3 client.py sample.bin

# Check the two files are identical (prints nothing if they are)
cmp sample.bin received/sample.bin
```

To watch it recover from failures, restart the server with `--loss 0.2 -v` and run:

```bash
python3 client.py sample.bin --window 4 --loss 0.2 --corrupt 0.05 -v
```

To send between two machines on the same network, start the server with
`--host 0.0.0.0` and pass `--host <server-ip>` to the client.

| Option | Meaning |
|---|---|
| `--window N` | Packets in flight; 1 means stop-and-wait (client) |
| `--timeout S` | Seconds before resending (client) |
| `--loss P`, `--corrupt P` | Chance of dropping or damaging each outgoing packet, e.g. `0.2` |
| `--seed N` | Repeat the same simulated failures |
| `-v` | Log every packet |

## Packet format

All fields are in network byte order. The header is 11 bytes.

```
+--------+---------+---------+----------+------------------+
|  TYPE  | SEQ NO  | LENGTH  | CHECKSUM |       DATA       |
| 1 byte | 4 bytes | 2 bytes | 4 bytes  | 0 to 1024 bytes  |
+--------+---------+---------+----------+------------------+
```

| Field | Meaning |
|---|---|
| TYPE | 1 `SYN`, 2 `ACK`, 3 `DATA`, 4 `FIN` |
| SEQ NO | Packet number; the SYN and its ACK use 0xFFFFFFFF |
| LENGTH | Number of data bytes |
| CHECKSUM | CRC-32 of header (with this field as zero) and data |

## Protocol rules

**1. Handshake.** The client sends `SYN` with JSON data holding the file's name,
size and SHA-256 hash, and resends until the server ACKs it.

**2. Data transfer.** The file is split into 1024-byte `DATA` packets numbered from 0.
- The client keeps up to `window` unacknowledged packets in flight.
- The server accepts only the next expected packet. It discards anything else and
  repeats its last ACK.
- `ACK n` is cumulative: everything up to and including packet `n` has arrived.
- On timeout, the client resends everything from the oldest unacknowledged packet.

**3. Finish.** The client sends `FIN` with the sequence number equal to the packet
count. The server compares the SHA-256 hash, then replies with an `ACK` containing `OK`
or `HASH_MISMATCH`. A verified file is renamed from `.part` to its real name; a failed
one is deleted.

| Failure | What happens |
|---|---|
| Packet lost | No ACK arrives, so the client times out and resends |
| Packet damaged | CRC-32 fails, so it is discarded and treated as lost |
| ACK lost | A later cumulative ACK covers it, or the client resends and the server discards the duplicate |
| Duplicate or out-of-order packet | Discarded by sequence number |
| Server unreachable | The client stops after 20 failed tries |
| Client disappears | After 10 idle seconds, a new client's SYN replaces the session and the partial file is deleted |

## Code layout

| File | Purpose |
|---|---|
| `protocol.py` | Packet format, checksum, and the channel that simulates failures |
| `client.py` | Sender: handshake and Go-Back-N sliding window |
| `server.py` | Receiver: sessions, ordering, and file verification |
| `test_ruft.py` | Automated tests: `python3 -m unittest` |
| `benchmark.py` | Measures window sizes against loss rates |
| `results.md` | Benchmark output |

## Results

See [results.md](results.md). These runs used the loopback interface, where round-trip
time is close to zero, and simulated loss.

- Under loss, windows of 4 or more were about twice as fast as stop-and-wait, because
  one timeout recovers several losses at once.
- Windows above 4 gave no clear further speed here but multiplied retransmissions: at 20%
  loss, window 64 retransmitted 6528 packets against 420 for window 4.
- The 0% loss rows are too short to compare window sizes. A sliding window's main
  benefit on a real link with delay is not shown by this setup.

## Limitations

- No encryption or authentication: anyone who can reach the server can send it files,
  and a file with the same name is overwritten. The server listens on localhost by default.
- No congestion control or adaptive timeout.
- One transfer at a time; a second client is ignored until the first finishes.
- IPv4 only, and an interrupted transfer cannot resume.
