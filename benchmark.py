"""Compare window sizes under packet loss: python3 benchmark.py > results.md"""
import statistics
import sys
import tempfile
from pathlib import Path

from client import send_file
from server import start_background

SIZE = 500_000
WINDOWS = (1, 4, 16, 64)
LOSSES = (0.0, 0.05, 0.10, 0.20)
RUNS = 3
TIMEOUT = 0.02


def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "data.bin"
        path.write_bytes(bytes(i % 251 for i in range(SIZE)))
        print(f"{SIZE // 1000} KB file over loopback, {TIMEOUT * 1000:.0f} ms timeout, "
              f"median of {RUNS} runs. Loss applies to each direction.\n")
        print("| Window | Loss | Time (s) | Throughput (KB/s) | Retransmitted packets |")
        print("|---|---|---|---|---|")
        for window in WINDOWS:
            for loss in LOSSES:
                runs = []
                for seed in range(RUNS):
                    port = start_background(Path(tmp) / "out", loss=loss, seed=seed + 100)
                    runs.append(send_file(path, "127.0.0.1", port, window, TIMEOUT, loss, seed=seed))
                    print(".", end="", file=sys.stderr, flush=True)
                seconds = statistics.median(r["seconds"] for r in runs)
                retransmits = statistics.median(r["retransmits"] for r in runs)
                print(f"| {window} | {loss:.0%} | {seconds:.3f} | {SIZE / 1000 / seconds:.0f} "
                      f"| {retransmits:.0f} |")


if __name__ == "__main__":
    main()
