"""Runtime network guard: executes the whole E2E pipeline with sockets blocked
and asserts no connection is attempted. Complements the static tripwire."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BlockedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        raise OSError("network access attempted")


def main() -> int:
    import tempfile

    socket.socket = BlockedSocket
    socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(
        OSError("network access attempted")
    )
    with tempfile.TemporaryDirectory() as tmp:
        from legal_anonymizer.application.benchmark import BenchmarkRunner


        runner = BenchmarkRunner(Path(tmp) / "state")
        metrics = runner.run(Path(tmp) / "bench")
        if metrics.critical_identifier_misses or metrics.roundtrip_failures:
            print("FAIL: benchmark invariants broke under network guard")
            return 1
    print("PASS: full pipeline runs with all sockets blocked (no network attempted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
