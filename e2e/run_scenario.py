import argparse
import importlib
import inspect
import os
import random
import subprocess
import sys
import time
from pathlib import Path

from mininet.log import info, setLogLevel
from minindn.minindn import Minindn
from minindn.util import MiniNDNCLI


def ensure_local_ndnd(repo_root: Path) -> None:
    local_bin = repo_root / ".bin"
    local_ndnd = local_bin / "ndnd"
    local_bin.mkdir(parents=True, exist_ok=True)
    if not local_ndnd.exists():
        info("Building local ndnd binary for E2E scenario\n")
        subprocess.check_call(
            ["go", "build", "-o", str(local_ndnd), "./cmd/ndnd"],
            cwd=repo_root,
        )
    os.environ["PATH"] = f"{local_bin}:{os.environ.get('PATH', '')}"


def main():
    parser = argparse.ArgumentParser(description="Run one Mini-NDN E2E scenario headlessly")
    parser.add_argument("--scenario", required=True, help="Python module name under e2e/, e.g. test_003")
    parser.add_argument("--network", default="/minindn", help="NDN network prefix passed to scenario")
    parser.add_argument("--topo", default="e2e/topo.sprint.conf", help="Topology config file")
    args = parser.parse_args()
    sys.argv = [sys.argv[0]]

    # Prefer workspace binary and build it if missing.
    repo_root = Path(__file__).resolve().parent.parent
    ensure_local_ndnd(repo_root)

    setLogLevel("info")

    Minindn.cleanUp()
    Minindn.verifyDependencies()

    ndn = Minindn(topoFile=args.topo)
    ndn.start()
    try:
        mod = importlib.import_module(args.scenario)
        scenario = getattr(mod, "scenario")
        sig = inspect.signature(scenario)

        random.seed(0)

        info("===================================================\n")
        start = time.time()
        if "network" in sig.parameters:
            scenario(ndn, network=args.network)
        else:
            scenario(ndn)
        info(f"Scenario completed in: {time.time()-start:.2f}s\n")
        info("===================================================\n")

        if os.getenv("MININDN_CLI"):
            MiniNDNCLI(ndn.net)
        for cleanup in reversed(ndn.cleanups):
            cleanup()
    finally:
        ndn.stop()
        os.system("pkill -9 ndnd")
        os.system("pkill -9 nfd")


if __name__ == "__main__":
    main()
