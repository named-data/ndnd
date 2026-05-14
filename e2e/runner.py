import os
import random
import shutil
import subprocess
import time
from pathlib import Path
from types import FunctionType

from mininet.log import setLogLevel, info
from minindn.minindn import Minindn

import test_001
import test_002
import test_003
import test_004
import test_005
import test_006


def ensure_local_binaries() -> None:
    """Build ndnd into .bin/ (or use pre-built if already available)."""
    repo_root = Path(__file__).resolve().parent.parent
    local_bin = repo_root / ".bin"
    local_bin.mkdir(parents=True, exist_ok=True)

    name, pkg = "ndnd", "./cmd/ndnd"
    if not (local_bin / name).exists() and not shutil.which(name):
        subprocess.check_call(["go", "build", "-o", str(local_bin / name), pkg], cwd=repo_root)

    os.environ["PATH"] = f"{local_bin}:{os.environ.get('PATH', '')}"


def run_suite(topo_file: Path, scenarios: list[tuple[str, FunctionType]]) -> None:
    global ndn

    info(f"Using topology file {topo_file}\n")
    Minindn.cleanUp()

    ndn = Minindn(topoFile=str(topo_file))
    ndn.start()
    try:
        for name, scenario in scenarios:
            run(name, scenario)
    finally:
        ndn.stop()
        Minindn.cleanUp()


def run(name: str, scenario: FunctionType, **kwargs) -> None:
    info(f"\n{'='*60}\n  SCENARIO: {name}\n{'='*60}\n")
    start = time.time()
    try:
        random.seed(0)
        scenario(ndn, **kwargs)
        elapsed = time.time() - start
        info(f"{'='*60}\n  PASSED: {name}  ({elapsed:.1f}s)\n{'='*60}\n\n")
    except Exception as e:
        ndn.stop()
        raise
    finally:
        for cleanup in reversed(ndn.cleanups):
            cleanup()
        os.system('pkill -9 ndnd 2>/dev/null; pkill -9 nfd 2>/dev/null; true')


if __name__ == '__main__':
    setLogLevel('info')

    ensure_local_binaries()
    Minindn.verifyDependencies()

    topo_dir = Path(__file__).resolve().parent

    run_suite(topo_dir / "topo.sprint.conf", [
        ("test_001: basic file transfer (two-phase lookup)", test_001.scenario),
        ("test_002: node disconnect/reconnect resilience",   test_002.scenario),
        ("test_003: stub-mode prefix insertion",             test_003.scenario),
        ("test_004: LVS prefix insertion security",          test_004.scenario),
        ("test_005: BIER SVS alo-latest test",               test_005.scenario),
    ])

    run_suite(topo_dir / "topo.edge-core.conf", [
        ("test_006: core-edge PET and BIER split", test_006.scenario),
    ])
