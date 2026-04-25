import random
import subprocess
import time
from pathlib import Path
from threading import Thread

from mininet.log import info
from minindn.apps.app_manager import AppManager
from minindn.minindn import Minindn

from fw import NDNd_FW
import dv_util


def _ensure_alo_latest() -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    alo_bin_path = repo_root / ".bin" / "alo-latest"
    if alo_bin_path.exists():
        return alo_bin_path

    info("Building local alo-latest binary for test_005\n")
    alo_bin_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(
        ["go", "build", "-o", str(alo_bin_path), "./std/examples/svs/alo-latest"],
        cwd=repo_root,
    )
    return alo_bin_path


def _assign_bier_indices(hosts):
    sorted_hosts = sorted(hosts, key=lambda h: h.name)
    return {host: idx for idx, host in enumerate(sorted_hosts)}


def _wait_for_log_message(node, log_path: str, expected_msg: str, deadline: float) -> str | None:
    while time.time() < deadline:
        match = node.cmd(f"grep -F '{expected_msg}' {log_path} | tail -1").strip()
        if match:
            return match
        time.sleep(0.05)
    return None


def scenario(ndn: Minindn, network="/minindn"):
    """
    BIER SVS test using the std/examples alo-latest application.

    Starts alo-latest chat instances on 8 chatter nodes, sends two messages
    from each of two producers, and verifies that all consumers receive all
    four messages.
    """

    alo_bin_path = _ensure_alo_latest()

    hosts = ndn.net.hosts
    if len(hosts) < 4:
        raise Exception("SVS alo-latest test requires at least 4 nodes")

    bier_map = _assign_bier_indices(hosts)

    info("Starting ndnd forwarder on all nodes\n")
    for host in hosts:
        AppManager(ndn, [host], NDNd_FW, network=network, bier_index=bier_map[host])

    dv_util.setup(ndn, network=network)
    dv_util.converge(hosts, network=network)
    dv_util.populate_bift(hosts, bier_map, network=network)

    chatters = random.sample(sorted(hosts, key=lambda h: h.name), min(8, len(hosts)))
    producers = chatters[:2]
    consumers = chatters[2:]
    sync_prefix = "/ndn/svs/32=svs"
    procs = {}
    logs = {}

    info(
        f"Starting alo-latest on {len(chatters)} chatters; producers={[node.name for node in producers]}, "
        f"consumers={[node.name for node in consumers]}\n"
    )
    for node in chatters:
        log_path = f"/tmp/minindn/{node.name}/alo-latest.log"
        logs[node] = log_path
        node.cmd(f"rm -f {log_path}")
        procs[node] = node.popen(
            [
                "bash",
                "-lc",
                (
                    f'export HOME="/tmp/minindn/{node.name}"; '
                    f'exec "{alo_bin_path}" /{node.name} > "{log_path}" 2>&1'
                ),
            ],
            stdin=subprocess.PIPE,
            text=True,
        )

    # Let the processes start, then wait until the multicast sync prefix is
    # replicated everywhere so the first publication uses the BIER path.
    dv_util.wait_prefix_pet_ready({node: {sync_prefix} for node in hosts}, deadline=180)

    expected_messages = []
    for producer in producers:
        for idx in range(2):
            msg = f"svs-msg-from-{producer.name}-{idx}"
            expected_messages.append((producer, msg))
            info(f"Publishing test message from {producer.name}: {msg}\n")
            procs[producer].stdin.write(msg + "\n")
            procs[producer].stdin.flush()

    failures = []
    beginning = time.time()
    deadline = beginning + 120
    def test_consumer(consumer):
        for producer, msg in expected_messages:
            received = _wait_for_log_message(consumer, logs[consumer], msg, deadline)
            elapsed = time.time() - beginning
            if received is None:
                failures.append(
                    f"{consumer.name} did not receive {msg!r} from {producer.name}\n"
                    f"log tail:\n{consumer.cmd(f'tail -80 {logs[consumer]} 2>/dev/null || true')}"
                )
                info(f"  [FAIL] t={elapsed:.2f} {consumer.name}: missing {msg}\n")
            else:
                info(f"  [OK]   t={elapsed:.2f} {consumer.name}: {received}\n")

    threads = []
    for consumer in consumers:
        t = Thread(target=test_consumer, args=(consumer,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    for node in chatters:
        info(f"Stopping alo-latest on {node.name}\n")
        proc = procs[node]
        if proc.stdin is not None:
            proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)

    if failures:
        raise Exception(
            f"alo-latest SVS test failed: {len(failures)} missing deliveries across {len(consumers)} consumers\n"
            + "\n".join(failures)
            + dv_util.dump_bier_logs(chatters, label="alo-latest")
        )

    info("alo-latest SVS test passed: all consumers received both producers' messages\n")
