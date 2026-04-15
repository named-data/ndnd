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


def _require_alo_latest() -> None:
    alo_bin_path = Path.cwd() / ".bin" / "alo-latest"
    if not alo_bin_path.exists():
        raise RuntimeError(
            f"alo-latest not found at {alo_bin_path}; build it with `make examples`"
        )


def _assign_bier_indices(hosts):
    sorted_hosts = sorted(hosts, key=lambda h: h.name)
    return {host: idx for idx, host in enumerate(sorted_hosts)}


def _wait_for_log_message(node, log_path: str, expected_msg: str, deadline: float) -> str | None:
    while time.time() < deadline:
        match = node.cmd(f"grep -F '{expected_msg}' {log_path} | tail -1").strip()
        if match:
            return match
        time.sleep(0.2)
    return None


def scenario(ndn: Minindn, network="/minindn"):
    """
    BIER SVS test using the std/examples alo-latest application.

    Starts a alo-latest chat instance on 8 chatter nodes and sends a message
    from one node. Then it verifies that all nodes receive the message.
    """

    _require_alo_latest()

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
    producer = chatters[0]
    consumers = chatters[1:]
    sync_prefix = "/ndn/svs/32=svs"
    procs = {}
    logs = {}

    info(
        f"Starting alo-latest on {len(chatters)} chatters; producer={producer.name}, "
        f"consumers={[node.name for node in consumers]}\n"
    )
    for node in chatters:
        log_path = f"/tmp/alo-latest-{node.name}.log"
        logs[node] = log_path
        node.cmd(f"rm -f {log_path}")
        procs[node] = node.popen(
            [
                "bash",
                "-lc",
                (
                    f'export HOME="/tmp/minindn/{node.name}"; '
                    f'exec alo-latest /{node.name} > "{log_path}" 2>&1'
                ),
            ],
            stdin=subprocess.PIPE,
            text=True,
        )

    # Let the processes start, then wait until the multicast sync prefix is
    # replicated everywhere so the first publication uses the BIER path.
    dv_util.wait_prefix_pet_ready({node: {sync_prefix} for node in hosts}, deadline=180)

    msg = f"svs-msg-from-{producer.name}"
    info(f"Publishing test message from {producer.name}: {msg}\n")
    procs[producer].stdin.write(msg + "\n")
    procs[producer].stdin.flush()

    failures = []
    beginning = time.time()
    deadline = beginning + 90
    def test_consumer(consumer):
        received = _wait_for_log_message(consumer, logs[consumer], msg, deadline)
        elapsed = time.time() - beginning
        if received is None:
            failures.append(
                f"{consumer.name} did not receive {msg!r}\n"
                f"log tail:\n{consumer.cmd(f'tail -40 {logs[consumer]} 2>/dev/null || true')}"
            )
            info(f"  [FAIL] t={elapsed:.2f} {consumer.name}\n")
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
            f"alo-latest SVS smoke test failed: {len(failures)}/{len(consumers)} consumers\n"
            + "\n".join(failures)
            + dv_util.dump_bier_logs(chatters, label="alo-latest")
        )

    info("alo-latest SVS smoke test passed: all consumers received the publication\n")
