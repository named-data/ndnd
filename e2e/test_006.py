import os
import subprocess
import time
from threading import Thread

from mininet.log import info
from minindn.apps.app_manager import AppManager
from minindn.minindn import Minindn

import dv
import dv_util
import test_005
from dv import NDNd_DV
from fw import NDNd_FW


def _partition_nodes(ndn: Minindn):
    nodes = {node.name: node for node in ndn.net.hosts}
    cores = [nodes[name] for name in sorted(nodes) if name.startswith("c")]
    edges = [nodes[name] for name in sorted(nodes) if name.startswith("e")]
    if not cores or len(edges) < 2:
        raise Exception(
            "Core-edge scenario requires at least one c* core router "
            f"and at least two e* edge routers; found cores={[n.name for n in cores]} "
            f"edges={[n.name for n in edges]}"
        )
    return nodes, cores, edges


def _pet_line(node, prefix: str) -> str:
    pet = node.cmd("ndnd fw pet-list")
    for line in pet.splitlines():
        if line.startswith(f"  {prefix} "):
            return line.strip()
    raise Exception(
        f"PET entry for {prefix} not found on {node.name}\n"
        f"pet-list:\n{pet}\n"
    )


def _assert_pet_egress_only(node, prefix: str, egress: str):
    line = _pet_line(node, prefix)
    if f"egress={{{egress}}}" not in line:
        raise Exception(
            f"Unexpected PET egress for {prefix} on {node.name}\n"
            f"expected egress={{{egress}}}\n"
            f"line: {line}\n"
        )
    if "nexthops={}" not in line:
        raise Exception(
            f"Remote PET entry for {prefix} on {node.name} unexpectedly has local nexthops\n"
            f"line: {line}\n"
        )


def _assert_pet_origin(node, prefix: str, egress: str):
    line = _pet_line(node, prefix)
    if f"egress={{{egress}}}" not in line:
        raise Exception(
            f"Origin PET entry for {prefix} on {node.name} has wrong egress router\n"
            f"expected egress={{{egress}}}\n"
            f"line: {line}\n"
        )
    if "nexthops={}" in line:
        raise Exception(
            f"Origin PET entry for {prefix} on {node.name} is missing local nexthops\n"
            f"line: {line}\n"
        )


def _assert_pet_only_prefixes(node, prefixes: set[str], network: str):
    fib = node.cmd("ndnd fw fib-list")
    for prefix in prefixes:
        if prefix in fib:
            raise Exception(
                f"Application prefix {prefix} unexpectedly present in FIB on {node.name}\n"
                f"fib-list:\n{fib}\n"
            )

    if f"{network}/32=DV/32=PES/" in fib:
        raise Exception(
            f"Router-specific PES entries unexpectedly present in FIB on {node.name}\n"
            f"fib-list:\n{fib}\n"
        )
    if f"/localhop{network}/" in fib and "/32=DV" in fib:
        raise Exception(
            f"Router-specific localhop DV entries unexpectedly present in FIB on {node.name}\n"
            f"fib-list:\n{fib}\n"
        )


def _publish_test_data(node, prefix: str, payload_path: str):
    cmd = f'ndnd put --expose "{prefix}" < "{payload_path}" > "{payload_path}.put.log" 2>&1 &'
    info(f"{node.name} {cmd}\n")
    node.cmd(cmd)


def _fetch_and_compare(consumer, prefix: str, expected_path: str, label: str):
    recv_path = f"/tmp/{consumer.name}-{label}.recv.bin"
    cat_log = f"/tmp/{consumer.name}-{label}.cat.log"
    cmd = f'ndnd cat "{prefix}" > "{recv_path}" 2> "{cat_log}"'
    info(f"{consumer.name} {cmd}\n")
    consumer.cmd(cmd)

    if consumer.cmd(f'diff "{expected_path}" "{recv_path}"').strip():
        cat_output = consumer.cmd(f'cat "{cat_log}"')
        raise Exception(
            f"Core-edge transfer mismatch for {label} on {consumer.name}\n"
            f"cat.log:\n{cat_output}\n"
        )


class NDNdDVCoreNoPrefixReplicate(NDNd_DV):
    def __init__(self, node, network=dv.DEFAULT_NETWORK, **kwargs):
        super().__init__(
            node,
            network=network,
            prefix_egre_state_replicate=not node.name.startswith("c"),
            **kwargs,
        )


def _assert_pet_absent(node, prefix: str):
    pet = node.cmd("ndnd fw pet-list")
    for line in pet.splitlines():
        if line.startswith(f"  {prefix} "):
            raise Exception(
                f"PET entry for {prefix} unexpectedly present on {node.name}\n"
                f"pet-list:\n{pet}\n"
            )


def _run_edge_alo_latest_multicast(edges, cores):
    alo_bin_path = test_005._ensure_alo_latest()
    ordered_edges = sorted(edges, key=lambda h: h.name)
    if len(ordered_edges) < 2:
        raise Exception("Need at least two edge routers for edge-only alo-latest multicast test")

    producer_count = min(2, len(ordered_edges) - 1)
    producers = ordered_edges[:producer_count]
    consumers = ordered_edges[producer_count:]
    sync_prefix = "/ndn/svs/32=svs"
    procs = {}
    logs = {}

    info(
        f"Starting alo-latest on edge routers only; producers={[node.name for node in producers]}, "
        f"consumers={[node.name for node in consumers]}\n"
    )
    for node in ordered_edges:
        log_path = f"/tmp/minindn/{node.name}/alo-latest-edge-only.log"
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

    try:
        dv_util.wait_prefix_pet_ready({node: {sync_prefix} for node in ordered_edges}, deadline=180)
        for core in cores:
            _assert_pet_absent(core, sync_prefix)

        expected_messages = []
        for producer in producers:
            for idx in range(2):
                msg = f"edge-svs-msg-from-{producer.name}-{idx}"
                expected_messages.append((producer, msg))
                info(f"Publishing edge-only sync test message from {producer.name}: {msg}\n")
                procs[producer].stdin.write(msg + "\n")
                procs[producer].stdin.flush()

        failures = []
        beginning = time.time()
        deadline = beginning + 120

        def test_consumer(consumer):
            for producer, msg in expected_messages:
                received = test_005._wait_for_log_message(consumer, logs[consumer], msg, deadline)
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

        if failures:
            raise Exception(
                f"edge-only alo-latest multicast failed: {len(failures)} missing deliveries across "
                f"{len(consumers)} consumers\n"
                + "\n".join(failures)
                + dv_util.dump_bier_logs(ordered_edges + cores, label="edge-only-alo-latest")
            )

        info("edge-only alo-latest multicast passed: all edge consumers received producer messages\n")
    finally:
        for node in ordered_edges:
            info(f"Stopping alo-latest on {node.name}\n")
            proc = procs.get(node)
            if proc is None:
                continue
            if proc.stdin is not None and not proc.stdin.closed:
                proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def scenario(ndn: Minindn, network="/minindn"):
    """
    Core-edge forwarding-plane scenario for a mixed c*/e* topology.

    Expectations:
    - edge routers still learn remote edge prefixes in PET and can fetch each
      other's content successfully.
    - core routers do not mirror application prefixes into PET.
    - edge routers can also exchange sync traffic via alo-latest while the
      shared sync prefix stays absent from core PET state.
    """

    nodes, cores, edges = _partition_nodes(ndn)
    ordered = cores + edges
    bier_map = test_005._assign_bier_indices(ordered)

    info("Starting BIER-enabled forwarder on c*/e* topology with PET replication disabled on cores\n")
    for host in ordered:
        AppManager(ndn, [host], NDNd_FW, network=network, bier_index=bier_map[host])

    dv_util.setup(
        ndn,
        network=network,
        nodes=ordered,
        app_cls=NDNdDVCoreNoPrefixReplicate,
    )
    dv_util.converge(ordered, network=network)
    dv_util.populate_bift(ordered, bier_map, network=network)

    payload_paths = {}
    prefixes = {}
    for edge in edges:
        prefix = f"{network}/{edge.name}/forwarding-plane"
        payload_path = f"/tmp/{edge.name}-forwarding-plane-core-no-pes.bin"
        with open(payload_path, "wb") as f:
            f.write(os.urandom(4096))

        prefixes[edge.name] = prefix
        payload_paths[edge.name] = payload_path
        _publish_test_data(edge, prefix, payload_path)

    dv_util.wait_prefix_pet_ready({node: set(prefixes.values()) for node in edges}, deadline=180)

    for node in ordered:
        _assert_pet_only_prefixes(node, set(prefixes.values()), network)

    for edge in edges:
        _assert_pet_origin(edge, prefixes[edge.name], f"{network}/{edge.name}")

    for edge in edges:
        for remote in edges:
            if edge == remote:
                continue
            _assert_pet_egress_only(
                edge,
                prefixes[remote.name],
                f"{network}/{remote.name}",
            )

    for core in cores:
        for producer in edges:
            _assert_pet_absent(core, prefixes[producer.name])

    for consumer in edges:
        for producer in edges:
            if consumer == producer:
                continue
            _fetch_and_compare(
                consumer,
                prefixes[producer.name],
                payload_paths[producer.name],
                f"{consumer.name}-from-{producer.name}",
            )

    _run_edge_alo_latest_multicast(edges, cores)
