import os

from mininet.log import info
from minindn.apps.app_manager import AppManager
from minindn.minindn import Minindn

from fw import NDNd_FW
import dv_util


def _partition_nodes(ndn: Minindn):
    nodes = {node.name: node for node in ndn.net.hosts}
    cores = [nodes[name] for name in sorted(nodes) if name.startswith("c")]
    edges = [nodes[name] for name in sorted(nodes) if name.startswith("e")]
    if not cores or len(edges) < 2:
        raise Exception(
            "Forwarding-plane scenario requires at least one c* core router "
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
            f"Forwarding-plane transfer mismatch for {label} on {consumer.name}\n"
            f"cat.log:\n{cat_output}\n"
        )


def scenario(ndn: Minindn, network="/minindn"):
    """
    Focused forwarding-plane scenario for a mixed c*/e* router topology.

    The test publishes one application prefix on each edge router, verifies that
    the prefixes are replicated into PET but not injected into FIB, checks that
    every non-origin router sees each remote edge prefix as an egress-only PET
    entry, and finally performs fetches from every node to every remote edge
    prefix to exercise the two-phase forwarding path across the graph.
    """

    nodes, cores, edges = _partition_nodes(ndn)
    ordered = cores + edges

    info("Starting forwarder on c*/e* forwarding-plane topology\n")
    AppManager(ndn, ordered, NDNd_FW, network=network)

    dv_util.setup(ndn, network=network, nodes=ordered)
    dv_util.converge(ordered, network=network)

    payload_paths = {}
    prefixes = {}
    for edge in edges:
        prefix = f"{network}/{edge.name}/forwarding-plane"
        payload_path = f"/tmp/{edge.name}-forwarding-plane.bin"
        with open(payload_path, "wb") as f:
            f.write(os.urandom(4096))

        prefixes[edge.name] = prefix
        payload_paths[edge.name] = payload_path
        _publish_test_data(edge, prefix, payload_path)

    dv_util.wait_prefix_pet_ready({node: set(prefixes.values()) for node in ordered}, deadline=180)

    for node in ordered:
        _assert_pet_only_prefixes(node, set(prefixes.values()), network)

    for edge in edges:
        _assert_pet_origin(edge, prefixes[edge.name], f"{network}/{edge.name}")

    for consumer in ordered:
        for producer in edges:
            if consumer == producer:
                continue
            _assert_pet_egress_only(
                consumer,
                prefixes[producer.name],
                f"{network}/{producer.name}",
            )

    for consumer in ordered:
        for producer in edges:
            if consumer == producer:
                continue
            _fetch_and_compare(
                consumer,
                prefixes[producer.name],
                payload_paths[producer.name],
                f"{consumer.name}-from-{producer.name}",
            )
