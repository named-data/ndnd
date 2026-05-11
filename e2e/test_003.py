import os
import random
import re
import time
from pathlib import Path

from mininet.log import info
from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager

from fw import NDNd_FW
import dv
import dv_util

CLIENT_LVS_SCHEMA = str(Path(__file__).resolve().parent / "client_lvs_minindn.tlv")


def _build_neighbors(nodes):
    neighbors = {node: {} for node in nodes}
    for node in nodes:
        for intf in node.intfList():
            if intf.link is None:
                continue
            other_intf = intf.link.intf2 if intf.link.intf1 == intf else intf.link.intf1
            neighbors[node][other_intf.node] = other_intf.IP()
    return neighbors


def _is_connected(nodes, neighbors):
    if len(nodes) <= 1:
        return True
    remaining = set(nodes)
    start = nodes[0]
    stack = [start]
    seen = {start}
    while stack:
        cur = stack.pop()
        for nxt in neighbors.get(cur, {}):
            if nxt in remaining and nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return len(seen) == len(remaining)


def _pick_producer_router(nodes):
    neighbors = _build_neighbors(nodes)
    if not any(neighbors.values()):
        raise Exception("No linked nodes found in topology")

    # Prefer a dedicated leaf client attached to a router.
    leaf_candidates = []
    fallback_candidates = []
    for producer, peer_map in neighbors.items():
        if not peer_map:
            continue
        peers = list(peer_map.items())
        for router, router_ip in peers:
            routers = [n for n in nodes if n != producer]
            if not _is_connected(routers, neighbors):
                continue
            fallback_candidates.append((producer, router, router_ip))
            if len(peer_map) == 1:
                leaf_candidates.append((producer, router, router_ip))

    if leaf_candidates:
        return random.choice(leaf_candidates)
    if fallback_candidates:
        return random.choice(fallback_candidates)

    raise Exception("No producer/router pair keeps router set connected")


def _assert_no_local_dv(node):
    pet = node.cmd("ndnd fw pet-list")
    if re.search(r"^\s*/localhost/dv\b", pet, re.MULTILINE):
        raise Exception(
            f"Producer {node.name} must not run local DV in stub-mode test.\n"
            f"PET unexpectedly contains /localhost/dv:\n{pet}\n"
        )


def _wait_for_default_router_pet(node, router_face, deadline=120):
    info(f"Waiting for default PET route on {node.name} to {router_face}\n")
    face_pat = re.compile(rf"faceid=(\d+) remote={re.escape(router_face)}(?:\s|$)")
    start = time.time()
    while time.time() - start < deadline:
        face_out = node.cmd("ndnd fw face-list")
        face_match = face_pat.search(face_out)
        if face_match:
            faceid = face_match.group(1)
            pet_out = node.cmd("ndnd fw pet-list")
            root_pat = re.compile(rf"^\s*/\s+egress=.*nexthops=\{{[^}}]*faceid={faceid}\b", re.MULTILINE)
            if root_pat.search(pet_out):
                info(f"Default PET route visible on {node.name} via faceid={faceid}\n")
                return
        time.sleep(1)

    raise Exception(
        f"Default PET route '/' not installed on {node.name} for router {router_face}\n"
        f"face-list:\n{node.cmd('ndnd fw face-list')}\n"
        f"pet-list:\n{node.cmd('ndnd fw pet-list')}\n"
    )


def _wait_for_prefix_insertion(node, prefix, deadline=120):
    info(f"Waiting for router insertion on {node.name} for {prefix}\n")
    start = time.time()
    while time.time() - start < deadline:
        out = node.cmd("ndnd dv prefix-list")
        if f"prefix={prefix} " in out:
            info(f"Router insertion visible on {node.name}\n")
            return
        time.sleep(1)
    raise Exception(f"Router insertion did not appear on {node.name} for {prefix}")

def _prepare_producer_keychain(node, network):
    keychain_dir = f"/tmp/prefix-insertion-{node.name}-keys"
    node.cmd(f'rm -rf "{keychain_dir}" && mkdir -p "{keychain_dir}"')
    node.cmd(f'ndnd sec keygen "{network}/{node.name}" ed25519 > "{keychain_dir}/{node.name}.key"')
    node.cmd(
        f'ndnd sec sign-cert "{dv.TRUST_ROOT_PATH}.key" '
        f'< "{keychain_dir}/{node.name}.key" > "{keychain_dir}/{node.name}.cert"'
    )
    node.cmd(f'cp "{dv.TRUST_ROOT_PATH}.cert" "{keychain_dir}/root.cert"')
    return keychain_dir


def scenario(ndn: Minindn, network="/minindn"):
    """
    Validate stub-mode prefix insertion end-to-end.
    Security model:
    - DV routers run with trust anchors and signed router certs (dv_util.setup).
    - Exposing client sends unsigned command Interests carrying signed PA Data.
    """

    info("Starting forwarder on nodes\n")
    producer, router, router_ip = _pick_producer_router(ndn.net.hosts)
    routers = [n for n in ndn.net.hosts if n != producer]
    if not routers:
        raise Exception("Need at least one router node distinct from producer")

    # Producer is a stub client only; only router nodes run DV and need BIER indices.
    bier_map = dv_util.assign_bier_indices(routers)
    for host in ndn.net.hosts:
        bier_idx = bier_map.get(host, -1)  # producer gets -1 (disabled)
        AppManager(ndn, [host], NDNd_FW, network=network, bier_index=bier_idx)

    if network != "/minindn":
        raise Exception(
            f"This scenario requires network=/minindn (received {network}) "
            f"because it uses {CLIENT_LVS_SCHEMA}"
        )
    if not os.path.exists(CLIENT_LVS_SCHEMA):
        raise Exception(f"Missing client LVS schema fixture: {CLIENT_LVS_SCHEMA}")

    # Producer is a stub client only; only router nodes run DV.
    dv_util.setup(
        ndn,
        network=network,
        nodes=routers,
        routing_trust_schema=dv.ROUTING_LVS_SCHEMA,
        prefix_insertion_keychain="inherit",
        prefix_insertion_trust_schema=CLIENT_LVS_SCHEMA,
    )
    dv_util.converge(routers, network=network)
    dv_util.populate_bift(routers, bier_map, network=network)
    _assert_no_local_dv(producer)

    consumer_candidates = [n for n in routers if n != router]
    if not consumer_candidates:
        consumer_candidates = [n for n in routers]
    if not consumer_candidates:
        raise Exception("Need at least two nodes for prefix insertion E2E test")
    consumer = random.choice(consumer_candidates)

    prefix = f"{network}/{producer.name}/prefix-inserted"
    test_file = f"/tmp/prefix-insertion-{producer.name}.bin"
    recv_file = f"/tmp/prefix-insertion-{consumer.name}.recv.bin"
    put_log = f"/tmp/prefix-insertion-{producer.name}.put.log"

    os.system(f"dd if=/dev/urandom of={test_file} bs=64K count=1 status=none")
    router_face = f"udp4://{router_ip}:6363"
    producer_keychain = _prepare_producer_keychain(producer, network)

    cmd = (
        f"NDN_CLIENT_ROUTING_MODE=stub "
        f"NDN_CLIENT_ROUTER_URI={router_face} "
        f"NDND_CLIENT_KEYCHAIN=dir://{producer_keychain} "
        f"NDND_CLIENT_TRUST_SCHEMA={CLIENT_LVS_SCHEMA} "
        f"NDND_CLIENT_TRUST_ANCHORS='{dv.TRUST_ROOT_NAME}' "
        f"ndnd put --expose \"{prefix}\" < {test_file} > {put_log} 2>&1 &"
    )
    info(f"{producer.name} {cmd}\n")
    producer.cmd(cmd)

    _wait_for_default_router_pet(producer, router_face)
    _wait_for_prefix_insertion(router, prefix)
    dv_util.wait_prefix_pet_ready({consumer: {prefix}, router: {prefix}}, deadline=180)

    cat_cmd = f'ndnd cat "{prefix}" > {recv_file} 2> /tmp/prefix-insertion-cat.log'
    info(f"{consumer.name} {cat_cmd}\n")
    consumer.cmd(cat_cmd)

    if consumer.cmd(f"diff {test_file} {recv_file}").strip():
        cat_log = consumer.cmd("cat /tmp/prefix-insertion-cat.log")
        put_out = producer.cmd(f"tail -n 100 {put_log}")
        raise Exception(
            "Prefix insertion transfer mismatch\n"
            f"cat.log:\n{cat_log}\n"
            f"put.log:\n{put_out}\n"
        )
