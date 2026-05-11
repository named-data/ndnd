import os
import random
import time
from pathlib import Path

from mininet.log import info
from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager

from fw import NDNd_FW
from dv import NDNd_DV, TRUST_ROOT_PATH
import dv
import dv_util
import test_003


CLIENT_LVS_SCHEMA = str(Path(__file__).resolve().parent / "client_lvs_minindn.tlv")
# Human-readable policy source: e2e/client_lvs_minindn.lvs


def _dv_log_path(node):
    home_dir = node.params.get("params", {}).get("homeDir")
    if home_dir:
        return f"{home_dir}/log/dv.log"
    return f"/tmp/minindn/{node.name}/log/dv.log"


def _wait_for_prefix_absence(node, prefix, deadline=15):
    info(f"Ensuring router insertion stays absent on {node.name} for {prefix}\n")
    start = time.time()
    while time.time() - start < deadline:
        out = node.cmd("ndnd dv prefix-list")
        if f"prefix={prefix} " in out:
            raise Exception(
                f"Unexpected router insertion appeared on {node.name} for {prefix}\n"
                f"prefix-list:\n{out}\n"
            )
        time.sleep(1)


def _wait_for_trust_schema_violation(node, prefix, deadline=20):
    info(f"Waiting for trust schema rejection on {node.name} for {prefix}\n")
    log_path = _dv_log_path(node)
    start = time.time()
    while time.time() - start < deadline:
        out = node.cmd(f'tail -n 200 "{log_path}" 2>/dev/null')
        if "trust schema mismatch" in out and prefix in out:
            info(f"Observed trust schema mismatch on {node.name} for {prefix}\n")
            return
        time.sleep(1)

    tail_out = node.cmd(f'tail -n 200 "{log_path}" 2>/dev/null')
    raise Exception(
        f"Expected trust schema mismatch not observed on {node.name} for {prefix}\n"
        f"log-path: {log_path}\n"
        f"dv.log tail:\n{tail_out}\n"
    )


def _prepare_producer_keychain(node, network):
    keychain_dir = f"/tmp/prefix-insertion-lvs-{node.name}-keys"
    node.cmd(f'rm -rf "{keychain_dir}" && mkdir -p "{keychain_dir}"')
    node.cmd(f'ndnd sec keygen "{network}/{node.name}" ed25519 > "{keychain_dir}/{node.name}.key"')
    node.cmd(
        f'ndnd sec sign-cert "{TRUST_ROOT_PATH}.key" '
        f'< "{keychain_dir}/{node.name}.key" > "{keychain_dir}/{node.name}.cert"'
    )
    node.cmd(f'cp "{TRUST_ROOT_PATH}.cert" "{keychain_dir}/root.cert"')
    return keychain_dir


def _prepare_schema_violation_keychain(node, network):
    keychain_dir = f"/tmp/prefix-insertion-lvs-{node.name}-schema-violation-keys"
    node.cmd(f'rm -rf "{keychain_dir}" && mkdir -p "{keychain_dir}"')

    owner_id = f"{network}/{node.name}"
    issuer_id = f"{network}/{node.name}-issuer"
    node.cmd(f'ndnd sec keygen "{owner_id}" ed25519 > "{keychain_dir}/owner.key"')
    node.cmd(f'ndnd sec keygen "{issuer_id}" ed25519 > "{keychain_dir}/issuer.key"')
    node.cmd(
        f'ndnd sec sign-cert "{TRUST_ROOT_PATH}.key" '
        f'< "{keychain_dir}/issuer.key" > "{keychain_dir}/issuer.cert"'
    )
    node.cmd(
        f'ndnd sec sign-cert "{keychain_dir}/issuer.key" '
        f'< "{keychain_dir}/owner.key" > "{keychain_dir}/owner.cert"'
    )
    node.cmd(f'cp "{TRUST_ROOT_PATH}.cert" "{keychain_dir}/root.cert"')
    return keychain_dir


def scenario(ndn: Minindn, network="/minindn"):
    """
    Validate explicit LVS prefix insertion security end-to-end.
    - Expose requests with untrusted PA signatures are rejected.
    - Expose requests with trust-schema-violating cert chains are rejected.
    - Properly signed expose requests are accepted.
    """
    if not os.path.exists(CLIENT_LVS_SCHEMA):
        raise Exception(f"Missing client LVS schema fixture: {CLIENT_LVS_SCHEMA}")

    info("Starting forwarder on nodes\n")
    producer, router, router_ip = test_003._pick_producer_router(ndn.net.hosts)
    routers = [n for n in ndn.net.hosts if n != producer]
    if not routers:
        raise Exception("Need at least one router node distinct from producer")

    # Producer is a stub client; only router nodes need BIER indices.
    bier_map = dv_util.assign_bier_indices(routers)
    for host in ndn.net.hosts:
        bier_idx = bier_map.get(host, -1)  # producer gets -1 (disabled)
        AppManager(ndn, [host], NDNd_FW, network=network, bier_index=bier_idx)

    time.sleep(1)  # wait for fw to start
    NDNd_DV.init_trust(network=network)
    info("Starting ndn-dv on router nodes with LVS prefix insertion security\n")
    AppManager(
        ndn,
        routers,
        NDNd_DV,
        network=network,
        routing_trust_anchors=[dv.TRUST_ROOT_NAME],
        routing_trust_schema=dv.ROUTING_LVS_SCHEMA,
        prefix_insertion_keychain="inherit",
        prefix_insertion_trust_anchors=[dv.TRUST_ROOT_NAME],
        prefix_insertion_trust_schema=CLIENT_LVS_SCHEMA,
    )

    # This scenario runs security-heavy setup and can take longer on large topologies.
    dv_util.converge(routers, network=network, deadline=300)
    dv_util.populate_bift(routers, bier_map, network=network)
    test_003._assert_no_local_dv(producer)

    consumer_candidates = [n for n in routers if n != router]
    if not consumer_candidates:
        consumer_candidates = [n for n in routers]
    if not consumer_candidates:
        raise Exception("Need at least two nodes for LVS prefix insertion E2E test")
    consumer = random.choice(consumer_candidates)

    test_file = f"/tmp/prefix-insertion-lvs-{producer.name}.bin"
    recv_file = f"/tmp/prefix-insertion-lvs-{consumer.name}.recv.bin"
    put_reject_log = f"/tmp/prefix-insertion-lvs-{producer.name}.reject.put.log"
    put_schema_violation_log = f"/tmp/prefix-insertion-lvs-{producer.name}.schema-violation.put.log"
    put_accept_log = f"/tmp/prefix-insertion-lvs-{producer.name}.accept.put.log"
    os.system(f"dd if=/dev/urandom of={test_file} bs=64K count=1 status=none")
    router_face = f"udp4://{router_ip}:6363"

    rejected_prefix = f"{network}/{producer.name}/lvs-rejected"
    reject_cmd = (
        f"NDN_CLIENT_ROUTING_MODE=stub "
        f"NDN_CLIENT_ROUTER_URI={router_face} "
        f"ndnd put --expose \"{rejected_prefix}\" < {test_file} > {put_reject_log} 2>&1 &"
    )
    info(f"{producer.name} {reject_cmd}\n")
    producer.cmd(reject_cmd)
    test_003._wait_for_default_router_pet(producer, router_face)
    _wait_for_prefix_absence(router, rejected_prefix)

    schema_violation_keychain = _prepare_schema_violation_keychain(producer, network)
    schema_violation_prefix = f"{network}/{producer.name}/lvs-schema-violation"
    schema_violation_cmd = (
        f"NDN_CLIENT_ROUTING_MODE=stub "
        f"NDN_CLIENT_ROUTER_URI={router_face} "
        f"NDND_CLIENT_KEYCHAIN=dir://{schema_violation_keychain} "
        f"NDND_CLIENT_TRUST_SCHEMA={CLIENT_LVS_SCHEMA} "
        f"NDND_CLIENT_TRUST_ANCHORS='{dv.TRUST_ROOT_NAME}' "
        f"ndnd put --expose \"{schema_violation_prefix}\" < {test_file} > {put_schema_violation_log} 2>&1 &"
    )
    info(f"{producer.name} {schema_violation_cmd}\n")
    producer.cmd(schema_violation_cmd)

    _wait_for_prefix_absence(router, schema_violation_prefix)
    _wait_for_trust_schema_violation(router, schema_violation_prefix)

    producer_keychain = _prepare_producer_keychain(producer, network)
    accepted_prefix = f"{network}/{producer.name}/lvs-accepted"
    accept_cmd = (
        f"NDN_CLIENT_ROUTING_MODE=stub "
        f"NDN_CLIENT_ROUTER_URI={router_face} "
        f"NDND_CLIENT_KEYCHAIN=dir://{producer_keychain} "
        f"NDND_CLIENT_TRUST_SCHEMA={CLIENT_LVS_SCHEMA} "
        f"NDND_CLIENT_TRUST_ANCHORS='{dv.TRUST_ROOT_NAME}' "
        f"ndnd put --expose \"{accepted_prefix}\" < {test_file} > {put_accept_log} 2>&1 &"
    )
    info(f"{producer.name} {accept_cmd}\n")
    producer.cmd(accept_cmd)

    test_003._wait_for_prefix_insertion(router, accepted_prefix)
    dv_util.wait_prefix_pet_ready({consumer: {accepted_prefix}, router: {accepted_prefix}}, deadline=180)

    cat_cmd = f'ndnd cat "{accepted_prefix}" > {recv_file} 2> /tmp/prefix-insertion-lvs-cat.log'
    info(f"{consumer.name} {cat_cmd}\n")
    consumer.cmd(cat_cmd)

    if consumer.cmd(f"diff {test_file} {recv_file}").strip():
        cat_log = consumer.cmd("cat /tmp/prefix-insertion-lvs-cat.log")
        reject_out = producer.cmd(f"tail -n 100 {put_reject_log}")
        schema_violation_out = producer.cmd(f"tail -n 100 {put_schema_violation_log}")
        accept_out = producer.cmd(f"tail -n 100 {put_accept_log}")
        raise Exception(
            "LVS prefix insertion transfer mismatch\n"
            f"cat.log:\n{cat_log}\n"
            f"reject-put.log:\n{reject_out}\n"
            f"schema-violation-put.log:\n{schema_violation_out}\n"
            f"accept-put.log:\n{accept_out}\n"
        )
