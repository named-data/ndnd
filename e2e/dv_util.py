import time

from mininet.log import info
from mininet.node import Node

from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager

import dv
from dv import NDNd_DV, DEFAULT_NETWORK

def setup(ndn: Minindn, network=DEFAULT_NETWORK, nodes=None, app_cls=NDNd_DV, **dv_kwargs) -> None:
    time.sleep(1) # wait for fw to start

    NDNd_DV.init_trust(network=network)
    root_anchor = dv.TRUST_ROOT_NAME

    routing_anchors = dv_kwargs.get('routing_trust_anchors')
    if not routing_anchors or any(a is None or a == '' for a in routing_anchors):
        dv_kwargs['routing_trust_anchors'] = [root_anchor]

    dv_kwargs.setdefault('routing_trust_schema', dv.ROUTING_LVS_SCHEMA)
    dv_kwargs.setdefault('prefix_insertion_keychain', 'inherit')

    prefix_anchors = dv_kwargs.get('prefix_insertion_trust_anchors')
    if not prefix_anchors or any(a is None or a == '' for a in prefix_anchors):
        dv_kwargs['prefix_insertion_trust_anchors'] = [root_anchor]

    if network == DEFAULT_NETWORK:
        dv_kwargs.setdefault('prefix_insertion_trust_schema', dv.CLIENT_LVS_SCHEMA)
    info('Starting ndn-dv on nodes\n')
    if nodes is None:
        nodes = ndn.net.hosts
    AppManager(ndn, nodes, app_cls, network=network, **dv_kwargs)

def converge(nodes: list[Node], deadline=120, network=DEFAULT_NETWORK, use_nfdc=False) -> int:
    info('Waiting for routing to converge\n')
    start = time.time()
    while time.time() - start < deadline:
        time.sleep(1)
        if is_converged(nodes, network=network, use_nfdc=use_nfdc):
            total = round(time.time() - start)
            info(f'Routing converged in {total} seconds\n')
            return total

    raise Exception('Routing did not converge')

def is_converged(nodes: list[Node], network=DEFAULT_NETWORK, use_nfdc=False) -> bool:
    converged = True
    for node in nodes:
        if use_nfdc:
            # NFD returns status datasets without a FinalBlockId.
            # We don't support that.
            routes = node.cmd('nfdc route list')
        else:
            routes = node.cmd('ndnd fw route-list 2>&1')
        for other in nodes:
            if other == node:
                continue
            if f'{network}/{other.name}' not in routes:
                info(f'Routing not converged on {node.name} for {other.name}\n')
                converged = False
                break # break out of inner loop
        if not converged:
            return False
    return converged

def wait_prefix_pet_ready(node_to_prefixes: dict[Node, set[str]], deadline=30) -> int:
    info('Waiting for PET prefix replication\n')
    start = time.time()
    while time.time() - start < deadline:
        all_ready = True
        for node, prefixes in node_to_prefixes.items():
            pet = node.cmd('ndnd fw pet-list')
            for prefix in prefixes:
                if f'  {prefix} ' not in pet:
                    info(f'PET not ready on {node.name} for {prefix}\n')
                    all_ready = False
                    break
            if not all_ready:
                break

        if all_ready:
            total = round(time.time() - start)
            info(f'PET replication converged in {total} seconds\n')
            return total

        time.sleep(1)

    raise Exception('PET prefix replication did not converge')

def assign_bier_indices(hosts: list[Node]) -> dict[Node, int]:
    """Assign a unique BIER index to each host, sorted by name."""
    sorted_hosts = sorted(hosts, key=lambda h: h.name)
    return {host: idx for idx, host in enumerate(sorted_hosts)}


def populate_bift(nodes: list[Node], bier_map: dict, network=DEFAULT_NETWORK):
    info(f'Deploying BIER indices to BIFT ({len(bier_map)} routers)...\n')
    for node in nodes:
        for router, idx in bier_map.items():
            router_name = f'{network}/{router.name}'
            node.cmd(f'ndnd fw bift-register prefix="{router_name}" index={idx}')
        node.cmd('ndnd fw bift-rebuild')
    info('BIFT populated on all nodes\n')


def dump_bier_logs(nodes: list[Node], label: str = '', lines: int = 40) -> str:
    """Return BIER-relevant log lines from each node's ndnd log (for failure diagnostics)."""
    out = f'\n=== BIER forwarder logs{" (" + label + ")" if label else ""} ===\n'
    for node in nodes:
        log = node.cmd(
            f'cat /tmp/minindn/{node.name}/log/yanfd.log'
            f' 2>/dev/null | grep -iE "bier|bift|bfir|bfr|bfer|strategy" | tail -{lines}'
        )
        if log.strip():
            out += f'--- {node.name} ---\n{log}\n'
    return out
