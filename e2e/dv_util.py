import time

from mininet.log import info
from mininet.node import Node

from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager

from dv import NDNd_DV, DEFAULT_NETWORK

def setup(ndn: Minindn, network=DEFAULT_NETWORK) -> None:
    time.sleep(1) # wait for fw to start

    NDNd_DV.init_trust()
    info('Starting ndn-dv on nodes\n')
    AppManager(ndn, ndn.net.hosts, NDNd_DV, network=network)

def converge(nodes: list[Node], deadline=30, network=DEFAULT_NETWORK, use_nfdc=False) -> int:
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
            routes = node.cmd('ndnd fw route-list')
        for other in nodes:
            if f'{network}/{other.name}' not in routes:
                info(f'Routing not converged on {node.name} for {other.name}\n')
                converged = False
                break # break out of inner loop
        if not converged:
            return False
    return converged
