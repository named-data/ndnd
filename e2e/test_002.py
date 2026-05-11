import random
import os
import time

from mininet.log import info
from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager

from fw import NDNd_FW
import dv_util

def scenario(ndn: Minindn, network='/minindn'):
    """
    This scenario tests routing convergence and cat/put operations
    when a router joins the network
    after the network has already converged.
    """

    # Choose a node with a single link to the network
    lazy_node = random.choice([node for node in ndn.net.hosts if len(node.intfList()) == 1])
    if not lazy_node:
        raise Exception('No lazy node found')
    others = [node for node in ndn.net.hosts if node != lazy_node]

    # Disconnect the node from the network
    info(f'Disconnecting {lazy_node.name}\n')
    downIntf = lazy_node.intfList()[0]
    downIntf.config(loss=99.99)

    info('Starting forwarder on nodes\n')
    bier_map = dv_util.assign_bier_indices(ndn.net.hosts)
    for host in ndn.net.hosts:
        AppManager(ndn, [host], NDNd_FW, network=network, bier_index=bier_map[host])

    dv_util.setup(ndn, network=network)
    dv_util.converge(others)
    dv_util.populate_bift(others, bier_map, network=network)

    # Make sure the node is really disconnected
    if not dv_util.is_converged(others, network=network):
        raise Exception('Routing did not converge on other nodes (?!)')
    if dv_util.is_converged(ndn.net.hosts):
        raise Exception('Routing converged on lazy node (?!)')

    # Reconnect the node to the network
    info(f'Reconnecting {lazy_node.name}\n')
    downIntf.config(loss=0.0001)

    # Wait for convergence
    dv_util.converge(ndn.net.hosts)
    dv_util.populate_bift(ndn.net.hosts, bier_map, network=network)

    # Ensure that cat/put works with the newly joined node
    data = os.urandom(16).hex()
    put_prefix = f'{network}/{lazy_node.name}/test'
    cmd = f'ndnd put --expose "{put_prefix}" < <(echo {data}) &> put_log.txt &'
    info(f'{lazy_node.name} {cmd}\n')
    lazy_node.cmd(cmd)
    dv_util.wait_prefix_pet_ready(
        {node: {put_prefix} for node in ndn.net.hosts},
        deadline=180
    )

    sample_size = min(8, len(ndn.net.hosts))
    for node in random.sample(ndn.net.hosts, sample_size):
        cmd = f'ndnd cat "{put_prefix}" > recv.bin 2> cat.log'
        info(f'{node.name} {cmd}\n')
        node.cmd(cmd)
        cat_output = node.cmd(f'cat recv.bin').strip()
        if cat_output != data:
            info(node.cmd(f'cat cat.log'))
            raise Exception(f'Test file contents ({cat_output=} != {data=}) do not match on {node.name}')
