import random
import os

from mininet.log import info
from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager

from fw import NDNd_FW
import dv_util

def scenario(ndn: Minindn, network='/minindn'):
    """
    Simple file transfer scenario with NDNd forwarder.
    This tests routing convergence and cat/put operations.
    """

    info('Starting forwarder on nodes\n')
    AppManager(ndn, ndn.net.hosts, NDNd_FW, network=network)

    dv_util.setup(ndn, network=network)
    dv_util.converge(ndn.net.hosts, network=network)

    info('Testing file transfer\n')
    test_file = '/tmp/test.bin'
    os.system(f'dd if=/dev/urandom of={test_file} bs=64K count=1')

    sample_size = min(8, len(ndn.net.hosts)-1)
    put_nodes = random.sample(ndn.net.hosts, sample_size)
    cat_nodes = random.sample(ndn.net.hosts, sample_size)
    cat_requests = [(cat_node, random.choice(put_nodes)) for cat_node in cat_nodes]
    put_prefixes = {f"{network}/{node.name}/test" for node in put_nodes}
    control_prefixes = {
        f"/localhop{network}/32=DV/32=PES/32=svs",
        f"/localhop{network}/32=DV/32=ADS/32=PSV",
    }

    for node in put_nodes:
        prefix = f"{network}/{node.name}/test"
        cmd = f'ndnd put --expose "{prefix}" < {test_file} &'
        info(f'{node.name} {cmd}\n')
        node.cmd(cmd)

    # New pipeline requires PET propagation before Interests can be forwarded.
    expected = {node: set(put_prefixes) for node in ndn.net.hosts}
    dv_util.wait_prefix_pet_ready(expected, deadline=180)

    # Prefix traffic should remain PET-driven; app prefixes must not be injected into FIB.
    for node in ndn.net.hosts:
        fib = node.cmd('ndnd fw fib-list')
        for prefix in put_prefixes:
            if prefix in fib:
                raise Exception(f'App prefix {prefix} unexpectedly present in FIB on {node.name}')
        for prefix in control_prefixes:
            if prefix in fib:
                raise Exception(f'Control prefix {prefix} unexpectedly present in FIB on {node.name}')
        if f'{network}/32=DV/32=PES/' in fib:
            raise Exception(f'Router-specific PES entries unexpectedly present in FIB on {node.name}')
        if f'/localhop{network}/' in fib and '/32=DV' in fib:
            raise Exception(f'Router-specific localhop DV entries unexpectedly present in FIB on {node.name}')

    # Validate the deprecation of multicast in DV code (#174)
    for node in ndn.net.hosts:
        strategy = node.cmd('ndnd fw strategy-list')
        if "multicast" in strategy:
            raise Exception(f'Multicast is to be retired, unexpectedly present in strategy on {node.name}')

    for node, put_node in cat_requests:
        cmd = f'ndnd cat "{network}/{put_node.name}/test" > recv.test.bin 2> cat.log'
        info(f'{node.name} {cmd}\n')
        node.cmd(cmd)
        if node.cmd(f'diff {test_file} recv.test.bin').strip():
            info(node.cmd(f'cat cat.log'))
            raise Exception(f'Test file contents do not match on {node.name}')
