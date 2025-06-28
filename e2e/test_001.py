import random
import os
import time

from mininet.log import info
from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager
from minindn.apps.nfd import Nfd

from fw import NDNd_FW
import dv_util

def scenario_ndnd_fw(ndn: Minindn):
    scenario(ndn, fw=NDNd_FW)

def scenario_nfd(ndn: Minindn):
    scenario(ndn, fw=Nfd)

def scenario(ndn: Minindn, fw=None, network='/minindn'):
    """
    Simple file transfer scenario with NDNd and NFD forwarders.
    This tests routing convergence and cat/put operations.
    Also tests routing compatibility for both NDNd and NFD.
    """

    info('Starting forwarder on nodes\n')
    AppManager(ndn, ndn.net.hosts, fw)

    dv_util.setup(ndn, network=network)
    dv_util.converge(ndn.net.hosts, network=network, use_nfdc=(fw==Nfd))

    info('Testing file transfer\n')
    test_file = '/tmp/test.bin'
    os.system(f'dd if=/dev/urandom of={test_file} bs=10M count=1')

    sample_size = min(8, len(ndn.net.hosts)-1)
    put_nodes = random.sample(ndn.net.hosts, sample_size)
    cat_nodes = random.sample(ndn.net.hosts, sample_size)

    for node in put_nodes:
        cmd = f'ndnd put --expose "{network}/{node.name}/test" < {test_file} &'
        info(f'{node.name} {cmd}\n')
        node.cmd(cmd)

    info('Waiting for put to complete\n')
    time.sleep(30)

    for node in cat_nodes:
        put_node = random.choice(put_nodes)
        cmd = f'ndnd cat "{network}/{put_node.name}/test" > recv.test.bin 2> cat.log'
        info(f'{node.name} {cmd}\n')
        node.cmd(cmd)
        if node.cmd(f'diff {test_file} recv.test.bin').strip():
            info(node.cmd(f'cat cat.log'))
            raise Exception(f'Test file contents do not match on {node.name}')
