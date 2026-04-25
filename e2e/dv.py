import json
import subprocess
import shutil
from pathlib import Path

from minindn.apps.application import Application

DEFAULT_NETWORK = '/minindn'
CLIENT_LVS_SCHEMA = str(Path(__file__).resolve().parent / "client_lvs_minindn.tlv")
ROUTING_LVS_SCHEMA = str((Path(__file__).resolve().parent.parent / "dv" / "config" / "schema.tlv"))

TRUST_ROOT_NAME: str = None
TRUST_ROOT_PATH = '/tmp/mn-dv-root'

class NDNd_DV(Application):
    config: str
    network: str

    def __init__(
        self,
        node,
        network=DEFAULT_NETWORK,
        routing_keychain=None,
        routing_trust_anchors=None,
        routing_trust_schema=None,
        prefix_insertion_keychain='inherit',
        prefix_insertion_trust_anchors=None,
        prefix_insertion_trust_schema=None,
        prefix_egre_state_replicate=None,
    ):
        Application.__init__(self, node)
        self.network = network

        if not shutil.which('ndnd'):
            raise Exception('ndnd not found in PATH, did you install it?')

        if TRUST_ROOT_NAME is None:
            raise Exception('Trust root not initialized (call NDNDV.init_trust first)')

        self.init_keys()
        if prefix_insertion_trust_anchors is None:
            prefix_insertion_trust_anchors = []
        router_keychain = f'dir://{self.homeDir}/dv-keys'
        if routing_keychain is None:
            routing_keychain = router_keychain
        if routing_trust_anchors is None:
            routing_trust_anchors = [TRUST_ROOT_NAME]
        if routing_trust_schema is None:
            routing_trust_schema = ROUTING_LVS_SCHEMA
        if routing_trust_schema and not Path(routing_trust_schema).exists():
            raise Exception(f'Routing trust schema file not found: {routing_trust_schema}')
        if prefix_insertion_keychain in (None, 'inherit', 'router'):
            prefix_insertion_keychain = router_keychain
        if prefix_insertion_trust_schema is None:
            if network != DEFAULT_NETWORK:
                raise Exception(
                    'prefix_insertion_trust_schema must be provided when network != /minindn'
                )
            prefix_insertion_trust_schema = CLIENT_LVS_SCHEMA

        config = {
            'dv': {
                'network': network,
                'router': f"{network}/{node.name}",
                'keychain': routing_keychain,
                'trust_anchors': routing_trust_anchors,
                'trust_schema': routing_trust_schema,
                'prefix_insertion_keychain': prefix_insertion_keychain,
                'prefix_insertion_trust_anchors': prefix_insertion_trust_anchors,
                'prefix_insertion_trust_schema': prefix_insertion_trust_schema,
                'neighbors': list(self.neighbors()),
            }
        }
        if prefix_egre_state_replicate is not None:
            config['dv']['prefix_egre_state_replicate'] = prefix_egre_state_replicate

        self.config = f'{self.homeDir}/dv.config.json'
        with open(self.config, 'w') as f:
            json.dump(config, f, indent=4)

    def start(self):
        Application.start(self, ['ndnd', 'dv', 'run', self.config], logfile='dv.log')

    @staticmethod
    def init_trust(network=DEFAULT_NETWORK) -> None:
        global TRUST_ROOT_NAME
        out = subprocess.check_output(f'ndnd sec keygen {network} ed25519 > {TRUST_ROOT_PATH}.key', shell=True)
        out = subprocess.check_output(f'ndnd sec sign-cert {TRUST_ROOT_PATH}.key < {TRUST_ROOT_PATH}.key > {TRUST_ROOT_PATH}.cert', shell=True)
        out = subprocess.check_output(f'cat {TRUST_ROOT_PATH}.cert | grep "Name:" | cut -d " " -f 2', shell=True)
        TRUST_ROOT_NAME = out.decode('utf-8').strip()

    def init_keys(self) -> None:
        self.node.cmd(f'rm -rf dv-keys && mkdir -p dv-keys')
        self.node.cmd(f'ndnd sec keygen {self.network}/{self.node.name}/32=DV ed25519 > dv-keys/{self.node.name}.key')
        self.node.cmd(f'ndnd sec sign-cert {TRUST_ROOT_PATH}.key < dv-keys/{self.node.name}.key > dv-keys/{self.node.name}.cert')
        self.node.cmd(f'cp {TRUST_ROOT_PATH}.cert dv-keys/')

    def neighbors(self):
        for intf in self.node.intfList():
            other_intf = intf.link.intf2 if intf.link.intf1 == intf else intf.link.intf1
            yield {"uri": f"udp4://{other_intf.IP()}:6363"}
