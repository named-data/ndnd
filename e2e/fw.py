import json
import os
import shutil

from minindn.apps.application import Application

class NDNd_FW(Application):
    def __init__(self, node, config={}, logLevel='TRACE', threads=2, network='/minindn', bier_index=-1):
        Application.__init__(self, node)

        if not shutil.which('ndnd'):
            raise Exception('ndnd not found in PATH, did you install it?')

        self.logFile = 'yanfd.log'
        logLevel = node.params['params'].get('nfd-log-level', logLevel)

        self.confFile = f'{self.homeDir}/yanfd.json'
        self.ndnFolder = f'{self.homeDir}/.ndn'
        self.clientConf = f'{self.ndnFolder}/client.conf'
        self.sockFile = f'/run/nfd/{node.name}.sock'

        self.envDict = {
            'GOMAXPROCS': str(threads),
        }

        # Make default configuration
        default_config = {
            'core': {
                'log_level': logLevel,
            },
            'faces': {
                # Higher queue to reduce drops in large CI topologies.
                'queue_size': 8192,
                'unix': {
                    'socket_path': self.sockFile,
                },
            },
            'fw': {
                'threads': threads,
                # Higher queue to reduce drops in large CI topologies.
                'queue_size': 8192,
                # Two-phase PET forwarding needs the local router identity.
                'router_name': f'{network}/{node.name}',
                # BIER bit index for this router (-1 = disabled)
                'bier_index': bier_index,
            },
        }

        # Write YaNFD config file
        with open(self.confFile, "w") as f:
            json.dump(default_config | config, f, indent=4)

        # Create client configuration for host to ensure socket path is consistent
        # Suppress error if working directory exists from prior run
        os.makedirs(self.ndnFolder, exist_ok=True)

        # This will overwrite any existing client.conf files, which should not be an issue
        with open(self.clientConf, "w") as client_conf_file:
            client_conf_file.write(f"transport=unix://{self.sockFile}\n")

    def start(self):
        Application.start(self, f'ndnd fw run {self.confFile}',
                          logfile=self.logFile, envDict=self.envDict)
