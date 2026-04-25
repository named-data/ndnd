import os

from mininet.log import info
from minindn.apps.app_manager import AppManager
from minindn.minindn import Minindn

import dv
import dv_util
import test_006
from dv import NDNd_DV
from fw import NDNd_FW


class NDNdDVCoreNoPrefixReplicate(NDNd_DV):
    def __init__(self, node, network=dv.DEFAULT_NETWORK, **kwargs):
        super().__init__(
            node,
            network=network,
            prefix_egre_state_replicate=not node.name.startswith("c"),
            **kwargs,
        )


def _assert_pet_absent(node, prefix: str):
    pet = node.cmd("ndnd fw pet-list")
    for line in pet.splitlines():
        if line.startswith(f"  {prefix} "):
            raise Exception(
                f"PET entry for {prefix} unexpectedly present on {node.name}\n"
                f"pet-list:\n{pet}\n"
            )


def scenario(ndn: Minindn, network="/minindn"):
    """
    Forwarding-plane scenario with prefix_egre_state_replicate disabled on c* routers.

    Expectations:
    - edge routers still learn remote edge prefixes in PET and can fetch each
      other's content successfully.
    - core routers do not mirror application prefixes into PET; this scenario
      validates that behavior structurally, while only exercising fetches from
      the edge routers.
    """

    nodes, cores, edges = test_006._partition_nodes(ndn)
    ordered = cores + edges

    info("Starting forwarder on c*/e* topology with PET replication disabled on cores\n")
    AppManager(ndn, ordered, NDNd_FW, network=network)

    dv_util.setup(
        ndn,
        network=network,
        nodes=ordered,
        app_cls=NDNdDVCoreNoPrefixReplicate,
    )
    dv_util.converge(ordered, network=network)

    payload_paths = {}
    prefixes = {}
    for edge in edges:
        prefix = f"{network}/{edge.name}/forwarding-plane"
        payload_path = f"/tmp/{edge.name}-forwarding-plane-core-no-pes.bin"
        with open(payload_path, "wb") as f:
            f.write(os.urandom(4096))

        prefixes[edge.name] = prefix
        payload_paths[edge.name] = payload_path
        test_006._publish_test_data(edge, prefix, payload_path)

    # Only the edges should mirror remote edge prefixes into PET in this setup.
    dv_util.wait_prefix_pet_ready({node: set(prefixes.values()) for node in edges}, deadline=180)

    for node in ordered:
        test_006._assert_pet_only_prefixes(node, set(prefixes.values()), network)

    for edge in edges:
        test_006._assert_pet_origin(edge, prefixes[edge.name], f"{network}/{edge.name}")

    for edge in edges:
        for remote in edges:
            if edge == remote:
                continue
            test_006._assert_pet_egress_only(
                edge,
                prefixes[remote.name],
                f"{network}/{remote.name}",
            )

    for core in cores:
        for producer in edges:
            _assert_pet_absent(core, prefixes[producer.name])

    for consumer in edges:
        for producer in edges:
            if consumer == producer:
                continue
            test_006._fetch_and_compare(
                consumer,
                prefixes[producer.name],
                payload_paths[producer.name],
                f"{consumer.name}-from-{producer.name}",
            )
