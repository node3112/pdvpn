#!/usr/bin/env python3

import logging
import random
import socket
import time
from typing import List, Union, Tuple

from . import Peer
from .outbound import OutboundPeer


class PeerDiscoverer:
    """
    Discovers peers through entrypoints.
    """

    def __init__(self, local: "Local") -> None:
        self.logger = logging.getLogger("pdvpn.p2p.discovery")

        self.local = local

    # ------------------------------ Hidden methods ------------------------------ #

    # noinspection PyMethodMayBeStatic
    def _find_entrypoints(self) -> List[Peer]:
        """
        Finds network entrypoints.
        """

        # TODO: Implement entrypoint discovery
        entrypoints = [PeerInfo("localhost", 5002), PeerInfo("spleefnet.ninja", 5001)]
        online_entrypoints = []

        self.logger.info("Have %i entrypoint(s), checking for online ones..." % len(entrypoints))
        for entrypoint in entrypoints:
            try:
                addr_info = socket.getaddrinfo(entrypoint.host, entrypoint.port, socket.AF_INET, socket.SOCK_STREAM)
                if addr_info:
                    address: Tuple[str, int] = addr_info[0][4]

                    try:
                        # All entrypoints are outbound, obviously
                        peer = OutboundPeer(self.local, socket.socket(socket.AF_INET, socket.SOCK_STREAM), *address)
                        peer.connect()
                        peer.start()

                        while not peer.ready and peer.connected:
                            time.sleep(0.05)

                        if peer.connected:
                            online_entrypoints.append(peer)
                            self.logger.debug("Entrypoint %s:%i (%s:%i) is online." % (entrypoint.address + address))

                    except Exception as error:
                        self.logger.debug("Error while connecting to %s:%i." % entrypoint.address, exc_info=True)
                        continue

            except Exception as error:
                self.logger.debug("Entrypoint %s:%i is offline." % entrypoint.address, exc_info=True)

        self.logger.info("Found %i online entrypoint(s)." % len(online_entrypoints))
        return online_entrypoints

    def _filter_peers(self) -> List["NodeList.NodeInfo"]:
        """
        Finds potential nodes in the node list that can act as peers, based on geolocation. Up to 10 nodes are returned.
        """

        # TODO: Geolocation stuff

        node_infos = list(self.local.node_list.nodes)  # TODO: We could also check unverified in the future?
        potential_peers: List[NodeList.NodeInfo] = []

        for index in range(10):
            random_node = random.choice(node_infos)
            # There could be so few nodes that we get the same one twice, it's fine to count it as a random choice
            # though as the network is obviously not saturated enough for this to matter. We should prefer having a
            # evenly distributed network, rather than a more concentrated one.
            # TODO: random_node.inid != self.local.inid????? <- would we not already be connected to the network?
            if random_node.inid != self.local.inid and not random_node in potential_peers:
                potential_peers.append(random_node)

        return potential_peers

    # ------------------------------ Public methods ------------------------------ #

    def discover(self) -> Union[List["PeerInfo"], None]:
        entrypoints = self._find_entrypoints()
        if not entrypoints:
            self.logger.fatal("No online entrypoints found, cannot connect to network.")
            return None

        self.local.peer_handler.update_node_list()  # Update the latest node list
        if self.local.node_list is None:  # Still haven't got the latest node list?
            self.logger.fatal("Could not retrieve valid node list, cannot connect to network.")
            return None

        if not self.local.node_list.valid:
            self.logger.warning("Node list is expired, perhaps the network isn't accepting new nodes?")

        # Ok, now we have the latest node list, let's find some peers to connect to

        potential_peers = self._filter_peers()
        if not potential_peers:
            self.logger.fatal("No potential peers found, cannot connect to network.")
            return None

        self.logger.info("Negotiating with %i potential peer(s)..." % len(potential_peers))
        for potential_peer in potential_peers:
            self.logger.debug("Tunneling to potential peer with INID %x..." % potential_peer.inid)
            tunnel = self.local.tunnel_handler.create_tunnel(potential_peer.inid)
            if tunnel is None:
                self.logger.debug("Failed to tunnel to potential peer with INID %x." % potential_peer.inid)
                continue

            try:
                tunnel.open(timeout=10)
            except Exception as error:
                self.logger.debug("Failed to open tunnel to potential peer with INID %x." % potential_peer.inid,
                                  exc_info=True)
                continue

            # TODO: Ask peer to pair

        else:
            while True:
                time.sleep(0.05)

            self.logger.fatal("Failed to connect to any potential peers.")
            return None  # TODO: Try again?

        return []


from ..info import PeerInfo, NodeList
from ..local import Local
