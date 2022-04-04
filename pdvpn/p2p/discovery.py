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

    def _find_entrypoints(self) -> List["PeerInfo"]:
        """
        Finds network entrypoints.
        """

        return [PeerInfo("localhost", 5002)]  # TODO: Implement

    def _get_node_list(self, entrypoints: List["PeerInfo"]) -> Union[Tuple["NodeList", Peer], Tuple[None, None]]:
        """
        Connects to the provided entrypoints and gets a valid node list.
        """

        potential_node_lists: List[Tuple[NodeList, PeerInfo]] = []

        for entrypoint in entrypoints:
            self.logger.info("Attempting to connect to entrypoint %s:%i..." % entrypoint.address)

            try:
                # All entrypoints are outbound, obviously
                peer = OutboundPeer(self.local, socket.socket(socket.AF_INET, socket.SOCK_STREAM), *entrypoint.address)
                peer.connect()
                peer.start()

            except Exception as error:
                self.logger.error("Error while connecting to entrypoint %s:%i." % entrypoint.address, exc_info=True)
                continue

            while not peer.ready and peer.connected:  # Wait until it is ready, or until it disconnects
                time.sleep(0.05)

            if not peer.connected:
                self.logger.warning("Entrypoint %s:%i disconnected." % entrypoint.address)
                continue

            try:
                self.logger.info("Receiving node list from entrypoint %s:%i..." % entrypoint.address)
                node_list = peer.request_node_list()
            except Exception as error:
                self.logger.error("Error while requesting node list from entrypoint %s:%i." % entrypoint.address,
                                  exc_info=True)
                peer.disconnect("nodelist error")
                peer.join()
                continue

            if not node_list.verify_signature(self.local):  # They have changed something about the list
                self.logger.warning("Node list signature from %s:%i is invalid." % entrypoint.address)
                peer.disconnect("nodelist signature invalid")
                peer.join()
                continue

            # Doesn't necessarily mean it's been tampered with, they might not be up-to-date, so we'll store it and
            # check the other entrypoints, to see if they have a more up-to-date version
            if not node_list.valid:
                potential_node_lists.append((node_list, entrypoint))
                peer.disconnect("node list not up-to-date")
                peer.join()
                continue

            # Excellent, we have an up-to-date node list!
            self.logger.info("Node list from %s:%i is up-to-date." % entrypoint.address)

            return node_list, peer

        if not potential_node_lists:  # Damn, we're out of options
            return None, None

        self.logger.warning("No up-to-date entrypoints, perhaps the network isn't accepting new nodes?")
        self.logger.info("Continuing with the latest node list anyway...")

        # TODO: Do we want to handle node lists ahead of time? I mean I'm not sure why those would be generated though
        latest_node_list, best_entrypoint = max(potential_node_lists, key=lambda pair: pair[0].valid_until)

        # noinspection PyTypeChecker
        self.logger.debug("Latest node list is valid until %s (from entrypoint %s:%i)." %
                          ((latest_node_list.valid_until,) + best_entrypoint.address))
        self.logger.debug("Reconnecting to entrypoint %s:%i..." % best_entrypoint.address)
        try:
            peer = OutboundPeer(self.local, socket.socket(socket.AF_INET, socket.SOCK_STREAM), *best_entrypoint.address)
            peer.connect()
            peer.start()

        except Exception as error:  # Our best entrypoint is offline, so redo all this, removing the best entrypoint
            self.logger.error("Error while connecting to entrypoint %s:%i." % best_entrypoint.address, exc_info=True)

            entrypoints = entrypoints.copy()
            entrypoints.remove(best_entrypoint)  # This entrypoint is offline, so don't reconnect to it
            if entrypoints:
                return self._get_node_list(entrypoints)
            else:
                return None, None

        return latest_node_list, peer

    def _filter_peers(self, node_list: "NodeList") -> List["NodeList.NodeInfo"]:
        """
        Finds potential nodes in the node list that can act as peers, based on geolocation. Up to 10 nodes are returned.
        """

        # TODO: Geolocation stuff

        node_infos = list(node_list.values())
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
            self.logger.fatal("No entrypoints found, cannot connect to network.")
            return None

        node_list, entrypoint_peer = self._get_node_list(entrypoints)
        if entrypoint_peer is None:
            self.logger.fatal("All known entrypoints are offline, unable to connect to network.")
            return None

        if self.local.node_list is not None and self.local.node_list.verify_signature(self.local):  # Is our node list valid?
            if node_list is not None and self.local.node_list.valid_until < node_list.valid_until:
                self.logger.info("Node list is outdated, updating...")
                self.local.node_list = node_list
                self.local.data_provider.set_nodes(self.local.node_list)  # Save the new node list
            else:
                if node_list is not None:  # Check we were actually given one
                    self.logger.debug("Our node list is up-to-date, yay!")
                node_list = self.local.node_list  # Use our node list, not whatever the entrypoint gave us

        elif node_list is not None:
            self.local.node_list = node_list
            self.local.data_provider.set_nodes(self.local.node_list)

        if not node_list:
            self.logger.fatal("No valid node list found, cannot connect to network.")
            return None

        potential_peers = self._filter_peers(node_list)
        if not potential_peers:
            self.logger.fatal("No potential peers found, cannot connect to network.")
            return None

        self.logger.info("Discovered %i potential peer(s)." % len(potential_peers))

        return []


from ..info import PeerInfo, NodeList
from ..local import Local
