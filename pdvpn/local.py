#!/usr/bin/env python3

import logging
import random
import socket
import time
from typing import Union, List, Tuple, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from . import config
from .tunnel import Tunnel


class Local:
    """
    Local node running on this computer.
    """

    INSTANCE: Union["Local", None] = None

    def __init__(self, data_provider: Union["DataProvider", None]) -> None:
        Local.INSTANCE = self

        self.logger = logging.getLogger("pdvpn.local")
        self.logger.info("Initialising local...")

        if data_provider is None:
            self.logger.warning("No data provider specified, using default.")
            data_provider = FileDataProvider(config.DATA_FILE)

        self.data_provider = DataGenerator(data_provider)

        self.inid = self.data_provider.get_inid()
        self.logger.debug("Local node ID: %i" % self.inid)

        self._public_key: RSAPublicKey = serialization.load_pem_public_key(self.data_provider.get_public_key())
        self.__private_key: RSAPrivateKey = serialization.load_pem_private_key(self.data_provider.get_private_key(),
                                                                               password=None)

        self._master_key = serialization.load_pem_public_key(config.MASTER_KEY)

        self.node_list: Union[NodeList, None] = self.data_provider.get_nodes()
        self.logger.debug("%i known node(s)." % (len(self.node_list) if self.node_list is not None else 0))

        self.peer_infos: List[PeerInfo] = self.data_provider.get_peers()
        self.logger.debug("%i paired peer(s)." % len(self.peer_infos))

        self._inbound_listener: Union[InboundPeerListener, None] = None
        self.running = False

        self.paired_peers: List[Peer] = []
        self.unpaired_peers: List[Peer] = []
        self.tunnels: List[Tunnel] = []

    def _can_do_inbound(self) -> bool:
        """
        Checks if the local node can accept inbound peers.
        """

        return True  # TODO: Figure this out, OS dependent really

    def _check_inid(self, node_list: Union["NodeList", None] = None) -> None:
        """
        Checks that our INID is valid, and is not already taken. If it is, change it.
        """

        if node_list is None:
            node_list = self.node_list
        if node_list is None:  # We have no data, so we can't tell
            return

        public_key = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Perhaps we are already in the list, we need to verify this by checking the public key as well
        while self.inid is None or (self.inid in node_list and node_list[self.inid].public_key != public_key):
            # noinspection PyProtectedMember
            self.inid = DataGenerator._generated_inid()  # TODO: Maybe we can move this somewhere else?

        self.data_provider.set_inid(self.inid)

    def _find_entrypoints(self) -> List["PeerInfo"]:
        """
        Finds network entrypoints.
        """

        return [PeerInfo("spleefnet.ninja", 5001)]  # TODO: Implement

    def _get_node_list(self, entrypoints: List["PeerInfo"]) -> Union[Tuple["NodeList", "Peer"], Tuple[None, None]]:
        """
        Connects to the provided entrypoints and gets a valid node list.
        """

        potential_node_lists: List[Tuple[NodeList, PeerInfo]] = []

        for entrypoint in entrypoints:
            self.logger.info("Attempting to connect to entrypoint %s:%i..." % entrypoint.address)

            try:
                # All entrypoints are outbound, obviously
                peer = OutboundPeer(self, socket.socket(socket.AF_INET, socket.SOCK_STREAM), *entrypoint.address)
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

            if not node_list.verify_signature(self):  # They have changed something about the list
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

        self.logger.debug("Latest node list is valid until %s (from entrypoint %s:%i)." %
                          ((latest_node_list.valid_until,) + best_entrypoint.address))
        self.logger.debug("Reconnecting to entrypoint %s:%i..." % best_entrypoint.address)
        try:
            peer = OutboundPeer(self, socket.socket(socket.AF_INET, socket.SOCK_STREAM), *best_entrypoint.address)
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
            # TODO: random_node.inid != self.inid????? <- would we not already be connected to the network?
            if random_node.inid != self.inid and not random_node in potential_peers:
                potential_peers.append(random_node)

        return potential_peers

    def run(self) -> None:
        self.running = True

        # If we're the initial node, we should expect inbound connections, we'll pair later
        if not self.peer_infos and not config.INITIAL_NODE:
            self.logger.info("No peers found, starting discovery...")

            entrypoints = self._find_entrypoints()
            if not entrypoints:
                self.logger.fatal("No entrypoints found, cannot connect to network.")
                self.running = False
                return

            node_list, entrypoint_peer = self._get_node_list(entrypoints)
            if not node_list:
                self.logger.fatal("No valid node list found, cannot connect to network.")
                self.running = False
                return

            if self.node_list is not None and self.node_list.verify_signature(self):  # Is our node list valid?
                if self.node_list.valid_until < node_list.valid_until:
                    self.logger.info("Node list is outdated, updating...")
                    self.node_list = node_list
                    self.data_provider.set_nodes(self.node_list)  # Save the new node list
                else:
                    self.logger.debug("Our node list is up-to-date, yay!")
                    node_list = self.node_list  # Use our node list, not whatever the entrypoint gave us

            self._check_inid(node_list)  # Make sure our INID is valid

            potential_peers = self._filter_peers(node_list)
            if not potential_peers:
                self.logger.fatal("No potential peers found, cannot connect to network.")
                self.running = False
                return

            self.logger.info("Found %i potential peer(s)." % len(potential_peers))

            # TODO: Generate new random public key and INID, temporarily, so we have something to identify ourselves with

            # TODO: Request tunnel to peers, verify they are valid, and connect to them

        do_inbound = config.INBOUND_ENABLED and self._can_do_inbound()

        if config.INITIAL_NODE:
            self.logger.info("We are acting as the initial node, if this is an error, please check your configuration.")

            if not do_inbound:
                self.logger.fatal("We are acting as the initial node, but inbound connections are disabled.")
                self.running = False
                return

            # We should have a signed node list with only us on it, if we don't, then something is wrong
            if (self.node_list is None or not self.node_list.verify_signature(self) or
                    not self.inid in self.node_list or
                    self.node_list[self.inid].public_key != self._public_key.public_bytes(  # We need all the valid info
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )):
                self.logger.fatal("Node list is invalid, cannot act as initial node.")
                self.running = False
                return

        if do_inbound:
            self._inbound_listener = InboundPeerListener(self)
            self._inbound_listener.start()

        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            ...

        self.logger.info("Shutting down local node...")
        self.running = False

        if self._inbound_listener is not None and self._inbound_listener.is_alive():
            self._inbound_listener.join()

        self.logger.debug("Disconnecting all peers...")
        for peer in self.paired_peers.copy() + self.unpaired_peers.copy():
            peer.disconnect("local node shutdown")

        self.logger.info("Local node shutdown.")


from .info import NodeList, PeerInfo
from .data import DataProvider, FileDataProvider, DataGenerator
from .p2p import Peer
from .p2p.inbound import InboundPeerListener
from .p2p.outbound import OutboundPeer
