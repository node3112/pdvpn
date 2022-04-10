#!/usr/bin/env python3

import logging
import threading
from typing import Union, List

from . import Peer
from .discovery import PeerDiscoverer
from ..info import PeerInfo


class PeerHandler:
    """
    Responsible for handling remote peers, routing traffic to them and peer discovery.
    """
    
    @property
    def paired(self) -> bool:
        """
        :return: Whether or not any paired peers are known.
        """
        
        return bool(self.peer_infos)
        
    @property
    def connected(self) -> bool:
        """
        :return: Whether or not we have any connection to the network.
        """
        
        return bool(self.paired_peers) or bool(self.unpaired_peers)
        
    @property
    def all_peers(self) -> List[Peer]:
        """
        :return: A list of all connected peers, mutable.
        """
        
        return self.paired_peers.copy() + self.unpaired_peers.copy()

    def __init__(self, local: "Local", peer_infos: Union[List[PeerInfo], None] = None) -> None:
        self.logger = logging.getLogger("pdvpn.peer.handler")
        
        self.local = local
        self.discoverer = PeerDiscoverer(self.local)
        
        self.peer_infos = []
        if peer_infos is not None:
            self.peer_infos.extend(peer_infos)
            
        self.logger.debug("%i paired peer(s)." % len(self.peer_infos))
        
        self.paired_peers: List[Peer] = []
        self.unpaired_peers: List[Peer] = []
        
        self._lock = threading.RLock()  # Events will be fired in different threads
        
    # ------------------------------ Events ------------------------------ #
    
    def on_peer_connected(self, peer: Peer, outbound: bool = False) -> None:
        """
        Called when a peer connects to us.
        
        :param peer: The peer that connected.
        :param outbound: Whether or not the peer is an outbound peer.
        """
        
        with self._lock:
            if not peer in self.paired_peers and not peer in self.unpaired_peers:
                self.logger.info("New peer: %s:%i (%s)." % (peer.address + ("outbound" if outbound else "inbound",)))
                # We don't know their intentions yet, so we'll say they're unpaired
                self.unpaired_peers.append(peer)
            
    def on_peer_disconnected(self, peer: Peer, reason: str = "unknown") -> None:
        """
        Called when a peer disconnects.
        
        :param peer: The peer that disconnected.
        :param reason: The reason for the disconnect, if any.
        """
        
        with self._lock:
            if peer in self.paired_peers or peer in self.unpaired_peers:
                self.logger.info("Disconnected from peer %s:%i: %r." % (peer.address + (reason,)))
            if peer in self.paired_peers:
                self.paired_peers.remove(peer)
            if peer in self.unpaired_peers:
                self.unpaired_peers.remove(peer)
            
    def on_peer_paired(self, peer: Peer) -> None:
        """
        Called when a peer pairs with us.
        
        :param peer: The peer that paired with us.
        """
        
        with self._lock:
            if peer in self.unpaired_peers:
                self.unpaired_peers.remove(peer)
            if not peer in self.paired_peers:
                self.logger.info("Paired with peer %s:%i." % peer.address)
                self.paired_peers.append(peer)
            
    # ------------------------------ Interfacing ------------------------------ #
    
    # TODO: Broadcasting stuff
            
    def discover(self) -> None:
        """
        Discovers peers from public entrypoints.
        """
        
        potential_peers = self.discoverer.discover()

        # TODO: Request tunnel to peers, verify they are valid, and connect to them

    def update_node_list(self, timeout: float = 30) -> None:
        """
        Requests the latest node list from all known peers.

        :param timeout: The timeout to use for each individual request.
        """

        self.logger.info("Attempting to update current node list...")
        self.logger.debug("Requesting revisions from %i peer(s)." % (len(self.paired_peers) + len(self.unpaired_peers)))

        revisions = []
        for peer in self.all_peers:
            try:
                revision, hash_ = peer.request_node_list_revision()
                if revision:
                    revisions.append((revision, hash_, peer))
            except Exception as error:
                self.logger.warning("Failed to request node list revision from peer %s:%i." % peer.address,
                                    exc_info=True)  # TODO: Maybe I should go easier on the exc_info=True's

        if not revisions:
            self.logger.warning("No node list revisions found, wtf?")
            return

        self.logger.debug("Found %i revision(s)." % len(revisions))

        current_revision = self.local.node_list.revision if self.local.node_list is not None else -1
        for revision, hash_, peer in revisions:
            if revision > current_revision:
                current_revision = revision

        if self.local.node_list is not None and self.local.node_list.revision == current_revision and \
                self.local.node_list.verify_signature(self.local._master_key):
            self.logger.info("Current node list (revision %i) is up to date." % current_revision)
            return

        node_lists = []
        for revision, hash_, peer in revisions:
            if revision == current_revision:
                try:
                    self.logger.debug("Requesting ndoe list from %s:%i." % peer.address)
                    node_list = peer.request_node_list(timeout=timeout)
                    if node_list is not None and node_list.verify_signature(self.local._master_key):
                        node_lists.append(node_list)
                    self.logger.info("Latest node list revision: %i (from %s:%i)." % ((current_revision,) + peer.address))
                    break

                except Exception as error:
                    self.logger.debug("Failed to request node list from peer %s:%i." % peer.address, exc_info=True)

        self.local.node_list = node_lists[0]  # The first one should be adequate
        self.local.data_provider.set_nodes(self.local.node_list)

    def disconnect_all(self, reason: str = "unknown") -> None:
        """
        Disconnects all peers currently connected, paired or unpaired.
        
        :param reason: The reason to give the peers for the disconnect.
        """
        
        if self.paired_peers:
            self.logger.debug("Disconnecting %i paired peer(s)..." % len(self.paired_peers))
            for peer in self.paired_peers.copy():
                peer.disconnect(reason)
        
        if self.unpaired_peers:
            self.logger.debug("Disconnecting %i unpaired peer(s)..." % len(self.unpaired_peers))
            for peer in self.unpaired_peers.copy():
                peer.disconnect(reason)
        

from ..local import Local
