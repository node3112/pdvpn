#!/usr/bin/env python3

import logging
import random
import socket
import time
from typing import Union, List, Tuple, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from . import config, encryption


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
        self.tunnels: Dict[int, Tunnel] = {}

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

    # ------------------------------ Tunneling ------------------------------ #

    def create_tunnel(self, node_inid: int) -> "Tunnel":
        """
        Creates a new tunneled connection to the node given by its INID.

        :param node_inid: The node's INID.
        :return: The tunnel that was created.
        :exception: Thrown if creating the tunnel fails.
        """

        if not node_inid in self.node_list:
            raise LookupError("Node with INID %i not found in node list." % node_inid)

        tunnel_id = (self.inid * node_inid) % int(time.time())  # TODO: Better randomness
        public_key, private_key = encryption.generate_rsa_keypair(key_size=config.TUNNEL_RSA_KEY_SIZE)
        tunnel = Tunnel(self, tunnel_id, public_key, private_key)
        tunnel.endpoint = self.node_list[node_inid]

        self.tunnels[tunnel_id] = tunnel
        return tunnel

    def on_tunnel_request(self, hops: int, ttl: int, tunnel: "Tunnel", tunnel_data: bytes, peer: "Peer",
                          skip_owner_check: bool = False) -> None:
        """
        Called when a tunnel request is received.

        :param hops: The number of hops the request has made.
        :param ttl: The TTL of the request.
        :param tunnel: The tunnel.
        :param tunnel_data: The tunnel data.
        :param peer: The peer that sent the tunnel request.
        :param skip_owner_check: Don't check if we're the owner or not.
        """

        if tunnel.tunnel_id in self.tunnels:  # We have already been told about this tunnel
            return

        self.logger.debug("Received tunnel request from %s:%i hops=%i, ttl=%i, len=%i." %
                          (peer.address + (hops, ttl, len(tunnel_data))))
        self.tunnels[tunnel.tunnel_id] = tunnel
        # Note down the next hop, for back-tracking, when the tunnel is acknowledged, we will get that message from the
        # next peer in the route, and we'll record that as tunnel.prev_hop, that way we know which peer to send the
        # data to, either direction.
        tunnel.next_hop = peer

        # We should pass this on, even if we are the intended endpoint of the request, because if we didn't and one of
        # our peers were malicious, they could recognise the fact that we didn't send them the request, and conclude
        # that we were the tunnel endpoint.
        if ttl < 0:  # Don't send if we have already reached the TTL limit
            self.logger.debug("Tunnel request from %s:%i failed, TTL expired." % peer.address)
        else:
            for peer_ in self.paired_peers:
                if peer != peer_ and peer.connected and peer.ready:  # Don't send it backwards, that would be dumb
                    try:
                        peer_.send_tunnel_request(hops + 1, ttl - 1, tunnel, tunnel_data)
                    except Exception as error:
                        self.logger.error("Error while passing tunnel request to %s:%i." % peer_.address, exc_info=True)

        if not skip_owner_check:
            try:
                tunnel_data = self.__private_key.decrypt(
                    tunnel_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None,
                    )
                )

                # TODO: Tunneling protocol stuff here

            except ValueError:  # We aren't the tunnel endpoint
                ...  # owner = False

    def on_tunnel_data(self, hops: int, tunnel_id: int, tunnel_data: bytes, peer: Union["Peer", None]) -> None:
        """
        Called when a tunnel data is received.

        :param hops: The number of hops the request has made.
        :param tunnel_id: The ID of the tunnel.
        :param tunnel_data: The tunnel data.
        :param peer: The peer that sent the tunnel data, None means we are the owner.
        """

        if tunnel_id not in self.tunnels:  # We don't know about this tunnel, so we can't do anything with it
            return

        self.logger.debug("Received tunnel data from %s:%i hops=%i, len=%i." % (peer.address + (hops, len(tunnel_data))))

        # TODO: Should we verify this has been sent by the tunnel owner, or should we leave that up to the owners?

        tunnel = self.tunnels[tunnel_id]
        # We prolly shouldn't be getting these if we're not the participant, but better safe than sorry
        if tunnel.participant:
            # We're getting the message from the previous hop, which we now know about. Note however, that due to
            # latency, the previous hop might not be the one we sent the message to, so we need to check that. If this
            # is the case, we'll just add this message to the queue to send later.
            if tunnel.prev_hop is None and peer != tunnel.next_hop:
                tunnel.prev_hop = peer  # Yay, we've established the tunnel now!

            if not tunnel.established:  # Not established yet, so add this to the queue
                tunnel.queued_messages.append((hops, tunnel_data))

            elif not tunnel.owner:  # Forward it to the next hop
                # Even if the peer is None, this should sort itself out
                if peer == tunnel.prev_hop:  # Forwards direction
                    tunnel.next_hop.send_tunnel_data(hops + 1, tunnel_id, tunnel_data)
                else:  # Backwards direction
                    tunnel.prev_hop.send_tunnel_data(hops + 1, tunnel_id, tunnel_data)

            else:  # The message is for us
                ...  # TODO: Tunneling protocol stuff

    def on_tunnel_close(self, tunnel_id: int, random_data: bytes, signature: bytes, peer: Union["Peer", None],
                        skip_verify: bool = False) -> None:
        """
        Called when a tunnel close is received.

        :param tunnel_id: The ID of the tunnel.
        :param random_data: The random data.
        :param signature: The random data signed with the tunnel private key.
        :param peer: The peer that sent the tunnel close.
        :param skip_verify: Don't verify the signature.
        """

        if tunnel_id not in self.tunnels:  # We don't know about this tunnel, so we can't do anything with it
            return

        self.logger.debug("Received tunnel close from %s:%i." % peer.address)

        tunnel = self.tunnels[tunnel_id]
        if tunnel.participant:
            if not skip_verify:
                try:
                    tunnel.public_key.verify(
                        signature,
                        random_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA1()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256(),
                    )
                except InvalidSignature:  # Definitely something malicious going on
                    self.logger.warning("Tunnel close from %s:%i failed, signature invalid." % peer.address)
                    # TODO: Should we handle this in any way, like disconnecting the peer?
                    return

            if peer == tunnel.prev_hop:  # Forwards direction
                tunnel.next_hop.send_tunnel_close(tunnel_id, random_data, signature)
            else:  # Backwards direction
                tunnel.prev_hop.send_tunnel_close(tunnel_id, random_data, signature)

            self.logger.info("Tunnel %i closed." % tunnel_id)
            del self.tunnels[tunnel_id]  # Tunnel is closed, so we can remove it

    # ------------------------------ Run ------------------------------ #

    def _shutdown(self) -> None:
        self.logger.info("Shutting down local node...")
        self.running = False

        if self._inbound_listener is not None and self._inbound_listener.is_alive():
            self._inbound_listener.join()

        self.logger.debug("Disconnecting all peers...")
        for peer in self.paired_peers.copy() + self.unpaired_peers.copy():
            peer.disconnect("local node shutdown")

        self.logger.info("Local node shutdown.")

    def run(self) -> None:
        self.running = True

        # If we're the initial node, we should expect inbound connections, we'll pair later
        if not self.peer_infos and not config.INITIAL_NODE:
            self.logger.info("No peers found, starting discovery...")

            peers = PeerDiscoverer(self).discover()
            if not peers:
                self._shutdown()
                return

            # TODO: Generate a public key to use for tunneling
            # TODO: Request tunnel to peers, verify they are valid, and connect to them

        do_inbound = config.INBOUND_ENABLED and self._can_do_inbound()
        # TODO: Do this when we're actually connected to the network
        self._check_inid(self.node_list)  # Make sure our INID is valid

        if config.INITIAL_NODE:
            self.logger.info("We are acting as the initial node, if this is an error, please check your configuration.")

            if not do_inbound:
                self.logger.fatal("We are acting as the initial node, but inbound connections are disabled.")
                self._shutdown()
                return

            # We should have a signed node list with only us on it, if we don't, then something is wrong
            if (self.node_list is None or not self.node_list.verify_signature(self) or
                    not self.inid in self.node_list or
                    self.node_list[self.inid].public_key != self._public_key.public_bytes(  # We need all the valid info
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )):
                self.logger.fatal("Node list is invalid, cannot act as initial node.")
                self._shutdown()
                return

        if do_inbound:
            self._inbound_listener = InboundPeerListener(self)
            self._inbound_listener.start()

        try:
            while self.running:
                for tunnel_id, tunnel in list(self.tunnels.items()):  # TODO: Might need to synchronize this stuff
                    # If we aren't the tunnel owner nor are we a participant and the tunnel is expired, there's no point
                    # storing it anymore
                    if not tunnel.owner and not tunnel.participant and tunnel.expired:
                        self.logger.debug("Tunnel %i expired, removing cached." % tunnel_id)
                        del self.tunnels[tunnel_id]

                    if tunnel.established and tunnel.queued_messages:
                        self.logger.debug("Tunnel %i has queued messages, sending them." % tunnel_id)
                        for hops, tunnel_data in tunnel.queued_messages:  # TODO: Sending the queued messages
                            tunnel.next_hop.send_tunnel_data(hops, tunnel_id, tunnel_data)

                        tunnel.queued_messages.clear()

                time.sleep(0.1)
        except KeyboardInterrupt:
            ...

        self._shutdown()


from .info import NodeList, PeerInfo
from .data import DataProvider, FileDataProvider, DataGenerator
from .p2p import Peer
from .p2p.discovery import PeerDiscoverer
from .p2p.inbound import InboundPeerListener
from .p2p.outbound import OutboundPeer
from .tunnel import Tunnel
