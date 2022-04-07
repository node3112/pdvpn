#!/usr/bin/env python3

import logging
import threading
import time
from typing import Dict, Union

from cryptography.hazmat.primitives import hashes

from . import Tunnel
from .. import config, encryption
from ..info import NodeList
from ..p2p import Peer


class TunnelHandler:
    """
    Responsible for managing tunnels.
    """
    
    def __init__(self, local: "Local") -> None:
        self.logger = logging.getLogger("pdvpn.tunnel.handler")
        
        self.local = local
        
        self._tunnels: Dict[int, Tunnel] = {}
        self._lock = threading.RLock()
        
    # ------------------------------ Internal ------------------------------ #
    
    def _broadcast_tunnel_request(self, hops: int, tunnel_id: int, public_key: bytes, test_data_hash: bytes,
                                  test_data_encrypted: bytes, shared_key: bytes, data: bytes,
                                  peer: Union[Peer, None] = None) -> None:
        """
        Broadcasts a tunnel request to all available peers.
        """

        for peer_ in self.local.peer_handler.all_peers:
            if peer != peer_ and peer_.connected and peer_.ready:  # Don't send it backwards, that would be dumb
                try:
                    peer_.send_tunnel_request(hops + 1, tunnel_id, public_key, test_data_hash, 
                                              test_data_encrypted, shared_key, data)
                except Exception as error:
                    self.logger.debug("Error while passing tunnel request to %s:%i." % peer_.address, exc_info=True)
                    
    def _send_tunnel_data(self, tunnel_id: int, data: bytes, peer: Union[Peer, None] = None) -> None:
        """
        Sends tunnel data through a tunnel.
        """
        
        with self._lock:
            tunnel = self._tunnels[tunnel_id]
        
        # If either one directional peer is None, this means we are the owner, it is not an error
        if peer == tunnel.prev_hop and tunnel.next_hop is not None:  # Forwards direction
            try:
                tunnel.next_hop.send_tunnel_data(tunnel_id, data)
            except Exception as error:  # TODO: Handle tunnel interruptions
                self.logger.debug("Error while passing tunnel data to %s:%i." % tunnel.next_hop.address, exc_info=True)
        elif tunnel.prev_hop is not None:  # Backwards direction
            try:
                tunnel.prev_hop.send_tunnel_data(tunnel_id, data)
            except Exception as error:
                self.logger.debug("Error while passing tunnel data to %s:%i" % tunnel.prev_hop.address, exc_info=True)
        else:  
            # Obviously we haven't fully connected the tunnel yet, this could be due to latency so we'll add this to the
            # message queue
            tunnel.queued_messages.append((peer, data))
            
    def _send_tunnel_close(self, tunnel_id: int, random_data: bytes, signature: bytes, peer: Union[Peer, None] = None) -> None:
        """
        Sends the tunnel close through a tunnel.
        """
        
        with self._lock:
            tunnel = self._tunnels[tunnel_id]
            
        # TODO: Probably don't need to send it in both directions as nodes in the middle can't sign it?
        if peer == tunnel.prev_hop and tunnel.next_hop is not None:  # Forwards direction
            try:
                tunnel.next_hop.send_tunnel_close(tunnel_id, random_data, signature)
            except Exception as error:
                self.logger.debug("Error while passing tunnel close to %s:%i." % tunnel.next_hop.address, exc_info=True)
        elif tunnel.prev_hop is not None:  # Backwards direction
            try:
                tunnel.prev_hop.send_tunnel_close(tunnel_id, random_data, signature)
            except Exception as error:
                self.logger.debug("Error while passing tunnel close to %s:%i" % tunnel.prev_hop.address, exc_info=True)
        
    def _add_tunnel(self, tunnel: Tunnel) -> None:
        """
        Adds a tunnel to the known tunnels.
        """
        
        with self._lock:
            if not tunnel.tunnel_id in self._tunnels:
                self._tunnels[tunnel.tunnel_id] = tunnel

    def _remove_tunnel(self, tunnel: Tunnel) -> None:
        """
        Removes a tunnel from the known tunnels.
        """
        
        with self._lock:
            if tunnel.tunnel_id in self._tunnels:
                del self._tunnels[tunnel.tunnel_id]
        
    # ------------------------------ Events ------------------------------ #
    
    def on_update(self) -> None:
        """
        Updates handler tasks.
        """
        
        with self._lock:
            for tunnel_id, tunnel in list(self._tunnels.items()):
                # If we aren't the tunnel owner nor are we a participant and the tunnel is expired, there's no point
                # storing it anymore
                if not tunnel.owner and tunnel.next_hop is None and tunnel.prev_hop is None and tunnel.expired:
                    self.logger.debug("Tunnel %x expired, removing cached." % tunnel_id)
                    del self._tunnels[tunnel_id]  # No need to "close" it as it was never "open", to us at least

                established = tunnel.next_hop is not None and tunnel.prev_hop is not None
                if tunnel.owner and (tunnel.next_hop is None or tunnel.prev_hop is None):
                    established = True  # Owners only have one hop
                if established and tunnel.queued_messages:
                    self.logger.debug("Tunnel %x has queued messages, sending them." % tunnel_id)
                    for peer, data in tunnel.queued_messages:
                        self._send_tunnel_data(tunnel.tunnel_id, data, peer)
    
                    tunnel.queued_messages.clear()
    
    def on_tunnel_request(self, hops: int, tunnel_id: int, public_key: bytes, test_data_hash: bytes, 
                          test_data_encrypted: bytes, shared_key: bytes, data: bytes, peer: Peer) -> None:
        """
        Called when a tunnel request is received.

        :param hops: The number of hops the request has made.
        :param tunnel_id: The ID of the tunnel being created.
        :param public_key: A unique public key for the tunnel.
        :param test_data_hash: The hash of the testing data, for checking who the request is for.
        :param test_data_encrypted: Test data that has been encrypted with a recipient's public key.
        :param shared_key: A shared AES-256 key that has been encrypted with the recipient's public key.
        :param data: Tunneling data.
        :param peer: The peer that sent the tunnel request.
        """

        with self._lock:  # We'll probably get this multiple times from different threads
            if tunnel_id in self._tunnels:  # We have already been told about this tunnel
                return
            tunnel = Tunnel(self.local, tunnel_id, public_key)
            self._add_tunnel(tunnel)
            
        self.logger.debug("Tunnel request from %s:%i (%i? hop(s), length %i)." % (peer.address + (hops, len(data),)))
            
        # Note down the previous hop, for back-tracking, when the tunnel is acknowledged, we will get that message from the
        # next peer in the route, and we'll record that as tunnel.next_hop, that way we know which peer to send the
        # data to, in either direction.
        if peer is not None:
            tunnel.prev_hop = peer

        # We should pass this on, even if we are the intended endpoint of the request, because if we didn't and one of
        # our peers were malicious, they could recognise the fact that we didn't send them the request, and conclude
        # that we were the tunnel endpoint.
        self._broadcast_tunnel_request(hops + 1, tunnel_id, public_key, test_data_hash, test_data_encrypted, shared_key, 
                                       data, peer)

        try:
            test_data = self.local.decrypt(test_data_encrypted)
            
            digest = hashes.Hash(hashes.SHA256())
            digest.update(test_data)
            if test_data_hash == digest.finalize():  # Ok, this message was definitely intended for us
                tunnel.on_tunnel_request(hops, self.local.decrypt(shared_key), data)

        except ValueError as error:  # We aren't the tunnel endpoint
            raise error

    def on_tunnel_data(self, tunnel_id: int, data: bytes, peer: Peer) -> None:
        """
        Called when a tunnel data is received.

        :param tunnel_id: The ID of the tunnel.
        :param data: The tunnel data.
        :param peer: The peer that sent the tunnel data.
        """

        with self._lock:
            if not tunnel_id in self._tunnels:  # We don't know about this tunnel, so we can't do anything with it
                return
            tunnel = self._tunnels[tunnel_id]

        self.logger.debug("Tunnel data from %s:%i (length %i)." % (peer.address + (len(data),)))

        # TODO: Should we verify this has been sent by the tunnel owner, or should we leave that up to the owners?

        # We prolly shouldn't be getting these if we're not the participant, but better safe than sorry. Note the
        # special case if we are the owner. On the initial request, we will not know our next hop, so we need to
        # account for that.
        if tunnel.owner or tunnel.next_hop is not None or tunnel.prev_hop is not None:
            if not tunnel.owner:  # Forward the message if it isn't for us
                if tunnel.next_hop is None and tunnel.prev_hop != peer:  # TODO: Only do this if it's signed
                    tunnel.next_hop = peer
                self._send_tunnel_data(tunnel_id, data, peer)

            else:  # The message is for us
                if tunnel.next_hop is None:
                    tunnel.next_hop = peer
                tunnel.on_tunnel_data(data)

    def on_tunnel_close(self, tunnel_id: int, random_data: bytes, signature: bytes, peer: Union[Peer, None],
                        skip_verify: bool = False) -> None:
        """
        Called when a tunnel close is received.

        :param tunnel_id: The ID of the tunnel.
        :param random_data: The random data.
        :param signature: The random data signed with the tunnel private key.
        :param peer: The peer that sent the tunnel close.
        :param skip_verify: Don't verify the signature.
        """

        with self._lock:
            # We don't know about this tunnel, so we can't do anything with it
            if not tunnel_id in self._tunnels:
                return
            tunnel = self._tunnels[tunnel_id]

        self.logger.debug("Received tunnel close from %s:%i." % peer.address)

        if tunnel.next_hop is not None or tunnel.prev_hop is not None:
            # Definitely something malicious going on if this fails
            if len(random_data) != config.TUNNEL_CLOSE_RANDOM_SIZE or not tunnel.verify(random_data, signature):
                self.logger.warning("Tunnel close from %s:%i failed, signature invalid." % peer.address)
                # TODO: Should we handle this in any way, like disconnecting the peer?
                return

            self._send_tunnel_close(tunnel_id, random_data, signature, peer)
            
            tunnel.close(dont_notify=True)
        
    # ------------------------------ Interfacing ------------------------------ #
    
    def create_tunnel(self, inid: int, ignore_untrusted: bool = False) -> "Tunnel":
        """
        Creates a new tunneled connection to the node given by its INID. This does not open the tunnel.

        :param inid: The node's INID.
        :param ignore_untrusted: Don't check if the node is trusted.
        :return: The tunnel that was created.
        :exception: Thrown if creating the tunnel fails.
        """

        if not inid in self.local.node_list:
            raise LookupError("Node with INID %x not found in node list." % inid)

        tunnel_id = (self.local.inid * inid) % int(time.time())  # TODO: Better randomness
        public_key, private_key = encryption.generate_rsa_keypair(key_size=config.TUNNEL_RSA_KEY_SIZE)
        tunnel = Tunnel(self.local, tunnel_id, public_key, private_key)
        tunnel.endpoint = self.local.node_list[inid]

        if isinstance(tunnel.endpoint, NodeList.UnverifiedInfo):
            if tunnel.endpoint.is_trusted(self.local.node_list) or ignore_untrusted:
                tunnel.endpoint = tunnel.endpoint.node_info
            else:
                raise PermissionError("Node with INID %x is untrusted." % inid)
        
        self._add_tunnel(tunnel)
        return tunnel
        
    def close_all(self) -> None:
        """
        Closes all active tunnels.
        """
        
        with self._lock:
            self.logger.debug("Closing %i tunnel(s)..." % len(self._tunnels))
            for tunnel_id, tunnel in list(self._tunnels.items()):
                tunnel.close()


from ..local import Local

