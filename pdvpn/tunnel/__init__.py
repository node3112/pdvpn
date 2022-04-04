#!/usr/bin/env python3

"""
Concepts:
 - Fragments of packet are routed through different parts of the network.
 - Fakes parts of packets can be sent.
"""

import logging
import os
import time
from collections import deque
from typing import Union, Any, Deque, Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .. import config
from ..info import NodeList
from ..p2p import Peer


class Tunnel:
    """
    A tunnel is set up between two endpoints on the network.
    """

    @property
    def owner(self) -> bool:
        """
        :return: Whether this node is the owner of the tunnel (i.e. start or end point).
        """

        return self.__private_key is not None

    @property
    def participant(self) -> bool:
        """
        :return: Whether this node is a participant in the tunnel.
        """

        return self.next_hop is not None or self.prev_hop is not None

    @property
    def established(self) -> bool:
        """
        :return: Whether the tunnel is established.
        """

        # If we're the owner, we'll only have one hop, as we're at the end of the tunnel
        return not self.owner and (self.next_hop is not None and self.prev_hop is not None)

    @property
    def expired(self) -> bool:
        """
        :return: Whether the tunnel has expired.
        """

        return time.time() - self._time_created > config.TUNNEL_EXPIRY

    def __init__(self, local: "Local", tunnel_id: int, public_key: Union[RSAPublicKey, bytes],
                 private_key: Union[RSAPrivateKey, bytes, None] = None) -> None:
        """
        :param local: The local node instance.
        :param tunnel_id: The ID of the tunnel.
        :param public_key: The public key of the tunnel.
        :param private_key: The private key of the tunnel.
        """

        self.logger = logging.getLogger("pdvpn.tunnel")

        self.local = local
        self.tunnel_id = tunnel_id

        if isinstance(public_key, RSAPublicKey):
            self.public_key = public_key
        else:
            self.public_key = serialization.load_der_public_key(public_key)

        if isinstance(private_key, RSAPrivateKey):
            self.__private_key = private_key
        elif isinstance(private_key, bytes):
            self.__private_key = serialization.load_der_private_key(private_key, password=None)
        else:
            self.__private_key: Union[RSAPrivateKey, None] = None

        self._time_created = time.time()

        # Collect queued messages until the tunnel is established
        self.queued_messages: Deque[Tuple[int, bytes]] = deque()

        self.next_hop: Union[Peer, None] = None
        self.prev_hop: Union[Peer, None] = None

        self.ready = not self.owner  # Obviously if we aren't creating it it'll be ready
        self.endpoint: Union[NodeList.NodeInfo, None] = None  # Only if we're the owner

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Tunnel):
            return other.tunnel_id == self.tunnel_id and other.public_key == self.public_key
        return False

    # ------------------------------ Higher level management ------------------------------ #

    def open(self) -> None:
        """
        Opens the tunnel.
        """

        if self.owner:
            if not self.ready:
                ...  # TODO: Tunneling protocol
                # TODO: What TTL?
                # self.local.on_tunnel_req(0, 65535, )

        else:
            self.logger.warning("Tunnel %i open call received from non-owner." % self.tunnel_id)

    def close(self) -> None:
        """
        Closes the tunnel.
        """

        if self.owner:
            if self.ready:
                random_data = os.urandom(config.TUNNEL_RANDOM_SIZE)
                signature = self.__private_key.sign(
                    random_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA1()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256(),
                )
                # We don't need to verify it, as we're know we signed it
                self.local.on_tunnel_close(self.tunnel_id, random_data, signature, None, skip_verify=True)
                self.ready = False

        else:
            self.logger.warning("Tunnel %i close call received from non-owner." % self.tunnel_id)


from ..local import Local
