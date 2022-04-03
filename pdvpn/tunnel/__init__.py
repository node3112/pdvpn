#!/usr/bin/env python3

"""
Concepts:
 - Fragments of packet are routed through different parts of the network.
 - Fakes parts of packets can be sent.
"""

import time
from collections import deque
from typing import Union, Any, Deque, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .. import config
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

        return time.time() - self._time_created > config.TUNNEL_TIMEOUT

    def __init__(self, tunnel_id: int, public_key: bytes, private_key: Union[bytes, None] = None) -> None:
        """
        :param tunnel_id: The ID of the tunnel.
        :param public_key: The public key of the tunnel.
        :param private_key: The private key of the tunnel, provided if this node is the one that created the tunnel,
                            or is the endpoint of the tunnel.
        """

        self.tunnel_id = tunnel_id
        self.public_key = serialization.load_der_public_key(public_key)
        self.__private_key: Union[RSAPrivateKey, None] = None
        if private_key is not None:
            self.__private_key = serialization.load_der_private_key(private_key, password=None)

        self._time_created = time.time()

        # Collect queued messages until the tunnel is established
        self.queued_messages: Deque[Tuple[int, bytes]] = deque()

        self.next_hop: Union[Peer, None] = None
        self.prev_hop: Union[Peer, None] = None

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Tunnel):
            return other.tunnel_id == self.tunnel_id and other.public_key == self.public_key
        return False
