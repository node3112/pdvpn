#!/usr/bin/env python3

"""
Concepts:
 - Fragments of packet are routed through different parts of the network.
 - Fakes parts of packets can be sent.
"""

from typing import Union, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class Tunnel:
    """
    A tunnel is set up between two endpoints on the network.
    """

    def __init__(self, tunnel_id: int, tunnel_public_key: bytes, tunnel_private_key: Union[bytes, None] = None) -> None:
        """
        :param tunnel_id: The ID of the tunnel.
        :param tunnel_public_key: The public key of the tunnel.
        :param tunnel_private_key: The private key of the tunnel, provided if this node is the one that created the
                                   tunnel, or is the endpoint of the tunnel.
        """

        self.tunnel_id = tunnel_id
        self._tunnel_public_key = serialization.load_der_public_key(tunnel_public_key)
        self._tunnel_private_key: Union[RSAPrivateKey, None] = None
        if tunnel_private_key is not None:
            self._tunnel_private_key = serialization.load_der_private_key(tunnel_private_key, password=None)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Tunnel):
            return other.tunnel_id == self.tunnel_id and other._tunnel_public_key == self._tunnel_public_key
        return False
