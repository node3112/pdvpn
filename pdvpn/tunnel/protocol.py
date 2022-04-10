#!/usr/bin/env python3

import logging
import struct
from enum import Enum
from io import BytesIO
from typing import Tuple

from . import Tunnel

logger = logging.getLogger("pdvpn.tunnel.protocol")


class TunnelingProtocol:  # TODO: HMAC support
    """
    The tunneling protocol "packets".
    """

    # ------------------------------ Intent ------------------------------ #

    @staticmethod
    def read_intent(data: BytesIO, tunnel: Tunnel) -> "TunnelingProtocol.Intent":
        """
        Reads the packet intent from the data.

        :param data: The tunneling data.
        :param tunnel: The tunnel that this data came from, for logging purposes.
        :return: The intent.
        """

        intent = TunnelingProtocol.Intent(data.read(1)[0])
        logger.debug("TID %x -> %s" % (tunnel.tunnel_id, intent.name))
        return intent

    @staticmethod
    def send_intent(data: BytesIO, tunnel: Tunnel, intent: "TunnelingProtocol.Intent") -> None:
        """
        Sends the packet intent to the socket.

        :param data: The tunneling data to write to.
        :param tunnel: The tunnel that this data is being sent to, for logging purposes.
        :param intent: The intent.
        """

        logger.debug("TID %x <- %s" % (tunnel.tunnel_id, intent.name))
        data.write(bytes([intent.value]))

    # ------------------------------ Tunnel "maintenance" ------------------------------ #

    @staticmethod
    def read_tunnel_create(data: BytesIO) -> Tuple[int, int, bytes, bytes]:
        """
        Reads the tunnel_create packet from the data.

        :param data: The tunneling data.
        :return: The offset for the number of hops, the tunnel ID, public key, and private key.
        """

        hops_offset, tunnel_id, public_key_size, private_key_size = struct.unpack(">IIHH", data.read(12))
        public_key = data.read(public_key_size)
        private_key = data.read(private_key_size)

        return hops_offset, tunnel_id, public_key, private_key

    @staticmethod
    def send_tunnel_create(data: BytesIO, hops_offset: int, tunnel_id: int, public_key: bytes, private_key: bytes) -> None:
        """
        Writes the tunnel_create packet to the data.

        :param data: The tunneling data to write to.
        :param hops_offset: The random offset for the number of hops.
        :param tunnel_id: The tunnel ID.
        :param public_key: The tunnel's public key.
        :param private_key: The tunnel's private_key.
        """

        data.write(struct.pack(">IIHH", hops_offset, tunnel_id, len(public_key), len(private_key)))
        data.write(public_key)
        data.write(private_key)
        
    @staticmethod
    def read_tunnel_create_ack(data: BytesIO) -> int:
        """
        Reads the tunnel_create_ack packet from the data.
        
        :param data: The tunneling data.
        :return: The number of hops.
        """
        
        return int.from_bytes(data.read(4), "big", signed=False)
        
    @staticmethod
    def send_tunnel_create_ack(data: BytesIO, hops: int) -> None:
        """
        Writes the tunnel_create_ack packet to the data.
        
        :param data: The tunneling data to write to.
        :param hops: The number of hops.
        """
        
        data.write(hops.to_bytes(4, "big", signed=False))

    class Intent(Enum):
        """
        The message intent.
        """

        # Tunnel "maintenance"

        TUNNEL_CREATE = 0
        TUNNEL_CREATE_ACK = 1

        KEEP_ALIVE = 2  # Send these, so we can be sure it hasn't been tampered with
        KEEP_ALIVE_ACK = 3

        # Misc intents

        PAIR_REQ = 4
        PAIR_RES = 5

        PROXY_REQ = 6
        PROXY_RES = 7
