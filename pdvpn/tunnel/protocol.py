#!/usr/bin/env python3
from io import BytesIO


class TunnelingProtocol:
    """
    The tunneling protocol "packets".
    """

    @staticmethod
    def read_tunnel_create(data: bytes) -> None:  # TODO: These
        data = BytesIO(data)

    @staticmethod
    def send_tunnel_create() -> bytes:
        ...

    class Intent:
        """
        The packet intent.
        """

        # Special intents

        TUNNEL_CREATE = 0
        TUNNEL_CLOSE = 1

        KEEP_ALIVE = 2  # Send these so we can be sure it hasn't been tampered with

        # Normal intents

        PAIR_REQ = 3
        PAIR_RES = 4

        PROXY_REQ = 5
        PROXY_RES = 6
