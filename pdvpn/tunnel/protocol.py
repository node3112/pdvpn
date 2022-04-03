#!/usr/bin/env python3


class TunnelingProtocol:
    """
    The tunneling protocol "packets".
    """

    class Intent:
        """
        The packet intent.
        """

        TUNNEL_CREATE = 0
        TUNNEL_CLOSE = 1

        KEEP_ALIVE = 2  # Send these so we can be sure it hasn't been tampered with
