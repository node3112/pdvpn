#!/usr/bin/env python3

import logging
import socket
import time
from typing import Union

from . import Peer, P2PProtocol
from ..info import NodeList


class OutboundPeer(Peer):
    """
    An outbound peer connection, we are connected to them.
    """

    def __init__(self, local: "Local", conn: socket.socket, hostname: str, port: int):
        super().__init__(local, conn, hostname, port)

        self.logger = logging.getLogger("pdvpn.p2p.outbound")

    def run(self) -> None:
        try:
            self._handshake(outbound=True)
        except Exception as error:
            self.logger.error("Failed to complete handshake with %s:%d." % (self.hostname, self.port), exc_info=True)
            self.disconnect("failed handshake")
            return


        try:
            while self.connected:
                intent = self._receive_intent()
                self._handle_intent(intent)

                if intent == P2PProtocol.Intent.KEEP_ALIVE:
                    P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.KEEP_ALIVE)

        except Exception as error:
            if self.connected:  # Might have been disconnected in another thread
                self.logger.error("Failed to receive intent from %s:%d." % self.address, exc_info=True)
                self.disconnect(str(error))


from ..local import Local
