#!/usr/bin/env python3

import logging
import socket
import threading
import time
from typing import Tuple

from . import Peer, P2PProtocol
from .. import config


class InboundPeerListener(threading.Thread):
    """
    Responsible for accepting connections from inbound peers.
    """

    def __init__(self, local: "Local") -> None:
        super().__init__()

        self.logger = logging.getLogger("pdvpn.p2p.inbound")

        self.local = local
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self) -> None:
        self.logger.debug("Starting inbound peer listener...")

        self.server.bind((config.INBOUND_HOSTNAME, config.INBOUND_PORT))
        self.server.listen(5)
        self.server.settimeout(1)

        self.logger.info("Inbound peer listener bound to %s:%d" % (config.INBOUND_HOSTNAME, config.INBOUND_PORT))

        while self.local.running:
            try:
                client, address = self.server.accept()
                address: Tuple[str, int]
                self.logger.debug("Accepted connection from %s:%d" % address)

            except socket.timeout:
                continue

            try:
                peer = InboundPeer(self.local, client, *address)
                peer.connect(outbound=False)  # Add to known peer list
                peer.start()

            except Exception as error:
                self.logger.debug("Failed to accept connection from %s:%d." % address, exc_info=True)

        self.server.close()

        self.logger.debug("Stopped inbound peer listener.")


class InboundPeer(Peer):

    def __init__(self, local: "Local", conn: socket.socket, hostname: str, port: int):
        super().__init__(local, conn, hostname, port)

        self.logger = logging.getLogger("pdvpn.p2p.inbound")

        self._last_keep_alive = time.time() - config.KEEP_ALIVE_INTERVAL
        self._awaiting_keep_alive = False

    def run(self) -> None:
        try:
            self._handshake(outbound=False)
        except Exception as error:
            self.logger.debug("Failed to complete handshake with %s:%d." % (self.hostname, self.port), exc_info=True)
            self.disconnect("failed handshake")
            return

        try:
            while self.connected:
                intent = self._receive_intent()
                self._handle_intent(intent)

                if intent == P2PProtocol.Intent.KEEP_ALIVE:
                    self._awaiting_keep_alive = False

                # Keepalive
                if time.time() - self._last_keep_alive > config.KEEP_ALIVE_INTERVAL:
                    if self._awaiting_keep_alive:
                        self.logger.warning("%s:%d did not respond to keepalive." % self.address)
                        self.disconnect("timeout")
                        break

                    # Too much info :p
                    # self.logger.debug("Sending keepalive to %s:%d" % self.peer.peer_info.address)
                    with self._lock:
                        P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.KEEP_ALIVE)
                    self._last_keep_alive = time.time()
                    self._awaiting_keep_alive = True

        except Exception as error:
            if self.connected:
                self.logger.debug("Failed to receive intent from %s:%d." % self.address, exc_info=True)
                self.disconnect(str(error))


from ..local import Local
