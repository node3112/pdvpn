#!/usr/bin/env python3
import logging
import os
import socket
import threading
import time
from typing import Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey

from .protocol import P2PProtocol
from .. import config, encryption
from ..info import NodeList


class Peer(threading.Thread):
    """
    An abstract representation of a peer.
    """

    @property
    def address(self) -> Tuple[str, int]:
        """
        :return: The address of the remote peer.
        """

        return self.hostname, self.port

    def __init__(self, local: "Local", conn: socket.socket, hostname: str, port: int) -> None:
        super().__init__()

        self.logger = logging.getLogger("pdvpn.p2p")

        self.local = local
        self.conn = conn
        self.hostname = hostname
        self.port = port

        self._lock = threading.RLock()

        self.connected = False
        self.ready = False  # Have we finished the handshake?

        # More specific stuff

        self._node_list_req: Union[threading.Event, None] = None
        self._node_list: Union[NodeList, None] = None  # The requested node list, use self.local.node_list for actual

    # ------------------------------ Hidden methods ------------------------------ #

    def _handshake(self, outbound=True) -> None:
        """
        Handshakes with the remote peer, in this class cos the code is basically the same.
        """

        if not self.ready:
            self.logger.info("Handshaking with %s:%i..." % self.address)

            if outbound:  # We're connecting to them
                self.logger.debug("Generating DHKE parameters...")
                parameters = dh.generate_parameters(generator=2, key_size=config.DHKE_KEY_SIZE)
                self.logger.debug("Generating a_private_key...")
                a_private_key = parameters.generate_private_key()
                self.logger.debug("Generating a_peer_public_key...")
                a_peer_public_key = a_private_key.public_key()

                P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.HELLO)
                P2PProtocol.send_hello(
                    self.conn,
                    a_peer_public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ),
                    parameters.parameter_numbers().g,
                    parameters.parameter_numbers().p,
                )

                intent = P2PProtocol.read_intent(self.conn, self.address)
                if intent != P2PProtocol.Intent.HELLO_ACK:
                    raise Exception("Handshake failed, %s received." % intent.name)

                self.logger.debug("Receiving b_peer_public_key...")
                b_peer_public_key_bytes, init_vector = P2PProtocol.read_hello_ack(self.conn)
                self.logger.debug("Generating shared secret...")
                # noinspection PyTypeChecker
                shared_secret = a_private_key.exchange(serialization.load_der_public_key(b_peer_public_key_bytes))

            else:  # They're connecting to us
                intent = P2PProtocol.read_intent(self.conn, self.address)
                if intent != P2PProtocol.Intent.HELLO:
                    raise Exception("Handshake failed, %s received." % intent.name)

                self.logger.debug("Receiving a_peer_public_key and parameters...")
                a_peer_public_key_bytes, param_g, param_p = P2PProtocol.read_hello(self.conn)
                parameters = dh.DHParameterNumbers(p=param_p, g=param_g).parameters()  # Oops, they're reversed :p
                self.logger.debug("Generating b_private_key...")
                b_private_key = parameters.generate_private_key()
                self.logger.debug("Generating b_peer_public_key...")
                b_peer_public_key = b_private_key.public_key()

                # noinspection PyTypeChecker
                shared_secret = b_private_key.exchange(serialization.load_der_public_key(a_peer_public_key_bytes))
                init_vector = os.urandom(16)

                P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.HELLO_ACK)
                P2PProtocol.send_hello_ack(
                    self.conn,
                    b_peer_public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ),
                    init_vector,
                )

            cipher = encryption.get_cipher_from_secrets(shared_secret, init_vector)
            self.conn = encryption.EncryptedSocketWrapper(self.conn, cipher.encryptor(), cipher.decryptor())

            # Check we can understand each other, if not, we've done something wrong
            if outbound:
                P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.FIN)
                P2PProtocol.send_fin(self.conn)

                intent = P2PProtocol.read_intent(self.conn, self.address)
                if intent != P2PProtocol.Intent.FIN_ACK:
                    raise Exception("Handshake failed, %s received." % intent.name)

            else:
                intent = P2PProtocol.read_intent(self.conn, self.address)
                if intent != P2PProtocol.Intent.FIN:
                    raise Exception("Handshake failed, %s receieved." % intent.name)
                P2PProtocol.read_fin(self.conn)
                P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.FIN_ACK)

            self.logger.debug("Secure connection established.")

            self.ready = True
            self.logger.info("Handshake with %s:%i complete." % self.address)

    def _receive_intent(self) -> Union[P2PProtocol.Intent, None]:
        """
        Receives an intent from the peer, if any at all.
        """

        try:
            with self._lock:
                self.conn.settimeout(0.1)  # Check if we have data to read.
                intent = P2PProtocol.read_intent(self.conn, self.address)
                self.conn.settimeout(30)

                return intent

        except socket.timeout:
            return None

    def _handle_intent(self, intent: P2PProtocol.Intent) -> None:
        """
        Handles intent, used by subclasses so I don't have to write duplicate pieces of code.
        """

        if intent == P2PProtocol.Intent.DISCONNECT:
            self.logger.info("Disconnect reason: %r" % P2PProtocol.read_disconnect(self.conn))
            self.disconnect("intent")

        # Node list

        elif intent == P2PProtocol.Intent.NLIST_REQ:  # TODO: Will people request us to send our node list?
            self.logger.debug("%s:%i requested node list." % self.address)

            with self._lock:
                P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.NLIST_RES)
                if self.local.node_list is None:  # I.e. we aren't on the network yet
                    P2PProtocol.send_nlist_res(self.conn, b"")
                else:
                    P2PProtocol.send_nlist_res(self.conn, self.local.node_list.serialize())

        elif intent == P2PProtocol.Intent.NLIST_RES:
            with self._lock:
                if self._node_list_req is not None and not self._node_list_req.is_set():
                    nlist_data = P2PProtocol.read_nlist_res(self.conn)

                    if nlist_data:
                        self.node_list = NodeList()
                        self.node_list.deserialize(nlist_data)
                    else:
                        self.node_list = None  # They didn't have a valid node list apparently

                    self._node_list_req.set()

        # Pairing

        elif intent == P2PProtocol.Intent.PAIR_REQ:  # TODO: Pairing
            ...

        elif intent == P2PProtocol.Intent.PAIR_RES:
            ...

        # Broadcast

        elif intent == P2PProtocol.Intent.DATA:
            ...

        # Tunneling

        elif intent == P2PProtocol.Intent.TUNNEL_REQ:
            ...

        elif intent == P2PProtocol.Intent.TUNNEL_DATA:
            ...

        elif intent == P2PProtocol.Intent.TUNNEL_CLOSE:
            ...

    # ------------------------------ Connection management ------------------------------ #

    def connect(self, outbound: bool = True) -> None:
        """
        Connect to the remote node.

        :param outbound: Whether to connect to the remote node as a client or server.
        """

        if not self.connected:
            if outbound:
                self.logger.debug("Connecting to %s:%i..." % self.address)

                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect(self.address)

                self.logger.debug("Connected.")

            self.connected = True
            self.ready = False

            if not self in self.local.unpaired_peers:
                self.local.unpaired_peers.append(self)

    def disconnect(self, reason: str = "unknown") -> None:
        """
        Disconnects this peer.

        :param reason: A reason for the disconnection.
        """

        if self in self.local.paired_peers:
            self.local.paired_peers.remove(self)
        if self in self.local.unpaired_peers:
            self.local.unpaired_peers.remove(self)

        if self.connected:
            if self.conn is not None:
                try:
                    P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.DISCONNECT)
                    P2PProtocol.send_disconnect(self.conn, reason)
                    self.conn.close()

                except Exception:
                    ...

            if self._node_list_req is not None:  # Disconnected, so update immediately
                self._node_list_req.set()

            self.conn = None

            self.connected = False
            self.ready = False

            self.logger.info("Disconnected from %s:%i: %r." % (self.address + (reason,)))

    # ------------------------------ Interfacing with the peer ------------------------------ #

    def request_node_list(self, timeout: int = 30) -> Union[NodeList, None]:
        """
        Requests the node list from the peer.

        :return: The node list, None if the peer doesn't have one.
        :exception: An exception if the request failed.
        """

        if self.ready:
            if self._node_list_req is not None:
                raise Exception("Node list request currently pending.")

            with self._lock:
                P2PProtocol.send_intent(self.conn, self.address, P2PProtocol.Intent.NLIST_REQ)

                self._node_list_req = threading.Event()

            self._node_list_req.wait(timeout)

            with self._lock:
                if not self._node_list_req.is_set():
                    raise TimeoutError("Node list request timed out.")

                self._node_list_req = None

            if not self.connected:
                raise ConnectionError("Peer disconnected.")

            # noinspection PyTypeChecker
            return self.node_list

        else:
            raise ConnectionError("Peer is not ready.")


from ..local import Local
