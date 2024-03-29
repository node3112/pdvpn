#!/usr/bin/env python3

"""
Concepts:
 - Fragments of packet are routed through different parts of the network.
 - Fakes parts of packets can be sent.
"""

import logging
import os
import random
import threading
import time
from collections import deque
from io import BytesIO
from typing import Union, Any, Deque, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.base import _AEADEncryptionContext, _AEADCipherContext

from .. import config, encryption
from ..info import NodeList
from ..p2p import Peer


class Tunnel:
    """
    A tunnel is set up between two endpoints on the network.
    """
    
    @property
    def owner(self) -> bool:
        """
        :return: Whether this local node owns this tunnel.
        """

        return self.__private_key is not None

    @property
    def expired(self) -> bool:
        """
        :return: Whether the tunnel has expired.
        """

        return time.time() - self._time_created > config.Standard.Changeable.TUNNEL_EXPIRY

    @property
    def last_keep_alive(self) -> float:  # TODO: Use this in the tunnel handler to manage keep alives
        """
        :return: The time since the last keep alive in seconds.
        """

        return time.time() - self._last_keep_alive

    @property
    def awaiting_keep_alive(self) -> bool:
        """
        :return: Whether this tunnel is awaiting a keep alive response.
        """

        return self._awaiting_keep_alive != -1

    @property
    def latency(self) -> float:
        """
        :return: The latency of this tunnel, in seconds.
        """

        return self._latency

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
            self._public_key = public_key
        else:
            self._public_key = serialization.load_der_public_key(public_key)

        super().__init__()  # Bruh

        if isinstance(private_key, RSAPrivateKey):
            self.__private_key = private_key
        elif isinstance(private_key, bytes):
            self.__private_key = serialization.load_der_private_key(private_key, password=None)
        else:
            self.__private_key: Union[RSAPrivateKey, None] = None

        self._time_created = time.time()

        # Collect queued messages until the tunnel is established
        self.queued_messages: Deque[Tuple[Peer, bytes]] = deque()
        # Responses that have been sent to us but not yet processed by whatever wants to use them
        self._queued_responses: Deque[bytes] = deque()

        self.next_hop: Union[Peer, None] = None
        self.prev_hop: Union[Peer, None] = None

        # Endpoint stuff

        self.endpoint: Union[NodeList.NodeInfo, None] = None  # Only if we're the one that started the tunnel

        self._encryptor: Union[_AEADEncryptionContext, None] = None
        self._decryptor: Union[_AEADCipherContext, None] = None

        self.alive = False

        self._latency = 0
        self._last_keep_alive = time.time() - config.Standard.Changeable.TUNNEL_KEEP_ALIVE_INTERVAL
        self._awaiting_keep_alive = -1

        # Threading stuff

        self._lock = threading.RLock()
        self._data: Union[threading.Event, None] = None

    def __repr__(self) -> str:
        return "Tunnel(id=%x)" % self.tunnel_id

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Tunnel):
            return other.tunnel_id == self.tunnel_id and other._public_key == self._public_key
        return False

    def __hash__(self) -> int:
        return hash((self.tunnel_id, self._public_key))

    def _send(self, data: bytes) -> None:
        """
        Sends data down the tunnel.
        """

        # noinspection PyProtectedMember
        self.local.tunnel_handler._send_tunnel_data(self.tunnel_id, self._encryptor.update(data), peer=None)

    def _recv(self, timeout: float = 30) -> bytes:
        """
        Waits to receive data through the tunnel.
        """

        with self._lock:
            if self._queued_responses:
                return self._queued_responses.popleft()

        if self._data is not None:
            raise Exception("Concurrent tunnel data requests.")

        self._data = threading.Event()
        self._data.wait(timeout)
        self._data = None

        if self._queued_responses:
            with self._lock:
                return self._queued_responses.popleft()
        else:
            raise TimeoutError("Tunnel %x timed out." % self.tunnel_id)

    # ------------------------------ Events ------------------------------ #

    def on_tunnel_request(self, hops: int, shared_key: bytes, data: bytes) -> None:
        cipher = encryption.get_cipher_from_secrets(shared_key[:32], shared_key[32:])
        self._encryptor = cipher.encryptor()
        self._decryptor = cipher.decryptor()
        
        with self._lock:
            data = BytesIO(self._decryptor.update(data))

        intent = TunnelingProtocol.read_intent(data, self)
        if intent != TunnelingProtocol.Intent.TUNNEL_CREATE:
            self.logger.warning("Tunnel %x received unexpected intent %s." % (self.tunnel_id, intent.name))
            self.close()
            return

        hops_offset, tunnel_id, public_key_bytes, private_key_bytes = TunnelingProtocol.read_tunnel_create(data)
        hops -= hops_offset
        with self._lock:
            self._public_key = serialization.load_der_public_key(public_key_bytes)
            self.__private_key = serialization.load_der_private_key(private_key_bytes, password=None)

        if tunnel_id != self.tunnel_id:  # TODO: Need to check public key too
            self.logger.warning("Tunnel %x received invalid metadata (something malicious could be occurring)." % self.tunnel_id)
            self.close()
            return

        self.alive = True

        data = BytesIO()
        TunnelingProtocol.send_intent(data, self, TunnelingProtocol.Intent.TUNNEL_CREATE_ACK)
        TunnelingProtocol.send_tunnel_create_ack(data, hops)
        self._send(data.getvalue())

        self.logger.info("Tunnel %x created in %i hop(s)." % (self.tunnel_id, hops))

    def on_tunnel_data(self, data: bytes) -> None:
        with self._lock:
            data = BytesIO(self._decryptor.update(data))

            if self._data is not None:
                self._queued_responses.append(data.getvalue())
                self._data.set()
                return

        # We weren't waiting for data, so we'll process it now
        intent = TunnelingProtocol.read_intent(data, self)

        if intent == TunnelingProtocol.Intent.KEEP_ALIVE:  # It's not pretty, but it works
            data = BytesIO()
            TunnelingProtocol.send_intent(data, self, TunnelingProtocol.Intent.KEEP_ALIVE_ACK)
            with self._lock:
                self._send(data.getvalue())
            return

        elif intent == TunnelingProtocol.Intent.KEEP_ALIVE_ACK:
            if self._awaiting_keep_alive != -1:
                self._latency = (time.time() - self._awaiting_keep_alive) / 2
                self._awaiting_keep_alive = -1

                self.logger.debug("Tunnel %x latency is %ims." % (self.tunnel_id, self._latency * 1000))
            
    # ------------------------------ Cryptography ------------------------------ #
        
    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifies that data is signed by this tunnel's public key.
        
        :param data: The data that has been signed.
        :param signature: The signature to check against.
        :return: Whether the signed data is valid.
        """
        
        try:
            self._public_key.verify(
                signature, data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False
        
    def sign(self, data: bytes) -> bytes:
        """
        Signs data with this tunnel's private key.
        
        :param data: The data to sign.
        :return: The signed data.
        """
        
        signature = self.__private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature

    # ------------------------------ Interfacing ------------------------------ #

    def send_keep_alive(self) -> None:
        """
        Sends a keep alive message to the tunnel.
        """

        if self.alive and self._awaiting_keep_alive == -1:
            self._last_keep_alive = time.time()
            self._awaiting_keep_alive = time.time()
            data = BytesIO()
            TunnelingProtocol.send_intent(data, self, TunnelingProtocol.Intent.KEEP_ALIVE)
            with self._lock:
                self._send(data.getvalue())

    # ------------------------------ Higher level management ------------------------------ #

    def open(self, timeout: float = 30) -> None:
        """
        Opens the tunnel.

        :param timeout: How long to wait for the tunnel to be established.
        """

        if self.owner:
            if self.endpoint is None:
                raise Exception("Tunnel %x has no endpoint." % self.tunnel_id)

            if not self.alive:
                # noinspection PyProtectedMember
                self.local.tunnel_handler._add_tunnel(self)  # Just in case this hasn't been done

                self.logger.debug("Opening tunnel with ID %x..." % self.tunnel_id)
                self.logger.debug("Tunnel %x endpoint is INID %x." % (self.tunnel_id, self.endpoint.inid))
                
                # Create a random offset for the number of hops. This is done so that the endpoint can know how many
                # hops were actually made, whereas nodes just passing the request along do not. This is done so that the
                # originator of the request cannot be identified accurately through the number of hops.
                hops_offset = random.randint(0, len(self.local.node_list.nodes))
                public_key_bytes = self._public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                tunnel_data = BytesIO()
                TunnelingProtocol.send_intent(tunnel_data, self, TunnelingProtocol.Intent.TUNNEL_CREATE)
                TunnelingProtocol.send_tunnel_create(
                    tunnel_data,
                    hops_offset,
                    self.tunnel_id,
                    public_key_bytes,
                    self.__private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
                
                test_data = os.urandom(10)
                test_data_hash = hashes.Hash(hashes.SHA256())
                test_data_hash.update(test_data)

                self.logger.debug("Creating cipher...")
                cipher_key = os.urandom(32)
                init_vector = os.urandom(16)

                cipher = encryption.get_cipher_from_secrets(cipher_key, init_vector)
                self._encryptor = cipher.encryptor()
                self._decryptor = cipher.decryptor()

                start = time.time()
                # noinspection PyProtectedMember
                self.local.tunnel_handler._broadcast_tunnel_request(
                    hops_offset, self.tunnel_id,
                    public_key_bytes,
                    test_data_hash.finalize(),
                    self.local.encrypt(self.endpoint.inid, test_data),
                    self.local.encrypt(self.endpoint.inid, cipher_key + init_vector),
                    self._encryptor.update(tunnel_data.getvalue()),
                    peer=None,  # Forward to all known peers
                )

                try:
                    data = BytesIO(self._recv(timeout=timeout))
                    
                    intent = TunnelingProtocol.read_intent(data, self)
                    if intent != TunnelingProtocol.Intent.TUNNEL_CREATE_ACK:
                        self.logger.debug("Tunnel %x failed to open, expected TUNNEL_CREATE_ACK, got %s." % intent.name)
                        self.close()
                        return
                    hops = TunnelingProtocol.read_tunnel_create_ack(data)    
                    
                except Exception as error:
                    self.logger.debug("Tunnel %x failed to open." % self.tunnel_id, exc_info=True)
                    self.close()
                    return

                self.logger.info("Tunnel %x created in %i hop(s) with %ims rt." % (self.tunnel_id, hops,
                                                                                   (time.time() - start) * 1000))

                self.alive = True

        else:
            self.logger.warning("Tunnel %x open call received from non-owner." % self.tunnel_id)

    def close(self, dont_notify: bool = False) -> None:
        """
        Closes the tunnel.
        
        :param dont_notify: Don't notify peers about the tunnel closing. DO NOT USE.
        """

        if self.owner:
            if self.alive:
                random_data = os.urandom(config.Standard.Changeable.TUNNEL_CLOSE_RANDOM_SIZE)
                signature = self.__private_key.sign(
                    random_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA1()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256(),
                )
                if not dont_notify:
                    # noinspection PyProtectedMember
                    self.local.tunnel_handler._send_tunnel_close(self.tunnel_id, random_data, signature)

            self.alive = False
            if self._data is not None:
                self._data.set()

        # noinspection PyProtectedMember
        self.local.tunnel_handler._remove_tunnel(self)
        self.logger.info("Tunnel %x closed." % self.tunnel_id)


from .protocol import TunnelingProtocol
from ..local import Local
