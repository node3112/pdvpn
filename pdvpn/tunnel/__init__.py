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


class Tunnel(threading.Thread):
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

        self._encryptor: Union[_AEADEncryptionContext, None] = None  # FIXME: Typing
        self._decryptor: Union[_AEADCipherContext, None] = None

        self.alive = False

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

    def run(self) -> None:
        try:
            while self.alive:
                try:
                    data = self._wait_tunnel_response(0.1)  # 0.1 seconds so if we get closed, it's pretty quick
                except TimeoutError:
                    ...

        except Exception as error:
            self.logger.debug("Tunnel %x closed." % self.tunnel_id, exc_info=True)
            self.close()

    def _wait_tunnel_response(self, timeout: float = 30) -> bytes:
        """
        Wait for a tunnel response.
        """

        if self._queued_responses:
            return self._queued_responses.popleft()

        if self._data is not None:
            raise Exception("Concurrent tunnel data requests.")

        self._data = threading.Event()
        self._data.wait(timeout)
        self._data = None

        if self._queued_responses:
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
        self.start()

        tunnel_data = BytesIO()
        TunnelingProtocol.send_intent(tunnel_data, self, TunnelingProtocol.Intent.TUNNEL_CREATE_ACK)
        TunnelingProtocol.send_tunnel_create_ack(tunnel_data, hops)
        # noinspection PyProtectedMember
        self.local.tunnel_handler._send_tunnel_data(self.tunnel_id, self._encryptor.update(tunnel_data.getvalue()), peer=None)

        self.logger.info("Tunnel %x created in %i hop(s)." % (self.tunnel_id, hops))

    def on_tunnel_data(self, data: bytes) -> None:
        with self._lock:
            self._queued_responses.append(self._decryptor.update(data))
            if self._data is not None:
                self._data.set()
            
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
                self.local.tunnel_handler._add_tunnel(self)  # Just in case this hasn't been done

                self.logger.debug("Opening tunnel with ID %x..." % self.tunnel_id)
                self.logger.debug("Tunnel %x endpoint is INID %x." % (self.tunnel_id, self.endpoint.inid))
                
                # Create a random offset for the number of hops. This is done so that the endpoint can know how many
                # hops were actually made, whereas nodes just passing the request along do not. This is done so that the
                # originator of the request cannot be identified accurately through the number of hops.
                hops_offset = random.randint(0, len(self.local.node_list))
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
                    data = BytesIO(self._wait_tunnel_response(timeout=timeout))
                    
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

                self.logger.info("Tunnel %x created in %i hop(s)." % (self.tunnel_id, hops))

                self.alive = True
                self.start()

        else:
            self.logger.warning("Tunnel %x open call received from non-owner." % self.tunnel_id)

    def close(self, dont_notify: bool = False) -> None:
        """
        Closes the tunnel.
        
        :param dont_notify: Don't notify peers about the tunnel closing. DO NOT USE.
        """

        if self.owner:
            if self.alive:
                random_data = os.urandom(config.TUNNEL_CLOSE_RANDOM_SIZE)
                signature = self.__private_key.sign(
                    random_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA1()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256(),
                )
                if not dont_notify:
                    self.local.tunnel_handler._send_tunnel_close(self.tunnel_id, random_data, signature)

            self.alive = False
            if self._data is not None:
                self._data.set()

            if self.is_alive() and threading.current_thread() != self:  # FIXME: Is this necessarily a good idea?
                self.join()
                
        self.local.tunnel_handler._remove_tunnel(self)
        self.logger.info("Tunnel %x closed." % self.tunnel_id)


from .protocol import TunnelingProtocol
from ..local import Local
