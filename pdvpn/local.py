#!/usr/bin/env python3

import logging
import time
from typing import Union, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from . import config


class Local:
    """
    Local node running on this computer.
    """

    INSTANCE: Union["Local", None] = None

    def __init__(self, data_provider: Union["DataProvider", None]) -> None:
        Local.INSTANCE = self

        self.logger = logging.getLogger("pdvpn.local")
        self.logger.info("Initializing local...")

        if data_provider is None:
            self.logger.warning("No data provider specified, using default.")
            data_provider = FileDataProvider(config.DATA_FILE)

        self.data_provider = DataGenerator(data_provider)

        self.inid = self.data_provider.get_inid()
        self.logger.info("Local node ID: %x" % self.inid)

        self._public_key: RSAPublicKey = serialization.load_pem_public_key(self.data_provider.get_public_key())
        self.__private_key: RSAPrivateKey = serialization.load_pem_private_key(self.data_provider.get_private_key(),
                                                                               password=None)

        self._master_key = serialization.load_pem_public_key(config.MASTER_KEY)

        self.node_list: Union[NodeList, None] = self.data_provider.get_nodes()
        if self.node_list is None:
            self.logger.debug("No valid node list.")
        else:
            self.logger.debug("Node list revision: %i." % self.node_list.revision)
            self.logger.debug("Node list hash: %r." % self.node_list.hash().hex())
            self.logger.debug("%i known node(s), %i unverified node(s)." % (len(self.node_list.nodes),
                                                                            len(self.node_list.unverified)))

        self.peer_handler = PeerHandler(self, self.data_provider.get_peers())
        self.broadcast_handler = BroadcastHandler(self)
        self.tunnel_handler = TunnelHandler(self)

        self._inbound_listener: Union[InboundPeerListener, None] = None
        self._public_key_cache: Dict[int, RSAPublicKey] = {}  # For caching node public keys
        self.running = False

        self.logger.info("Local node initialized.")

    def _can_do_inbound(self) -> bool:
        """
        Checks if the local node can accept inbound peers.
        """

        return True  # TODO: Figure this out, OS dependent really

    def _check_inid(self) -> None:
        """
        Checks that our INID is valid, and is not already taken. If it is, change it.
        """

        if self.node_list is None:  # We have no data, so we can't tell
            return

        public_key = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Perhaps we are already in the list, we need to verify this by checking the public key as well
        while self.inid is None or (self.inid in self.node_list and
                                    self.node_list.get_node(self.inid).public_key != public_key):
            # noinspection PyProtectedMember
            self.inid = DataGenerator._generated_inid()  # TODO: Maybe we can move this somewhere else?

        self.data_provider.set_inid(self.inid)
        
    # ------------------------------ Cryptography ------------------------------ #
    
    def encrypt(self, inid: int, data: bytes) -> bytes:
        """
        Encrypts the provided data with the node's public key.
        
        :param inid: The INID of the node to encrypt the data with.
        :parma data: The data to encrypt.
        :return: The encrypted data.
        """
        
        if inid in self._public_key_cache:
            public_key = self._public_key_cache[inid]
        else:
            public_key = serialization.load_der_public_key(self.node_list.get_node(inid).public_key)
            self._public_key_cache[inid] = public_key
        
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext
        
    def verify(self, inid: int, data: bytes, signature: bytes) -> bool:
        """
        Verifies that data signed by a node's public key is valid.
        
        :param inid: The INID of the node that signed the data.
        :param data: The signed data.
        :param signature: The signature of the data.
        :return: Whether the signed data is valid.
        """
        
        if inid in self._public_key_cache:
            public_key = self._public_key_cache[inid]
        else:
            public_key = serialization.load_der_public_key(self.node_list[inid].public_key)
            self._public_key_cache[inid] = public_key

        try:
            public_key.verify(
                data, signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts data with the local node's private key.
        
        :param data: The encrypted data.
        :return: The decrypted data.
        """
        
        plaintext = self.__private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext
        
    def sign(self, data: bytes) -> bytes:
        """
        Signs data with the local node's private key.
        
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

    # ------------------------------ Run ------------------------------ #

    def _shutdown(self) -> None:
        self.logger.info("Shutting down local node...")
        self.running = False

        if self._inbound_listener is not None and self._inbound_listener.is_alive():
            self._inbound_listener.join()

        self.logger.debug("Closing all tunnels...")
        self.tunnel_handler.close_all()
        self.logger.debug("All tunnels closed.")

        self.logger.debug("Disconnecting all peers...")
        self.peer_handler.disconnect_all("local node shutdown")
        self.logger.debug("All peers disconnected.")

        self.logger.info("Local node shutdown.")

    def run(self) -> None:
        # self.logger.info("Running local node.")
        self.running = True

        self.tunnel_handler.start()

        # If we're the initial node, we should expect inbound connections, we'll pair later
        if not self.peer_handler.paired and not config.INITIAL_NODE:
            self.logger.info("No peers found, starting discovery...")
            
            try:
                self.peer_handler.discover()
            except KeyboardInterrupt:
                ...
                
            if not self.peer_handler.paired:  # We won't shutdown in the actual case, but this is a POC
                self._shutdown()
                return

        do_inbound = config.INBOUND_ENABLED and self._can_do_inbound()
        # TODO: Do this when we're actually connected to the network
        self.peer_handler.update_node_list()  # Update our node list, if it's not up to date
        self._check_inid()  # Make sure our INID is valid

        if config.INITIAL_NODE:
            self.logger.info("We are acting as the initial node, if this is an error, please check your configuration.")

            if not do_inbound:
                self.logger.fatal("We are acting as the initial node, but inbound connections are disabled.")
                self._shutdown()
                return

            # We should have a signed node list with only us on it, if we don't, then something is wrong
            if (self.node_list is None or not self.node_list.verify_signature(self._master_key) or
                    not self.inid in self.node_list or
                    self.node_list.get_node(self.inid).public_key != self._public_key.public_bytes(  # We need all the valid info
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )):
                self.logger.fatal("Node list is invalid, cannot act as initial node.")
                self._shutdown()
                return

        if do_inbound:
            self._inbound_listener = InboundPeerListener(self)
            self._inbound_listener.start()

        try:
            while self.running:
                # self.tunnel_handler.on_update()
                time.sleep(0.1)
        except KeyboardInterrupt:
            ...

        self._shutdown()


from .broadcast.handler import BroadcastHandler
from .data import DataProvider, FileDataProvider, DataGenerator
from .info import NodeList
from .p2p.handler import PeerHandler
from .p2p.inbound import InboundPeerListener
from .tunnel.handler import TunnelHandler
