#!/usr/bin/env python3

import json
import logging
import os
import pickle
import random
from abc import ABC, abstractmethod
from typing import Any, Dict, IO, List, Tuple, Union

from cryptography.hazmat.primitives import serialization

from . import config, encryption
from .info import NodeList, PeerInfo


class DataProvider(ABC):
    """
    Provides data to the node.
    """

    @abstractmethod
    def get_inid(self) -> int:
        """
        :return: This node's internal network ID.
        """

        ...

    @abstractmethod
    def set_inid(self, inid: int) -> None:
        """
        Set this node's internal network ID.

        :param inid: The new internal network ID.
        """

        ...

    @abstractmethod
    def get_public_key(self) -> bytes:
        """
        :return: This node's public key.
        """

        ...

    @abstractmethod
    def set_public_key(self, public_key: bytes) -> None:
        """
        Set this node's public key.

        :param public_key: The new public key.
        """

        ...

    @abstractmethod
    def get_private_key(self) -> bytes:
        """
        :return: This node's private key.
        """

        ...

    @abstractmethod
    def set_private_key(self, private_key: bytes) -> None:
        """
        Set this node's private key.

        :param private_key: The new private key.
        """

        ...

    @abstractmethod
    def get_rid_public_key(self) -> bytes:
        """
        :return: The random identification public key.
        """

        ...

    @abstractmethod
    def set_rid_public_key(self, rid_public_key: bytes) -> None:
        """
        Sets this node's random identification public key.

        :param rid_public_key: The new random identification public key.
        """

        ...

    @abstractmethod
    def get_rid_private_key(self) -> bytes:
        """
        :return: The random identification private key.
        """

        ...

    @abstractmethod
    def set_rid_private_key(self, rid_private_key: bytes) -> None:
        """
        Sets this node's random identification private key.

        :param rid_private_key: The new random identification private key.
        """

        ...

    @abstractmethod
    def get_config(self) -> Dict[str, Any]:
        """
        :return: The current configuration.
        """

    @abstractmethod
    def set_config(self, config: Dict[str, Any]) -> None:
        """
        Sets the current configuration.

        :param config: The new configuration.
        """

        ...

    @abstractmethod
    def get_nodes(self) -> NodeList:
        """
        :return: A map of all known nodes on the network.
        """

        ...

    @abstractmethod
    def set_nodes(self, nodes: NodeList) -> None:
        """
        Set the list of nodes on the network.

        :param nodes: The new list of nodes.
        """

        ...

    @abstractmethod
    def get_peers(self) -> List[PeerInfo]:
        """
        :return: A list of information about peers this node was connected to.
        """

        ...

    @abstractmethod
    def set_peers(self, peers: List[PeerInfo]) -> None:
        """
        Set the list of peers this node is connected to.

        :param peers: The new list of peers.
        """

        ...

    @abstractmethod
    def reset_all(self) -> None:
        """
        Set the list of peers this node is connected to.

        :param peers: The new list of peers.
        """

        ...


class FileDataProvider(DataProvider):
    """
    Provides data to the node from a file.
    """

    def __init__(self, cfgdir: str = "vpn") -> None:
        """
        :param cfgdir: The path to the file to read data from.
        """

        self.cfgdir = cfgdir

    def _open(self, file_name: str, mode: str) -> IO[bytes]:
        if not os.path.exists(self.cfgdir) or not os.path.isdir(self.cfgdir):
            os.makedirs(self.cfgdir)

        file_path = os.path.join(self.cfgdir, file_name)
        if not os.path.exists(file_path):
            os.mknod(file_path)

        # noinspection PyTypeChecker
        return open(file_path, mode)

    def get_inid(self) -> Union[int, None]:
        with self._open("inid.bin", "rb") as fileobj:
            file_bytes = fileobj.read(8)
            if len(file_bytes) != 8:
                return None

            return int.from_bytes(file_bytes, "big", signed=True)

    def set_inid(self, inid: int) -> None:
        with self._open("inid.bin", "wb") as fileobj:
            fileobj.write(inid.to_bytes(8, "big", signed=True))

    def get_public_key(self) -> Union[bytes, None]:
        with self._open("public_key.pem", "rb") as fileobj:
            file_bytes = fileobj.read()
            if not file_bytes:
                return None

            return file_bytes

    def set_public_key(self, public_key: bytes) -> None:
        with self._open("public_key.pem", "wb") as fileobj:
            fileobj.write(public_key)

    def get_private_key(self) -> Union[bytes, None]:
        with self._open("private_key.pem", "rb") as fileobj:
            file_bytes = fileobj.read()
            if not file_bytes:
                return None

            return file_bytes

    def set_private_key(self, private_key: bytes) -> None:
        with self._open("private_key.pem", "wb") as fileobj:
            fileobj.write(private_key)

    def get_rid_public_key(self) -> Union[bytes, None]:
        with self._open("rid_public_key.pem", "rb") as fileobj:
            file_bytes = fileobj.read()
            if not file_bytes:
                return None

            return file_bytes

    def set_rid_public_key(self, rid_public_key: bytes) -> None:
        with self._open("rid_public_key.pem", "wb") as fileobj:
            fileobj.write(rid_public_key)

    def get_rid_private_key(self) -> Union[bytes, None]:
        with self._open("rid_private_key.pem", "rb") as fileobj:
            file_bytes = fileobj.read()
            if not file_bytes:
                return None

            return file_bytes

    def set_rid_private_key(self, rid_private_key: bytes) -> None:
        with self._open("rid_private_key.pem", "wb") as fileobj:
            fileobj.write(rid_private_key)

    def get_nodes(self) -> Union[NodeList, None]:
        with self._open("nodes.bin", "rb") as fileobj:
            file_bytes = fileobj.read()
            if not file_bytes:
                return None

            node_list = NodeList()
            node_list.deserialize(file_bytes)
            return node_list

    def set_nodes(self, nodes: NodeList) -> None:
        with self._open("nodes.bin", "wb") as fileobj:
            fileobj.write(nodes.serialize())

    def get_peers(self) -> List[PeerInfo]:
        with self._open("peers.pckl", "rb") as fileobj:
            try:
                return pickle.load(fileobj)
            except EOFError:
                return []

    def set_peers(self, peers: List[PeerInfo]) -> None:
        with self._open("peers.pckl", "wb") as fileobj:
            pickle.dump(peers, fileobj)

    def get_config(self) -> Dict[str, Any]:
        with self._open("config.json", "r") as fileobj:
            return json.load(fileobj)

    def set_config(self, config: Dict[str, Any]) -> None:
        with self._open("config.json", "w") as fileobj:
            json.dump(config, fileobj)

    def reset_all(self):
        for root, dirs, files in os.walk(self.cfgdir):
            for file in files:
                self.local.logger.debug("Attempting to remove file: '%s'" % os.path.join(root, file))  # TODO: temporary for testing first.
                #os.remove(os.path.join(root, file))


class DataGenerator(DataProvider):

    @staticmethod
    def _generated_inid() -> int:
        """
        Generate a random internal network ID.
        """

        # The first 100 IDs are reserved, we will not be accepted as valid if we use one of them
        return random.randint(100, 2 ** 63 - 1)

    @staticmethod
    def _generate_keypair(key_size: int = config.Standard.Changeable.RSA_KEY_SIZE) -> Tuple[bytes, bytes]:
        """
        Generate a new keypair.
        """

        logger = logging.getLogger("pdvpn.data")
        logger.info("Generating new keypair with size %i bytes..." % key_size)

        # Key size of 2048 is standard for regular nodes, but can be increased for user nodes
        public_key, private_key = encryption.generate_rsa_keypair(key_size=key_size)
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        logging.debug("Public key:")
        logging.debug(public_key.decode("utf-8"))
        logging.debug("Private key (do not share this):")
        logging.debug(private_key.decode("utf-8"))

        logger.info("Keypair generated.")

        return public_key, private_key

    def __init__(self, wrapped: DataProvider) -> None:
        self.wrapped = wrapped

    def get_inid(self) -> int:
        if self.wrapped.get_inid() is None:
            self.wrapped.set_inid(self._generated_inid())

        return self.wrapped.get_inid()

    def set_inid(self, inid: int) -> None:
        self.wrapped.set_inid(inid)

    def get_public_key(self) -> bytes:
        if self.wrapped.get_public_key() is None:
            public_key, private_key = self._generate_keypair()

            self.wrapped.set_public_key(public_key)
            self.wrapped.set_private_key(private_key)

        return self.wrapped.get_public_key()

    def set_public_key(self, public_key: bytes) -> None:
        self.wrapped.set_public_key(public_key)

    def get_private_key(self) -> bytes:
        if self.wrapped.get_private_key() is None:
            public_key, private_key = self._generate_keypair()

            self.wrapped.set_public_key(public_key)
            self.wrapped.set_private_key(private_key)

        return self.wrapped.get_private_key()

    def set_private_key(self, private_key: bytes) -> None:
        self.wrapped.set_private_key(private_key)

    def get_rid_public_key(self) -> bytes:
        if self.wrapped.get_rid_public_key() is None:
            public_key, private_key = self._generate_keypair()

            self.wrapped.set_rid_public_key(public_key)
            self.wrapped.set_rid_private_key(private_key)

        return self.wrapped.get_rid_public_key()

    def set_rid_public_key(self, public_key: bytes) -> None:
        self.wrapped.set_rid_public_key(public_key)

    def get_rid_private_key(self) -> bytes:
        if self.wrapped.get_rid_private_key() is None:
            public_key, private_key = self._generate_keypair(key_size=config.Standard.Changeable.RID_RSA_KEY_SIZE)

            self.wrapped.set_rid_public_key(public_key)
            self.wrapped.set_rid_private_key(private_key)

        return self.wrapped.get_rid_private_key()

    def set_rid_private_key(self, private_key: bytes) -> None:
        self.wrapped.set_rid_private_key(private_key)

    def get_nodes(self) -> Union[NodeList, None]:
        return self.wrapped.get_nodes()

    def set_nodes(self, nodes: NodeList) -> None:
        self.wrapped.set_nodes(nodes)

    def get_peers(self) -> List[PeerInfo]:
        return self.wrapped.get_peers()

    def set_peers(self, peers: List[PeerInfo]) -> None:
        self.wrapped.set_peers(peers)

    def get_config(self) -> Dict[str, Any]:
        return self.wrapped.get_config()

    def set_config(self, new_config: Dict[str, Any]) -> None:
        self.wrapped.set_config(new_config)

    def reset_all(self):
        self.wrapped.reset_all()
