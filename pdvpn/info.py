#!/usr/bin/env python3
import struct
import time
from io import BytesIO
from typing import List, Union, Tuple, Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from . import config

# TODO: UserList, ties UIDs to public keys


class NodeList:
    """
    A list of nodes that is handed out around the network. It is signed by the master key.
    """

    @property
    def nodes(self) -> List["NodeList.NodeInfo"]:
        """
        :return: A list of all nodes in this node list.
        """

        return list(self._nodes.values())

    @property
    def unverified(self) -> List["NodeList.UnverifiedInfo"]:
        """
        :return: A dictionary of unverified nodes.
        """

        return list(self._unverified.values())

    @property
    def valid(self) -> bool:
        """
        :return: If the node list is valid at this current time.
        """

        return self.valid_from <= time.time() <= self.valid_until

    def __init__(self, revision: int = 1, signature: bytes = b"", valid_from: int = 0,
                 valid_until: int = 1648971798) -> None:
        """
        :param revision: The current node list revision, should start at 1.
        :param signature: The signature of this node list, signed by the master key.
        :param valid_from: The unix timestamp (seconds) when the node list is valid from.
        :param valid_until: The unix timestamp (seconds) when the node list is valid until.
        """

        self.revision = revision

        self.signature = signature
        self.valid_from = valid_from
        self.valid_until = valid_until

        self._nodes: Dict[int, NodeList.NodeInfo] = {}
        self._unverified: Dict[int, NodeList.UnverifiedInfo] = {}
        self._public_keys: List[bytes] = []

    def __contains__(self, key: int) -> bool:
        return key in self._nodes or key in self._unverified

    def __delitem__(self, key: int) -> None:
        if key in self._nodes:
            del self._nodes[key]
        elif key in self._unverified:
            del self._unverified[key]
        else:
            raise KeyError(key)

    def __getitem__(self, key: int) -> Union["NodeList.NodeInfo", "NodeList.UnverifiedInfo"]:
        if key in self._nodes:
            return self._nodes[key]
        elif key in self._unverified:
            return self._unverified[key]

        raise KeyError(key)

    def __setitem__(self, key: int, value: Union["NodeList.NodeInfo", "NodeList.UnverifiedInfo"]) -> None:
        if isinstance(value, NodeList.NodeInfo):
            self._nodes[key] = value
        elif isinstance(value, NodeList.UnverifiedInfo):
            self._unverified[key] = value
        else:
            raise TypeError(value)

    def __len__(self) -> int:
        return len(self._nodes)  # TODO: + len(self._unverified)?

    # ------------------------------ Access ------------------------------ #

    def get_node(self, inid: int) -> "NodeList.NodeInfo":
        """
        :param inid: The INID of the node.
        :return: The node with the given INID.
        """

        return self._nodes[inid]

    def get_unverified(self, inid: int) -> "NodeList.UnverifiedInfo":
        """
        :param inid: The INID of the node.
        :return: The unverified node with the given INID.
        """

        return self._unverified[inid]

    # TODO: Adding nodes

    # ------------------------------ Access ------------------------------ #

    def serialize(self, signature: bool = False) -> bytes:
        """
        Serializes the node list.

        :param signature: Are we generating this for the signature?
        :return: The serialized node list.
        """

        data = BytesIO()
        data.write(struct.pack(">IqqI", self.revision, self.valid_from, self.valid_until, len(self._nodes)))

        for node_info in self._nodes.values():
            node_info.serialize(data)

        if not signature:
            data.write(struct.pack(">HH", len(self._unverified), len(self.signature)))

            for unverified_info in self._unverified.values():
                unverified_info.serialize(data)

            data.write(self.signature)

        return data.getvalue()

    def deserialize(self, data: bytes) -> None:
        """
        Populates this node list with the data from the given bytes.

        :param data: The serialized node list.
        """

        data = BytesIO(data)
        self.revision, self.valid_from, self.valid_until, nodes_count = struct.unpack(">IqqI", data.read(24))

        self.signature = b""

        self._nodes.clear()
        self._unverified.clear()

        for index in range(nodes_count):
            node_info = NodeList.NodeInfo.deserialize(data)
            self._nodes[node_info.inid] = node_info

        if data.tell() < len(data.getvalue()):  # More to read?
            unverified_count, signature_length = struct.unpack(">HH", data.read(4))

            for index in range(unverified_count):
                unverified_info = NodeList.UnverifiedInfo.deserialize(data)
                self._unverified[unverified_info.node_info.inid] = unverified_info

            self.signature = data.read(signature_length)

    # ------------------------------ Cryptography ------------------------------ #

    def hash(self) -> bytes:
        """
        Hashes the node list.

        :return: The hashed bytes.
        """

        hash_ = hashes.Hash(hashes.SHA256())
        hash_.update(self.serialize(signature=True))
        return hash_.finalize()

    def sign(self, master_private_key: RSAPrivateKey) -> bytes:
        """
        Signs the node list.

        :param master_private_key: The master private key.
        :return: The generated signature, it is also set to this node list's signature field.
        """

        self.signature = master_private_key.sign(
            self.serialize(signature=True),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return self.signature

    def verify_signature(self, master_public_key: RSAPublicKey) -> bool:
        """
        Verifies that the node list is actually signed by the master key.

        :param master_public_key: The public master key.
        :return: If it is signed or not.
        """

        try:
            master_public_key.verify(
                self.signature,
                self.serialize(signature=True),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False

        return True

    # ------------------------------ Element classes ------------------------------ #

    class NodeInfo:
        """
        Partial information about a node on the network.
        """

        @staticmethod
        def deserialize(data: BytesIO) -> "NodeList.NodeInfo":
            """
            Deserializes a node from the data.
            """

            inid, public_key_length, *geolocation = struct.unpack(">qHff", data.read(18))
            public_key = data.read(public_key_length)
            return NodeList.NodeInfo(inid, public_key, geolocation)

        def __init__(self, inid: int, public_key: bytes, geolocation: Tuple[float, float]) -> None:
            """
            :param inid: Node's internal network ID.
            :param public_key: Node's public key.
            :param geolocation: The rough geolocation of the node.
            """

            self.inid = inid
            self.public_key = public_key
            # IP hashes are insecure, as entrypoints can record the IP hash, and use that to find the peer INID when
            # they are connected to the network, de-anonymizing them.
            # self.ip_hash = ip_hash
            self.geolocation = geolocation

        def __repr__(self) -> str:
            return "NodeInfo(inid=%x)" % self.inid

        def __eq__(self, other: Any) -> bool:
            if isinstance(other, NodeList.NodeInfo):  # Geolocation is subject to change
                return other.inid == self.inid and other.public_key == self.public_key

            return False

        def serialize(self, data: BytesIO) -> None:
            """
            Serializes the node info.
            """

            data.write(struct.pack(">qHff", self.inid, len(self.public_key), *self.geolocation))
            data.write(self.public_key)
            
    class UnverifiedInfo:
        """
        Partial information about nodes on the network that are not yet verified by the master key.
        """

        @staticmethod
        def deserialize(data: BytesIO) -> "NodeList.UnverifiedInfo":
            """
            Deserializes a node from the data.
            """

            node_info = NodeList.NodeInfo.deserialize(data)
            signatures_count = int.from_bytes(data.read(2), "big", signed=False)
            # TODO: Signatures
            return NodeList.UnverifiedInfo(node_info)
        
        def __init__(self, node_info: "NodeList.NodeInfo", signatures: Union[List[bytes], None] = None) -> None:
            self.node_info = node_info
            self.signatures = []
            
            if signatures is not None:
                self.signatures.extend(signatures)
                
        def __repr__(self) -> str:
            return "UnverifiedInfo(node_info=%r, signatures_count=%i)" % (self.node_info, len(self.signatures))
            
        def __eq__(self, other: Any) -> bool:
            if isinstance(other, NodeList.UnverifiedInfo):
                return other.node_info == self.node_info and other.signatures == self.signatures
                
            return False

        def serialize(self, data: BytesIO) -> None:
            """
            Serializes the unverified info.
            """

            self.node_info.serialize(data)
            data.write(struct.pack(">H", len(self.signatures)))
            # TODO: How to store signatures?
            # for signature in self.signatures:
            #     data.write(signature)

        def is_trusted(self, node_list: "NodeList") -> bool:
            """
            Checks if the node is trusted.

            :param node_list: The node list.
            :return: If the node is trusted or not.
            """

            if len(self.signatures) < len(node_list.nodes) * config.Standard.Changeable.NODE_LIST_TRUST_THRESHOLD:
                return False

            return True


class PeerInfo:
    """
    Partial information about a peer.
    """

    @property
    def address(self) -> Tuple[str, int]:
        """
        :return: The address of this peer.
        """

        return self.host, self.port

    def __init__(self, host: str, port: int, inid: Union[int, None] = None, outbound: bool = True) -> None:
        """
        :param host: Hostname of the peer.
        :param port: Remote port of the peer.
        :param inid: Node's internal network ID, may be None.
        :param outbound: If we connect to the peer, rather than it connecting to us.
        """

        self.host = host
        self.port = port
        self.inid = inid
        self.outbound = outbound

    def __repr__(self) -> str:
        return "PeerInfo(inid=%s, host=%r, port=%i)" % (self.inid, self.host, self.port)
