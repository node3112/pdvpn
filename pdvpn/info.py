#!/usr/bin/env python3

import struct
import time
from io import BytesIO
from typing import Union, Tuple, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class NodeList(dict):
    """
    A list of nodes that is handed out around the network. It is signed by the master key.
    """

    @property
    def valid(self) -> bool:
        """
        :return: If the node list is valid at this current time.
        """

        return self.valid_from <= time.time() <= self.valid_until

    def __init__(self, signature: bytes = b"", valid_from: int = 0, valid_until: int = 1648971798) -> None:
        """
        :param signature: The signature of this node list, signed by the master key.
        :param valid_from: The unix timestamp (seconds) when the node list is valid from.
        :param valid_until: The unix timestamp (seconds) when the node list is valid until.
        """

        super().__init__()

        self.signature = signature
        self.valid_from = valid_from
        self.valid_until = valid_until

    def serialize(self, skip_signature: bool = False) -> bytes:
        """
        Serializes the node list.

        :param skip_signature: Don't include the signature in the serialized data.
        :return: The serialized node list.
        """

        serialized = BytesIO()
        serialized.write(struct.pack(">qqI", self.valid_from, self.valid_until, len(self)))

        for node_info in self.values():
            node_info: NodeList.NodeInfo
            serialized.write(struct.pack(">qH", node_info.inid, len(node_info.public_key)))
            serialized.write(node_info.public_key)
            serialized.write(struct.pack(">ff", *node_info.geolocation))

        if not skip_signature:
            serialized.write(len(self.signature).to_bytes(2, "big", signed=False))
            serialized.write(self.signature)

        return serialized.getvalue()

    def deserialize(self, data: bytes) -> None:
        """
        Populates this node list with the data from the given bytes.

        :param data: The serialized node list.
        """

        data = BytesIO(data)
        self.valid_from, self.valid_until, count = struct.unpack(">qqI", data.read(20))

        self.clear()
        for index in range(count):
            inid, public_key_length = struct.unpack(">qH", data.read(10))
            public_key = data.read(public_key_length)
            # ip_hash = data.read(32)  # SHA256, hopefully
            # noinspection PyTypeChecker
            geolocation: Tuple[float, float] = struct.unpack(">ff", data.read(8))

            self[inid] = NodeList.NodeInfo(inid, public_key, geolocation)

        self.signature = b""
        if data.tell() < len(data.getvalue()):  # More to read?
            signature_length = int.from_bytes(data.read(2), "big", signed=False)
            self.signature = data.read(signature_length)

    def sign(self, master_private_key: RSAPrivateKey) -> bytes:
        """
        Signs the node list.

        :param master_private_key: The master private key.
        :return: The generated signature, it is also set to this node list's signature field.
        """

        self.signature = master_private_key.sign(
            self.serialize(skip_signature=True),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return self.signature

    def verify_signature(self, local: "Local") -> bool:
        """
        Verifies that the node list is actually signed by the master key.

        :param local: The local node.
        :return: If it is signed or not.
        """

        try:
            # noinspection PyProtectedMember
            local._master_key.verify(
                self.signature,
                self.serialize(skip_signature=True),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False

        return True

    class NodeInfo:
        """
        Partial information about a node on the network.
        """

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
            return "NodeInfo(inid=%i)" % self.inid

        def __eq__(self, other: Any) -> bool:
            if isinstance(other, NodeList.NodeInfo):  # Geolocation is subject to change
                return other.inid == self.inid and other.public_key == self.public_key

            return False


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


from .local import Local
