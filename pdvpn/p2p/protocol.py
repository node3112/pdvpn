#!/usr/bin/env python3

import bz2
import logging
import os
import random
import socket
import struct
from enum import Enum
from typing import Tuple, Union, Dict

from pdvpn.encryption import EncryptedSocketWrapper

logger = logging.getLogger("pdvpn.p2p.protocol")


class P2PProtocol:
    """
    The P2P "packet" protocol.
    """

    # ------------------------------ Util ------------------------------ #

    @staticmethod
    def _decode_int(data: bytes) -> int:
        """
        Decodes an integer from the given data.
        """

        value = 0
        for index, value_ in enumerate(data):
            value += value_ * (256**index)
        return value

    @staticmethod
    def _encode_int(value: int) -> bytes:
        """
        Encodes an integer into a byte array.
        """

        data = []
        while value > 0:
            data.append(value % 256)
            value //= 256
        return bytes(data)

    @staticmethod
    def _read_all(conn: Union[socket.socket, EncryptedSocketWrapper], length: int) -> bytes:
        """
        Reads all bytes from the socket.
        """

        data = b""
        while len(data) < length:
            new_data = conn.recv(length - len(data))
            if not new_data:
                raise ConnectionError("Connection closed.")
            data += new_data
        return data

    # ------------------------------ Intent ------------------------------ #

    @staticmethod
    def read_intent(conn: Union[socket.socket, EncryptedSocketWrapper],
                    address: Tuple[str, int]) -> "P2PProtocol.Intent":
        """
        Reads the packet intent (the information the packet will contain).

        :param conn: The connection.
        :param address: The remote address, for logging purposes.
        :return: The intent.
        """

        intent = P2PProtocol.Intent(conn.recv(1)[0])

        logger.debug("%s:%i -> %s" % (address + (intent.name,)))
        return intent

    @staticmethod
    def send_intent(conn: Union[socket.socket, EncryptedSocketWrapper], address: Tuple[str, int],
                    intent: "P2PProtocol.Intent") -> None:
        """
        Sends the packet intent.

        :param conn: The connection.
        :param address: The remote address, for logging purposes.
        :param intent: The intent.
        """

        logger.debug("%s:%i <- %s" % (address + (intent.name,)))
        conn.send(bytes([intent.value]))

    # ------------------------------ Handshake ------------------------------ #

    @classmethod
    def read_hello(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[bytes, int, int]:
        """
        Reads the initial hello packet. This acts to start the DHKE.

        :param conn: The connection.
        :return: a_peer_public_key, param_g, param_p.
        """

        a_peer_public_key_size, param_g_size, param_p_size = struct.unpack(">HBB", conn.recv(4))
        a_peer_public_key = cls._read_all(conn, a_peer_public_key_size)
        param_g = cls._read_all(conn, param_g_size)
        param_p = cls._read_all(conn, param_p_size)

        return a_peer_public_key, cls._decode_int(param_g), cls._decode_int(param_p)

    @classmethod
    def send_hello(cls, conn: Union[socket.socket, EncryptedSocketWrapper], a_peer_public_key: bytes,
                   param_g: int, param_p: int) -> None:
        """
        Sends the initial hello packet.

        :param conn: The connection.
        :param a_peer_public_key: The peer's public key.
        :param param_g: The group parameter.
        :param param_p: The prime parameter.
        """

        param_g_data = cls._encode_int(param_g)
        param_p_data = cls._encode_int(param_p)
        conn.send(struct.pack(">HBB", len(a_peer_public_key), len(param_g_data), len(param_p_data)))
        conn.sendall(a_peer_public_key)
        conn.sendall(param_g_data)
        conn.sendall(param_p_data)

    @classmethod
    def read_hello_ack(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[bytes, bytes]:
        """
        Reads the hello_ack packet, this completes the DHKE.

        :param conn: The connection.
        :return: b_peer_public_key and the init vector.
        """

        b_peer_public_key_size = int.from_bytes(conn.recv(2), "big", signed=False)
        b_peer_public_key = cls._read_all(conn, b_peer_public_key_size)
        init_vector = conn.recv(16)

        return b_peer_public_key, init_vector

    @classmethod
    def send_hello_ack(cls, conn: Union[socket.socket, EncryptedSocketWrapper],
                       b_peer_public_key: bytes, init_vector: bytes) -> None:
        """
        Sends the hello_ack packet.

        :param conn: The connection.
        :param b_peer_public_key: The peer's public key.
        :param init_vector: The init vector.
        """

        conn.send(len(b_peer_public_key).to_bytes(2, "big", signed=False))
        conn.sendall(b_peer_public_key)
        conn.send(init_vector)

    @classmethod
    def read_fin(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> None:
        """
        Reads the fin packet, this verifies that a secure connection has been created.

        :param conn: The connection.
        """

        num_bytes = conn.recv(1)[0]  # Should be a random number, if the encryption did not work, this will fail
        cls._read_all(conn, num_bytes)

    @staticmethod
    def send_fin(conn: Union[socket.socket, EncryptedSocketWrapper]) -> None:
        """
        Sends the fin packet.

        :param conn: The connection.
        """

        num_bytes = random.randint(0, 255)
        conn.send(bytes([num_bytes]))
        conn.sendall(os.urandom(num_bytes))

    # ------------------------------ Basic needs ------------------------------ #

    @staticmethod
    def read_disconnect(conn: Union[socket.socket, EncryptedSocketWrapper]) -> str:
        """
        Reads the disconnect packet, this is used by either party to indicate a disconnect.

        :param conn: The connection.
        :return: The disconnect reason.
        """

        reason_size = conn.recv(1)[0]
        reason = conn.recv(reason_size).decode()

        return reason

    @staticmethod
    def send_disconnect(conn: Union[socket.socket, EncryptedSocketWrapper], reason: str) -> None:
        """
        Sends the disconnect packet.

        :param conn: The connection.
        :param reason: The disconnect reason, <= 255 bytes encoded utf-8.
        """

        reason_data = reason.encode("utf-8")
        if len(reason_data) > 255:  # FIXME: Maybe don't throw?
            raise ValueError("The reason is too long.")
        conn.send(bytes([len(reason_data)]))
        conn.send(reason_data)

    # ------------------------------ Node list sync ------------------------------ #

    @classmethod
    def read_nlist_rev(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, bytes]:
        """
        Reads the node list revision.

        :param conn: The connection.
        :return: The nodel list revisions.
        """

        revision = int.from_bytes(conn.recv(4), "big", signed=False)
        if revision:  # 0 indicates no revision (i.e. no node list)
            hash_ = cls._read_all(conn, 32)
        else:
            hash_ = b""
        return revision, hash_

    @classmethod
    def send_nlist_rev(cls, conn: Union[socket.socket, EncryptedSocketWrapper], revision: int,
                       hash_: bytes = b"") -> None:
        """
        Sends the node list revision.

        :param conn: The connection.
        :param revision: The node list revision.
        :param hash_: The node list hash.
        """

        conn.send(revision.to_bytes(4, "big", signed=False))
        if revision:
            conn.send(hash_)

    @classmethod
    def read_nlist_res(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> bytes:
        """
        Reads the node list response packet.

        :param conn: The connection.
        :return: The node list bytes.
        """

        # TODO: Would be nice to have some indication of progress
        nlist_size_size = conn.recv(1)[0]
        nlist_size = cls._decode_int(conn.recv(nlist_size_size))  # Could be pretty large
        node_list_data = cls._read_all(conn, nlist_size)

        return bz2.decompress(node_list_data)  # FIXME: Is bzip2 too slow?

    @classmethod
    def send_nlist_res(cls, conn: Union[socket.socket, EncryptedSocketWrapper], node_list_data: bytes) -> None:
        """
        Sends the node list response packet.

        :param conn: The connection.
        :param node_list_data: The node list bytes.
        """

        node_list_data = bz2.compress(node_list_data)
        nlist_size = cls._encode_int(len(node_list_data))
        conn.send(bytes([len(nlist_size)]))
        conn.send(nlist_size)
        conn.sendall(node_list_data)

    # ------------------------------ Pairing ------------------------------ #

    # TODO: Pairing

    # ------------------------------ Broadcast ------------------------------ #

    # TODO: Broadcast

    # ------------------------------ Tunneling ------------------------------ #

    @classmethod
    def read_tunnel_req(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, int, int, bytes, bytes,
                                                                                          bytes, bytes, bytes]:
        """
        Broadcasts that a tunnel request has been made.

        :param conn: The connection.
        :return: The number of hops, tunnel ID, public key, hashed test data, test data encrypted with the node's
                 public key, the shared tunnel key and tunnel metadata encrypted with the shared tunnel key.
        """

        hops, tunnel_id, public_key_size, tunnel_key_size, data_size = struct.unpack(">IqHHH", conn.recv(18))

        public_key = cls._read_all(conn, public_key_size)
        test_data_hash = conn.recv(32)
        test_data_encrypted = cls._read_all(conn, tunnel_key_size)
        shared_key = cls._read_all(conn, tunnel_key_size)
        data = cls._read_all(conn, data_size)

        # noinspection PyTypeChecker
        return hops, tunnel_id, public_key, test_data_hash, test_data_encrypted, shared_key, data

    @staticmethod
    def send_tunnel_req(conn: Union[socket.socket, EncryptedSocketWrapper], hops: int, tunnel_id: int,
                        public_key: bytes, test_data_hash: bytes, test_data_encrypted: bytes, shared_key: bytes,
                        data: bytes) -> None:
        """
        Sends the tunnel request packet.

        :param conn: The connection.
        :param hops: The number of hops that have been made.
        :param tunnel_id: The tunnel ID.
        :param public_key: The public key.
        :param test_data_hash: The hash of the test data.
        :param test_data_encrypted: The test data encrypted with the node's public key.
        :param shared_key: The shared tunnel key.
        :param data: The tunnel metadata encrypted with the shared tunnel key.
        """
        
        # TODO: Honestly, might be better to let it overflow since it'll kick malicious nodes
        if hops >= 2**32:
            hops = 0

        conn.send(struct.pack(">IqHHH", hops, tunnel_id, len(public_key), len(test_data_encrypted), len(data)))
        conn.sendall(public_key)
        conn.send(test_data_hash)
        conn.sendall(test_data_encrypted)
        conn.sendall(shared_key)
        conn.sendall(data)

    @classmethod
    def read_tunnel_data(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, bytes]:
        """
        Reads the tunnel data packet, this is data being sent through a tunnel.

        :param conn: The connection.
        :return: The tunnel ID and tunnel data (encrypted for the endpoint).
        """

        tunnel_id, data_size = struct.unpack(">qH", conn.recv(10))
        data = cls._read_all(conn, data_size)

        return tunnel_id, data

    @staticmethod
    def send_tunnel_data(conn: Union[socket.socket, EncryptedSocketWrapper], tunnel_id: int, data: bytes) -> None:
        """
        Sends the tunnel data packet.

        :param conn: The connection.
        :param tunnel_id: The tunnel ID.
        :param data: The tunnel data.
        """

        conn.send(struct.pack(">qH", tunnel_id, len(data)))
        conn.sendall(data)

    @classmethod
    def read_tunnel_close(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, bytes, bytes]:
        """
        Reads the close tunnel packet.

        :param conn: The connection.
        :return: The tunnel ID, random data and the signature of the random data.
        """

        tunnel_id, random_data_size, signature_size = struct.unpack(">qHH", conn.recv(12))
        random_data = cls._read_all(conn, random_data_size)
        signature = cls._read_all(conn, signature_size)

        return tunnel_id, random_data, signature

    @staticmethod
    def send_tunnel_close(conn: Union[socket.socket, EncryptedSocketWrapper], tunnel_id: int, random_data: bytes,
                          signature: bytes) -> None:
        """
        Sends the close tunnel packet.

        :param conn: The connection.
        :param tunnel_id: The tunnel ID.
        :param random_data: The random data.
        :param signature: The signature of the random data.
        """

        conn.send(struct.pack(">qHH", tunnel_id, len(random_data), len(signature)))
        conn.sendall(random_data)
        conn.sendall(signature)

    class Intent(Enum):
        """
        Packet intent.
        """

        # Initial handshake
        HELLO = 0
        HELLO_ACK = 1
        FIN = 2
        FIN_ACK = 3

        # Basic needs
        DISCONNECT = 4
        KEEP_ALIVE = 5

        # Syncing node list
        NLIST_REV_REQ = 6
        NLIST_REV_RES = 7
        NLIST_REQ = 8
        NLIST_RES = 9

        # Pairing with the peer
        PAIR_REQ = 10
        PAIR_RES = 11

        # Broadcast data
        DATA = 12

        # Tunneling data
        TUNNEL_REQ = 13
        TUNNEL_DATA = 14
        TUNNEL_CLOSE = 15
