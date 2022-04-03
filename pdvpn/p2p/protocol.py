#!/usr/bin/env python3
import bz2
import logging
import os
import random
import socket
import struct
from enum import Enum
from typing import Tuple, Union

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
        Reads the packet intent from the socket.

        :param conn: The connection.
        :param address: The remote address, for logging purposes.
        :return: The intent.
        """

        intent = P2PProtocol.Intent(conn.recv(1)[0])

        logger.debug("%s:%i <- %s" % (address + (intent.name,)))
        return intent

    @staticmethod
    def send_intent(conn: Union[socket.socket, EncryptedSocketWrapper], address: Tuple[str, int],
                    intent: "P2PProtocol.Intent") -> None:
        """
        Sends the packet intent to the socket.

        :param conn: The connection.
        :param address: The remote address, for logging purposes.
        :param intent: The intent.
        """

        logger.debug("%s:%i -> %s" % (address + (intent.name,)))
        conn.send(bytes([intent.value]))

    # ------------------------------ Handshake ------------------------------ #

    @classmethod
    def read_hello(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[bytes, int, int]:
        """
        Reads the packet hello from the socket.

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
        Sends the packet hello to the socket.

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
        Reads the packet hello_ack from the socket.

        :param conn: The connection.
        :return: b_peer_public_key and the init vector.
        """

        b_peer_public_key_size_size = conn.recv(1)[0]
        b_peer_public_key_size = cls._decode_int(conn.recv(b_peer_public_key_size_size))
        b_peer_public_key = cls._read_all(conn, b_peer_public_key_size)
        init_vector = conn.recv(16)

        return b_peer_public_key, init_vector

    @classmethod
    def send_hello_ack(cls, conn: Union[socket.socket, EncryptedSocketWrapper],
                       b_peer_public_key: bytes, init_vector: bytes) -> None:
        """
        Sends the packet hello_ack to the socket.

        :param conn: The connection.
        :param b_peer_public_key: The peer's public key.
        :param init_vector: The init vector.
        """

        b_peer_public_key_size = cls._encode_int(len(b_peer_public_key))
        conn.send(bytes([len(b_peer_public_key_size)]))
        conn.send(b_peer_public_key_size)
        conn.sendall(b_peer_public_key)
        conn.send(init_vector)

    @classmethod
    def read_fin(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> None:
        """
        Reads the packet fin from the socket.

        :param conn: The connection.
        """

        to_read = conn.recv(1)[0]  # Should be a random number, if the encryption did not work, this will fail
        cls._read_all(conn, to_read)

    @staticmethod
    def send_fin(conn: Union[socket.socket, EncryptedSocketWrapper]) -> None:
        """
        Sends the packet fin to the socket.

        :param conn: The connection.
        """

        num_bytes = random.randint(0, 255)
        conn.send(bytes([num_bytes]))
        conn.sendall(os.urandom(num_bytes))

    # ------------------------------ Basic needs ------------------------------ #

    @staticmethod
    def read_disconnect(conn: Union[socket.socket, EncryptedSocketWrapper]) -> str:
        """
        Reads the packet disconnect from the socket.

        :param conn: The connection.
        :return: The disconnect reason.
        """

        reason_size = conn.recv(1)[0]
        reason = conn.recv(reason_size).decode()

        return reason

    @staticmethod
    def send_disconnect(conn: Union[socket.socket, EncryptedSocketWrapper], reason: str) -> None:
        """
        Sends the packet disconnect to the socket.

        :param conn: The connection.
        :param reason: The disconnect reason, <= 255 bytes encoded utf-8.
        """

        reason_data = reason.encode("utf-8")
        if len(reason_data) > 255:
            raise ValueError("The reason is too long.")
        conn.send(bytes([len(reason_data)]))
        conn.send(reason_data)

    # ------------------------------ Data sync ------------------------------ #

    @classmethod
    def read_nlist_res(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> bytes:
        """
        Reads the packet nlist_res from the socket.

        :param conn: The connection.
        :return: The node list bytes.
        """

        nlist_size_size = conn.recv(1)[0]
        nlist_size = cls._decode_int(conn.recv(nlist_size_size))  # Could be pretty large
        node_list_data = cls._read_all(conn, nlist_size)

        return bz2.decompress(node_list_data)  # FIXME: Is bzip2 too slow?

    @classmethod
    def send_nlist_res(cls, conn: Union[socket.socket, EncryptedSocketWrapper], node_list_data: bytes) -> None:
        """
        Sends the packet nlist_res to the socket.

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
    def read_tunnel_req(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, int, int, bytes, bytes]:
        """
        Reads the packet tunnel_req from the socket.

        :param conn: The connection.
        :return: The number of hops, TTL, tunnel ID, public key and tunnel request data (encrypted for the endpoint).
        """

        hops, ttl, tunnel_id, tunnel_public_key_size, tunnel_request_data_size = struct.unpack(">HHqHH", conn.recv(10))
        tunnel_public_key = cls._read_all(conn, tunnel_public_key_size)
        tunnel_request_data = cls._read_all(conn, tunnel_request_data_size)

        return hops, ttl, tunnel_id, tunnel_public_key, tunnel_request_data

    @staticmethod
    def send_tunnel_req(conn: Union[socket.socket, EncryptedSocketWrapper], hops: int, ttl: int,
                        tunnel_id: int, tunnel_public_key: bytes, tunnel_request_data: bytes) -> None:
        """
        Sends the packet tunnel_req to the socket.

        :param conn: The connection.
        :param hops: The number of hops.
        :param ttl: The time to live.
        :param tunnel_id: The tunnel ID.
        :param tunnel_public_key: The tunnel public key.
        :param tunnel_request_data: The tunnel request data (encrypted for the endpoint).
        """

        conn.send(struct.pack(">HHqHH", hops, ttl, tunnel_id, len(tunnel_public_key), len(tunnel_request_data)))
        conn.sendall(tunnel_public_key)
        conn.sendall(tunnel_request_data)

    @classmethod
    def read_tunnel_data(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, int, bytes]:
        """
        Reads the packet tunnel_data from the socket.

        :param conn: The connection.
        :return: The number of hops, TTL, tunnel ID and tunnel data (encrypted for the endpoint).
        """

        hops, tunnel_id, tunnel_data_size = struct.unpack(">HqH", conn.recv(12))
        tunnel_data = cls._read_all(conn, tunnel_data_size)

        return hops, tunnel_id, tunnel_data

    @staticmethod
    def send_tunnel_data(conn: Union[socket.socket, EncryptedSocketWrapper], hops: int, tunnel_id: int,
                         tunnel_data: bytes) -> None:
        """
        Sends the packet tunnel_data to the socket.

        :param conn: The connection.
        :param hops: The number of hops.
        :param tunnel_id: The tunnel ID.
        :param tunnel_data: The tunnel data.
        """

        conn.send(struct.pack(">HqH", hops, tunnel_id, len(tunnel_data)))
        conn.sendall(tunnel_data)

    @classmethod
    def read_tunnel_close(cls, conn: Union[socket.socket, EncryptedSocketWrapper]) -> Tuple[int, bytes, bytes]:
        """
        Reads the packet tunnel_close from the socket.

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
        Sends the packet tunnel_close to the socket.

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

        # Syncing data
        NLIST_REQ = 6
        NLIST_RES = 7

        # Pairing with the peer
        PAIR_REQ = 8
        PAIR_RES = 9

        # Broadcast data
        DATA = 10

        # Tunneling data
        TUNNEL_REQ = 11
        TUNNEL_DATA = 12
        TUNNEL_CLOSE = 13
