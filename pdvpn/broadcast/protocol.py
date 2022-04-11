#!/usr/bin/env python3

import bz2
import struct
from enum import Enum
from io import BytesIO
from typing import Tuple, Dict, Any


class BroadcastProtocol:
    """
    The protocol for message broadcasts.
    """

    # ------------------------------ Intent ------------------------------ #

    @staticmethod
    def read_intent(data: BytesIO) -> Tuple["BroadcastProtocol.Intent", int, int, int]:
        """
        Reads the packet intent from the data.

        :param data: The tunneling data.
        :return: The intent, broadcast ID, flags and time sent.
        """

        intent = BroadcastProtocol.Intent(data.read(1)[0])
        broadcast_id = int.from_bytes(data.read(4), "big", signed=False)
        flags = data.read(1)[0]
        time_sent = int.from_bytes(data.read(8), "big", signed=False)
        return intent, broadcast_id, flags, time_sent

    @staticmethod
    def send_intent(data: BytesIO, intent: "BroadcastProtocol.Intent", broadcast_id: int, flags: int,
                    time_sent: int) -> None:
        """
        Sends the packet intent to the socket.

        :param data: The tunneling data to write to.
        :param intent: The intent.
        :param broadcast_id: The broadcast ID.
        :param flags: The flags to send with.
        :param time_sent: The time the broadcast was sent at.
        """

        data.write(bytes([intent.value]))
        data.write(broadcast_id.to_bytes(4, "big", signed=False))
        data.write(bytes([flags]))
        data.write(time_sent.to_bytes(8, "big", signed=False))

    @staticmethod
    def read_update(data: BytesIO) -> Tuple[BytesIO, str]:
        version_name = str(int.from_bytes(data.read(4), "big", signed=False))  # TODO: Make this a string
        return data, version_name

    @staticmethod
    def read_targeting(data: BytesIO) -> Tuple[bytes, bytes]:
        """
        Reads the targeted data, if the broadcast is targeted.

        :param data: The data to read from.
        :return: The test data hashed and the test data encrypted.
        """

    @staticmethod
    def read_peer_data(data: BytesIO) -> Tuple[str, int]:
        address = data.read(4)
        port = data.read(4)
        return address, port


    @staticmethod
    def write_targeting(data: BytesIO, test_data_hash: bytes, test_data_encrypted: bytes) -> None:
        """
        Writes targeting data.

        :param data: The data to write to.
        :param test_data_hash: The test data hashed.
        :param test_data_encrypted: The test data encrypted with the recipient's public key.
        """

        data.write(struct.pack(">HH", len(test_data_hash), len(test_data_encrypted)))

    @staticmethod
    def read_config(data: BytesIO) -> Dict[str, Any]:
        ...

    @staticmethod
    def read_update_node_list(data: BytesIO) -> bytes:
        """
        Reads the node list response packet.

        :param data: The data to read from.
        :return: The node list bytes.
        """

        node_list_size = int.from_bytes(data.read(4), "big", signed=False)
        return bz2.decompress(data.read(node_list_size))

    class Flags(Enum):
        IS_NODE = 0x01
        IS_USER = 0x02
        IS_MASTER = 0x04
        IS_TARGETED = 0x08

    class Intent(Enum):
        """
        Broadcast message intent.
        """

        # Stuff sent by the "master node"

        UPDATE_CONFIG = 0
        UPDATE_CLIENT = 1  # Update the new code
        UPDATE_NODE_LIST = 2
        UPDATE_USER_LIST = 3
        INFORMATION_REQUEST = 4  # Request the information of a specific node
        INFORMATION_RESPONSE = 5
        FORGET_PEER = 6
        FACTORY_RESET = 7

        # Misc
        NEW_NODE = 8  # Send information encrypted with master key
