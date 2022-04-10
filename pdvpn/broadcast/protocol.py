#!/usr/bin/env python3

import bz2
import string
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
    def read_intent(data: BytesIO) -> Tuple["BroadcastProtocol.Intent", int]:
        """
        Reads the packet intent from the data.

        :param data: The tunneling data.
        :return: The intent and broadcast ID.
        """

        intent = BroadcastProtocol.Intent(data.read(1)[0])
        broadcast_id = int.from_bytes(data.read(4), "big", signed=False)
        return intent, broadcast_id

    @staticmethod
    def send_intent(data: BytesIO, intent: "BroadcastProtocol.Intent", broadcast_id: int) -> None:
        """
        Sends the packet intent to the socket.

        :param data: The tunneling data to write to.
        :param intent: The intent.
        :param broadcast_id: The broadcast ID.
        """

        data.write(bytes([intent.value]))
        data.write(broadcast_id.to_bytes(4, "big", signed=False))

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
