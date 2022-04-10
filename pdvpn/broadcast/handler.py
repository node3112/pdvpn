#!/usr/bin/env python3

import logging
import time
from io import BytesIO
from typing import Union

from .protocol import BroadcastProtocol
from ..info import NodeList


class BroadcastHandler:
    """
    Handles broadcast messages.
    """

    def __init__(self, local: "Local") -> None:
        self.logger = logging.getLogger("pdvpn.broadcast.handler")

        self.local = local

        self._known_broadcasts = {}

    # ------------------------------ Internal ------------------------------ #

    def _forward_broadcast(self, intent: BroadcastProtocol.Intent, broadcast_id: int, data: bytes,
                           peer: Union["Peer", None]) -> None:
        """
        Forwards broadcast data to all peers that don't already know about it.
        """

        # TODO: This
        # TODO: Congestion handling

    def _handle_intent(self, intent: BroadcastProtocol.Intent, broadcast_id: int, data: bytes,
                       peer: Union["Peer", None]) -> None:
        """
        Handles broadcast data based on the intent.

        :param intent: The intent of the broadcast.
        :param broadcast_id: The ID of the broadcast, for logging purposes.
        :param data: The data of the broadcast.
        :param peer: The peer that sent the broadcast, for logging purposes.
        """

        data = BytesIO(data)  # FIXME: Way too much overhead

        # Updating stuff from the "master node"

        if intent == BroadcastProtocol.Intent.UPDATE_CONFIG:
            ...  # TODO: Ability to update config?

        elif intent == BroadcastProtocol.Intent.UPDATE_CLIENT:
            ...  # TODO: Idk, a lot of client determining stuff

        elif intent == BroadcastProtocol.Intent.UPDATE_NODE_LIST:
            # TODO: Make this a packet cos bruh
            node_list_data = data.read()  # The rest of the data will be the node list
            if not node_list_data:  # Wtf, no data?
                return

            node_list = NodeList()
            try:  # TODO: Pre-verification so we don't waste time on bad data
                node_list.deserialize(node_list_data)
            except Exception:
                # TODO: Should we warn about this?
                return

            if node_list.revision <= self.local.node_list.revision:  # We aren't gonna "update" to an older revision
                self.logger.warning("Received old node list from %s:%i, revision %i." %
                                    (peer.address + (node_list.revision,)))
                return
            elif not node_list.verify_signature(self.local._master_key):
                self.logger.warning("Received node list from %s:%i, signature invalid." % peer.address)
                # TODO: Why is the peer sending bad data, should we kick it?
                return

            self.local.node_list = node_list  # Update the local node list
            self.local.data_provider.set_nodes(self.local.node_list)

        elif intent == BroadcastProtocol.Intent.UPDATE_USER_LIST:
            ...  # TODO: User lists in general

        # More "master node" stuff

        elif intent == BroadcastProtocol.Intent.INFORMATION_REQUEST:
            ...

        elif intent == BroadcastProtocol.Intent.FORGET_PEER:
            ...  # TODO: self.local.peer_handler.unpair(...)

        elif intent == BroadcastProtocol.Intent.FACTORY_RESET:
            ...  # TODO: self.local.data_provider.reset_all()

    # ------------------------------ Events ------------------------------ #

    def on_broadcast_data(self, data: bytes, peer: "Peer") -> None:
        """
        Called when broadcast data is received from a peer.

        :param data: The data that was received.
        :param peer: The peer that the data was received from.
        """

        data_ = BytesIO(data)
        intent, broadcast_id = BroadcastProtocol.read_intent(data_)
        if broadcast_id in self._known_broadcasts:  # We already know about this broadcast, no need to retransmit
            return
        self._known_broadcasts[broadcast_id] = time.time()  # Record for the timeout
        # TODO: Removed timed out ones, should this be a thread?

        # noinspection PyTypeChecker
        self.logger.debug("Received broadcast data (BID %x) from %s:%i, length %i." %
                          ((broadcast_id,) + peer.address + (len(data),)))

        self._forward_broadcast(intent, broadcast_id, data_.read(), peer)
        self._handle_intent(intent, broadcast_id, data, peer)

    # ------------------------------ Interfacing ------------------------------ #

    # TODO: Interfacing options


from ..local import Local
from ..p2p import Peer
