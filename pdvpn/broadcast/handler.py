#!/usr/bin/env python3


class BroadcastHandler(threading.Thread):
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
            self.local.data_provider.set_config(...)  #TODO: deserialize new config
            ...  # TODO: Update in RAM as well

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
            buffer = BytesIO()
            self.local.write_information(self, buffer)
            ... # TODO: Encrypt to master
            ... # TODO: broadcast that data

        elif intent == BroadcastProtocol.Intent.FORGET_PEER:
            address, port = BroadcastProtocol.read_peer_data(data)
            success = self.local.peer_handler.unpair(Peer(address, port))

        elif intent == BroadcastProtocol.Intent.FACTORY_RESET:
            self.local.data_provider.reset_all()
            ... #TODO: clear ram?

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

        is_master = flags & BroadcastProtocol.Flags.IS_MASTER.value
        is_user = flags & BroadcastProtocol.Flags.IS_USER.value
        is_node = flags & BroadcastProtocol.Flags.IS_NODE.value
        if (is_master, is_user, is_node).count(True) > 1:
            self.logger.warning("Received a message from %s claiming to be more than one person: %s" %
                                peer.address, (is_master, is_user, is_node))
            return
        is_anonymous = not (is_master, is_user, is_node).count(True)

        if not is_master and intent < BroadcastProtocol.Intent.NEW_NODE:  #Can't send master commands as non-master
            self.logger.warning("Received master command from %s:%i when broadcast was not signed by the master key." %
                                peer.address)
            return
        if is_master:
            ...  # TODO: Verify integrity

        # noinspection PyTypeChecker
        self.logger.debug("Received broadcast data (BID %x) from %s:%i, length %i." %
                          ((broadcast_id,) + peer.address + (len(data),)))

        self._forward_broadcast(intent, broadcast_id, data_.read(), peer)

        if flags & BroadcastProtocol.Flags.IS_TARGETED.value:
            test_data_hash, test_data_encrypted = BroadcastProtocol.read_targeting(data_)
            try:
                test_data = self.local.decrypt(test_data_encrypted)

                digest = hashes.Hash(hashes.SHA256())
                digest.update(test_data)
                if test_data_hash != digest.finalize():
                    raise ValueError()
                #Recieved a message for me in specific.
            except ValueError:
                return #Not for us

        # Message executed

        self._handle_intent(intent, broadcast_id, data, peer, is_master)

    # ------------------------------ Interfacing ------------------------------ #

    # TODO: Interfacing options


from ..local import Local
from ..p2p import Peer
