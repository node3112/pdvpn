#!/usr/bin/env python3

"""
Config for PD VPN.
"""


# ------------------------------ Standard constants ------------------------------ #
from typing import Dict, Any


class Standard:
    """
    The standard config.
    """

    @classmethod
    def update_mutable(cls, config: Dict[str, Any]) -> None:
        """
        Updates the mutable (changeable) config options.

        :param config:


        the new node selects a potential friend from the list. He marks it out so that only the potential friend himself will know that he is the guy he wants to connect to.
        The entry point does not know however who this potential friend is. The entry point just forwards the message in the hopes that it will be recieved.
        This message will not be spammed because there is proof of work on top of it.

        Now the entry point has got a tunneled connection with the potential friend, but the entry point has no idea who.
        The potential friend does however know the entry point and verifies if he is really an entry point now.

        An important part to understand is that a malicious node would not want to connect to another malicious node. That would be useless. The problem arises when a malicious node connects to many vanilla nodes.
        We can ensure this way that either the potential friend or the newly connecting node is malicious.

        Now the entry point signs a commitment that they have paired a node. When the potential friend has actually succesfully paired,
        he will broadcast that commitment so that the entry point can't register too many nodes. If the entry point doesn't sign this, then the potential friend refuses to pair.
        This commitment is only valid with POW from the potential friend.

        The potential friend responds with a POW which can be used later for signing the commitment.

        New node sends addSignature(hash(IP), myPrivateKey)

        The potential friend would broadcast the hash(hash(IP)). He would broadcast that new IP anonymously and asks other people if they know the hash(IP)
        If like too many people do, then he will refuse connection. However if not then it means that not many legit nodes are connected to the potentially malicious node.

        Potential friend sends hash of IP to new node.

        New node asks everybody similarly if they know him. If not too many, then connect.

        New node sends IP to potential friend which is double checked by him.

        If okay then potential friend connects to new node and they pair.
        Now that they are all paired up, the potential friend would broadcast the entry point's commitment, and he would not be able to talk himself out of it because he signed it.

        NOTE: the new node "pays" for all the broadcasts and connects via POW. This way he can't spam register himself with false hashes.
        NOTE: if the potential friend publicices the commitment too early, he has still paid for that.
        NOTE: If anyone does not follow the protocol then the connection is simply refused by the other legit party.
        NOTE: If the potential friend would just refuse to do the POW at all (maybe because already too many peers he sais),
        then that doesn't matter, because then the entry point won't get switched and the new node could just select another potential friend. And if he honestly
        said that he had too many peers then that does reduce the network stress.
        NOTE: An alternative to broadcasting the hash(hash(IP)) is by broadcasting half the hash(IP), and then let someone else finish the rest.



        ----------- Entry Point Picking -----------
        * We could make an RNG by having every node sending a random piece of data to the network and signing it. Now we will assume that every node reciesves it.
        If we hash all those random pieces together then we will have a random number which everybody can agree on. This could for example be used to select the new entry points.

        * We could have the nodes be entry point in the order that they connected them in. So like the first node would be entry point and connect 2 nodes or wait an hour
        (so that they can't be it forever if they refuse to work)


        """

    class Immutable:
        """
        Standard constants that are not subject to change over the network lifetime.
        """

        MASTER_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA1ztvdU1UE0QJrqqh/LP1
88RIGmLdLjLdHI+bZ/c42ZU40RTr+wTZplnuJqbYnoZrzOXwuhTomf9SdgtJQ4HE
LP4rPYMQwLO6GHzWAT1Z32qZnQdfZpoZQfWMUK3pZT601GGY5V+5lf1++bD6ve42
tFUGgjn0Ptu6KtJ+cCYzghi/aK02FLxzKQaXvtI4MaWM7Al7qWYyUUu32KVwRv8M
009tYMSEfAIlWH5D6RtvxvOd+vkN6PPYsktFBUeq1suJYWx+3tS2SNmzWESH/3SR
JOYm+2/0w8bgTe92mkZazaLRo4NwozV/zSis3+KtVLexqSgFNG3RGT/8jysfPBAD
qHyMzRWztQUFsJ0VFSYwo0cxmZTlX5Uy9rQIsse8IBSXNfZ8asUSXdn8ODsI4Xhu
Yy5XWFxMg+B1DKImOEMltB2TwSw7oSJwy4glP/pZAzmmpKbXU4YutvN3lCCMGzhm
9GbCinaAbHherehbWwQ5uvTMyeBIO/XYSwFTcx/p2kEtY/TUj9U66zPCc4Qln63U
DvPBspDfDKiHurofwcYU5r3w6S+UWGMcUDJfy8Cosvuk9ZXyUJ3gE28N9Mak8EZ/
VhxKNVhKDITDwRjzXoCjYAa05v56Pv/eKlxreqWSV1KhMbdUQibi64Br1i2MV9bT
pyVRphNiz19xKE5VjwXNF6mOaabK7B5TWR097W94WgmGaRfy1sifRhVFYb3D/g/J
7COzFKG9B4xlx45lOMEKqLTZCuNoi1EqQDLKVx4iq1IxVQsf+RxL6UTWaa5LBGz6
WIYp06Rd0PR6kC9+JIGYK/VFcECh6KdIP8ZfumHLvH0fOLVZj4Rho6cPmT1Z9W9Y
WHLEtC1GWTfCIRaqERMeTvTcNyoRPiXiysMBlaA25sZU+sMhFq0e2olPAh+cyqzk
h/wLukRFz/+WI3IxcjmomfJi7rZ4NHEVp+g7kCJZDzezBfqei0nIPut0W7Xh06v8
p5f7XzOV+JNQzbBVQRSc10AByTdODqAfjpeEKX2sVBhUEnGiWDQjQc5NkBthlh8x
cLzkro5b/OowiMeEmDI144NMbUoSTfGUgeoTqdxthOvy1Lu6fNRmOg7ZINijPXWg
HlRUjLrCWRueqwf4OvOH3jMKHtM0AdwJvJh9YPWDaM6LyeFo67Vz7r7ZbHivUa70
9zR/EHmXhgTdoMCmAbsqf7V2fqp27D4wp2AkclSJ99LsUtFWjKgYR3PA1fJ4WGWx
Zp9Z4AAMUpu7LP3etfgYRvW4cZltVLspBQR2sVSAALe7x10/q6divfhFwTUciggl
e+IVrwO0B0R7DCH/vbeb4fIPxYHu7wndP55HUEFnCJ3O8jFwqY6eWdQyi+wrY8MJ
2wIDAQAB
-----END PUBLIC KEY-----"""

        CLIENT = "py3"  # Client name/type
        VERSION = "0.1.4"  # Client version

    class Mutable:
        """
        Standard constants that are subject to change over the network's lifetime.
        """

        NODE_LIST_TRUST_THRESHOLD = 0.9  # % of valid nodes required to trust an unverified node

        RSA_KEY_SIZE = 2048
        RID_RSA_KEY_SIZE = 2048
        DHKE_KEY_SIZE = 512
        TUNNEL_RSA_KEY_SIZE = 1024

        KEEP_ALIVE_INTERVAL = 60  # Seconds
        TUNNEL_KEEP_ALIVE_INTERVAL = 30  # Seconds
        # TODO: Temp values, may need to change later
        BROADCAST_EXPIRY = 60  # Seconds
        TUNNEL_EXPIRY = 60  # Seconds

        # ------------------------------ Tunnel stuff ------------------------------ #

        TUNNEL_TIMEOUT = 30  # Seconds
        # TODO: Uh idk prolly proper data to sign, like the time?
        TUNNEL_DATA_RANDOM_SIZE = 16  # The distinction is so that one can't be copied
        TUNNEL_CLOSE_RANDOM_SIZE = 32


# ------------------------------ Data provider stuff ------------------------------ #

DATA_FILE = "vpnconf"

# ------------------------------ Connection stuff ------------------------------ #

INITIAL_NODE = True  # Are we the initial node on the network?
INBOUND_ENABLED = True
INBOUND_HOSTNAME = "localhost"  # Local node server's hostname
INBOUND_PORT = 5002  # Local node server's port, should prolly be 5002
