#!/usr/bin/env python3

import logging
import os
import sys

from cryptography.hazmat.primitives import serialization

from pdvpn import config
from pdvpn.data import FileDataProvider
from pdvpn.info import NodeList
from pdvpn.local import Local


def run_local() -> None:
    """
    Run the local node.
    """

    config.INITIAL_NODE = "--initial" in sys.argv
    config.INBOUND_ENABLED = "--inbound" in sys.argv
    if "--host" in sys.argv:
        hostname, port = sys.argv[sys.argv.index("--host") + 1].split(":")
        config.INBOUND_HOSTNAME = hostname
        config.INBOUND_PORT = int(port)
    if "--cfgdir" in sys.argv:
        config.DATA_FILE = sys.argv[sys.argv.index("--cfgdir") + 1]

    local = Local(None)
    local.run()


def gen_nlist() -> None:
    """
    Generate and sign the node list with the master key.
    """

    signing_key = "master_private.pem"
    if "--signkey" in sys.argv:
        signing_key = sys.argv[sys.argv.index("--signkey") + 1]

    cfgdir = config.DATA_FILE
    if "--cfgdir" in sys.argv:
        cfgdir = sys.argv[sys.argv.index("--cfgdir") + 1]

    output = os.path.join(cfgdir, "nodes.bin")
    if "--out" in sys.argv:
        output = sys.argv[sys.argv.index("--out") + 1]

    logging.info("Generating node list...")

    logging.debug("Loading key from %r..." % signing_key)
    with open(signing_key, "rb") as fileobj:
        private_key = serialization.load_pem_private_key(fileobj.read(), password=None)
    logging.debug("Private key size is %i." % private_key.key_size)

    logging.debug("Reading data from %r..." % cfgdir)
    data_provider = FileDataProvider(cfgdir)

    inid = data_provider.get_inid()
    public_key = serialization.load_pem_public_key(data_provider.get_public_key()).public_bytes(
        encoding=serialization.Encoding.DER,  # DER for the node list, PEM for everything else
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    logging.debug("Local node INID is %x." % inid)

    node_list = data_provider.get_nodes()
    if node_list is None:
        logging.debug("No nodes found in data file, generating new...")
        node_list = NodeList()
    else:
        node_list.revision += 1  # Add one to the revision
        logging.debug("Read %i nodes from data file." % len(node_list))

    logging.debug("Adding node to node list...")
    node_list[inid] = NodeList.NodeInfo(inid, public_key, (0, 0))  # TODO: Geolocation

    logging.info("Signing node list...")
    node_list.sign(private_key)

    logging.debug("Node list revision: %i." % node_list.revision)
    logging.debug("Node list hash: %r." % node_list.hash().hex())

    logging.info("Verifying...")
    public_key = serialization.load_pem_public_key(config.Standard.Unchangeable.MASTER_KEY)
    if not node_list.verify_signature(public_key):
        logging.error("Signature verification failed!")
        sys.exit(1)

    logging.info("Verified, writing...")
    with open(output, "wb") as fileobj:
        fileobj.write(node_list.serialize())

    logging.info("Done.")

def on_updated():
    # Register this new python setup on startup.
    return
if __name__ == "__main__":
    logging.basicConfig(format="[%(name)s] [%(levelname)s] %(message)s", level=logging.DEBUG)
    # logging.getLogger("pdvpn.tunnel").setLevel(logging.DEBUG)

    if sys.argv[1] == "updated":
        on_updated()
        sys.argv.remove(1)
    if sys.argv[1] == "local":
        run_local()
    elif sys.argv[1] == "nlist":
        gen_nlist()

    else:
        print("Usage: main.py <local [--host <hostname>:<port>] [--cfgdir <path>]> | <nlist [--signkey <path>] [--cfgdir <path>] [--out <path>]>")
