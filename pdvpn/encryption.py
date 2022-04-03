#!/usr/bin/env python3

import socket

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import _AEADEncryptionContext, _AEADCipherContext


def get_cipher_from_secrets(shared_key: bytes, iv: bytes) -> Cipher:
    """
    Gets an AES 256 cipher from the shared key and iv.

    :param shared_key: The shared key.
    :param iv: The init vector.
    :return: The AES 256 cipher.
    """

    if len(shared_key) > 32:
        shared_key = shared_key[:32]

    if len(iv) > algorithms.AES.block_size // 8:
        iv = iv[:algorithms.AES.block_size // 8]

    return Cipher(algorithms.AES(shared_key), modes.CFB8(iv))  # CFB mode


class EncryptedSocketWrapper:
    """
    Wraps a socket and encrypts/decrypts data.
    """

    def __init__(self, conn: socket.socket, encryptor: _AEADEncryptionContext, decryptor: _AEADCipherContext) -> None:
        self.conn = conn
        self.encryptor = encryptor
        self.decryptor = decryptor

    # Wrap useful functions from socket.socket

    def settimeout(self, timeout: float) -> None:
        self.conn.settimeout(timeout)

    def send(self, data: bytes) -> int:
        return self.conn.send(self.encryptor.update(data))

    def sendall(self, data: bytes) -> None:
        self.conn.sendall(self.encryptor.update(data))

    def recv(self, length: int) -> bytes:
        return self.decryptor.update(self.conn.recv(length))

    def fileno(self) -> int:
        return self.conn.fileno()

    def close(self) -> None:
        self.conn.close()

    def shutdown(self, how: int) -> None:
        self.conn.shutdown(how)