# The P2P protocol
An outline of the entire P2P protocol. This is the protocol that acts between nodes connected to each other (peers).

## Handshake
1. Outbound generates DHKE `param_g`, `param_p` and `a_peer_public_key`.
2. `-> HELLO(a_peer_public_key, param_g, param_p)`
3. Inbound receives DHKE params, generates `b_peer_public_key`, `shared_secret` and `init_vector`.
4. `<- HELLO_ACK(b_peer_public_key, init_vector)`
5. Outbound receives finalizing parameters and `init_vector`, generates `shared_secret`.
6. Both peers now begin an AES-256 encrypted connection with `shared_secret` and `init_vector`.
7. `-> FIN`
8. `<- FIN_ACK`
9. If either of the above packets fail to decode, we know the handshake failed, so the peers drop each other.

## Disconnects
1. Either party can send disconnects.
2. `-> DISCONNECT(reason)` or `<- DISCONNECT(reason)`
3. The peer should be marked as offline if this happens.

## Keep alives
1. The inbound peer is responsible for sending initial keepalives, if the `KEEPALIVE_INTERVAL` has been reached.
2. `<- KEEP_ALIVE`
3. If the outbound peer does not respond to the keepalive within the `KEEPALIVE_INTERVAL`, it is disconnected for "timeout".
4. `-> KEEP_ALIVE`

TODO: Finish this

## Packets
 - `0x00` **HELLO** - sent on first connection.
   - `uint16 a_peer_public_key_size` - the size (bytes) of a_peer_public_key.
   - `uint8 param_g_size` - the size (bytes) of param_g.
   - `uint8 param_p_size` - the size (bytes) of param_p.
   - `bytes(a_peer_public_key_size) a_peer_public_key` - DHKE a_peer_public_key.
   - `varint(param_g_size) param_g` - DHKE param_g.
   - `varint(param_p_size) param_p` - DHKE param_p.

 - `0x01` **HELLO_ACK** - sent in response to **HELLO**.
   - `uint16 b_peer_public_key_size` - the size (bytes) of b_peer_public_key.
   - `bytes(b_peer_public_key_size)` - DHKE b_peer_public_key.

 - `0x02` **FIN** - sent to finalize handshake.
   - `uint8 num_bytes` - random number symbolizing how many bytes to read.
   - `bytes(num_bytes) random_data` - random data to confirm the encryption is correct.

 - `0x03` **FIN_ACK** - sent in response to **FIN** *empty packet*.

 - `0x04` **DISCONNECT** - sent to inform peer of a disconnect.
   - `uint8 reason_size` - the size of the reason data.
   - `utf8(reason_size) reason` - the reason for the disconnect.

 - `0x05` **KEEP_ALIVE** - sent to check if peer is still connected *empty packet*.

 - `0x06` **NLIST_REQ**

 - `0x07` **NLIST_RES**

 - `0x08` **PAIR_REQ**

 - `0x09` **PAIR_RES**

 - `0x0a` **DATA**

 - `0x0b` **TUNNEL_REQ**

 - `0x0c` **TUNNEL_DATA**

 - `0x0d` **TUNNEL_CLOSE**