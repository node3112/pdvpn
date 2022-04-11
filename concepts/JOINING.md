#Joining 
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

### Notes
* the new node "pays" for all the broadcasts and connects via POW. This way he can't spam register himself with false hashes.

* if the potential friend publicices the commitment too early, he has still paid for that.

* If anyone does not follow the protocol then the connection is simply refused by the other legit party.

* If the potential friend would just refuse to do the POW at all (maybe because already too many peers he sais),
then that doesn't matter, because then the entry point won't get switched and the new node could just select another potential friend. And if he honestly
said that he had too many peers then that does reduce the network stress.

* An alternative to broadcasting the hash(hash(IP)) is by broadcasting half the hash(IP), and then let someone else finish the rest.

## Entry Point Picking
* We could make an RNG by having every node sending a random piece of data to the network and signing it. Now we will assume that every node reciesves it.
If we hash all those random pieces together then we will have a random number which everybody can agree on. This could for example be used to select the new entry points.

* We could have the nodes be entry point in the order that they connected them in. So like the first node would be entry point and connect 2 nodes or wait an hour
(so that they can't be it forever if they refuse to work)

## How Node Connect To Entry Point

* Discord based voting principle for entry point selection. Every node would vote in the discord server, and then the newly joining node would count all the votes.
The discord server would get shut down because of authority pretty soon though, however, that means that it is time
to stop accepting new nodes.
We would give some people voting right by signing a public key with the master key for voting. Then we would give all the nodes which could vote that key.
Problem: discord would know all the IP's of the voters.