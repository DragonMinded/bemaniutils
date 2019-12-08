The eAmusement protocol layer is divided into the main encoder/decoder class,
a class for parsing old-style XML, a class for parsing new-style binary tree
structure, a class representing a single node in a tree, and a few helper
classes to tie the whole system together. Each message as sent to or received
from a game can be represented as a tree of nodes. A node can either have
additional nodes as children, or it can have a data value. Both types of node
can have attributes. Given a tree of nodes, the encoder will output valid
binary data suitable for returning to a game over HTTP, including any optional
encryption or compression. Given binary data posted over HTTP from a game, the
decoder will output a tree of nodes.

A rough sketch of how the pieces fit together is as follows:

            ------------------             --------
            | EAmuseProtocol |------------>| Lz77 |
            ------------------             --------
                 |      |
                 |      -------------------
                 |                        |
                 V                        V
          ---------------           ------------------
          | XmlEncoding |           | BinaryEncoding |
          ---------------           ------------------
             |       ^                 ^         |
             |       |   ----------    |         |
             |       --->| Stream |<----         |
             |           ----------              |
             |                                   |
             |            --------               |
             ------------>| Node |<---------------
                          --------

A packet will come in as data representing XML or a binary packet. It is
optionally wrapped with Lz77 compression. That is optionally wrapped with
RC4 encryption. Note that a packet may be encrypted and not compressed, but
a packet with both compression and encryption will have RC4 as the outermost
layer, followed by Lz77, followed finally by the raw data either as XML or
binary.

EAmuseProtocol is responsible for encryption/decryption using inlined RC4
code, Lz77 compression/decompression using the Lz77 helper class, and finally
uses either the XmlEncoding or BinaryEncoding class to convert to/from a
tree of Node objects. Both XmlEncoding and BinaryEncoding use the Stream class
as a helper for creating and dissecting raw binary data that will be exchanged
with EamuseProtocol. Finally, Node is a representation of one element in the
tree, having a name, an optional value and optional children which are also
instances of the Node class.

This setup is designed from the perspective of having a HTTP server such as
flask pass binary data to EAmuseProtocol, and retrieve encoded responses from
it. Game server code is expected to receive a tree in the form of a root Node
instance. It will use various helper methods to walk the tree, decide on an
appropriate response and then build that response using additional helper
methods on the Node class. In this way, the game server component can work
entirely on nodes, decoupled from the wire protocol itself and the HTTP request
details.

For details on how each piece works, see the respective classes as they have
complete docstrings and type hints.
