import requests

from bemani.client.common import random_hex_string
from bemani.protocol import EAmuseProtocol, Node


class ClientProtocol:
    def __init__(
        self,
        address: str,
        port: int,
        encryption: bool,
        compression: bool,
        verbose: bool,
    ) -> None:
        self.__address = address
        self.__port = port
        self.__encryption = encryption
        self.__compression = compression
        self.__verbose = verbose

    def exchange(
        self,
        uri: str,
        tree: Node,
        text_encoding: str = "shift-jis",
        packet_encoding: str = "binary",
    ) -> Node:
        headers = {}

        if self.__verbose:
            print("Outgoing request:")
            print(tree)

        # Handle encoding
        if packet_encoding == "xml":
            _packet_encoding = EAmuseProtocol.XML
        elif packet_encoding == "binary":
            _packet_encoding = EAmuseProtocol.BINARY
        else:
            raise Exception(f"Unknown packet encoding {packet_encoding}")

        # Handle encryption
        if self.__encryption:
            encryption = f"1-{random_hex_string(8)}-{random_hex_string(4)}"
            headers["X-Eamuse-Info"] = encryption
        else:
            encryption = None

        # Handle compression
        if self.__compression:
            compression = "lz77"
        else:
            compression = None
        headers["X-Compress"] = compression

        # Convert it
        proto = EAmuseProtocol()
        req = proto.encode(
            compression,
            encryption,
            tree,
            text_encoding=text_encoding,
            packet_encoding=_packet_encoding,
        )

        # Send the request, get the response
        r = requests.post(
            f"http://{self.__address}:{self.__port}/{uri}",
            headers=headers,
            data=req,
        )

        # Get the compression and encryption
        encryption = headers.get("X-Eamuse-Info")
        compression = headers.get("X-Compress")

        # Decode it
        packet = proto.decode(
            compression,
            encryption,
            r.content,
        )
        if self.__verbose:
            print("Incoming response:")
            print(packet)
        return packet
