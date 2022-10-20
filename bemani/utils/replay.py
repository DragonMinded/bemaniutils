import argparse
import random
import requests
import sys

from bemani.protocol import EAmuseProtocol, Node


def hex_string(length: int, caps: bool = False) -> str:
    if caps:
        string = "0123456789ABCDEF"
    else:
        string = "0123456789abcdef"
    return "".join([random.choice(string) for x in range(length)])


class Protocol:
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
            encryption = f"1-{hex_string(8)}-{hex_string(4)}"
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
            f'http://{self.__address}:{self.__port}{"/" if uri[0] != "/" else ""}{uri}',
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A utility to replay a packet from a log or binary dump."
    )
    parser.add_argument(
        "-i",
        "--infile",
        help="File containing an XML or binary node structure. Use - for stdin.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "-e",
        "--encoding",
        help="Encoding for the packet, defaults to UTF-8.",
        type=str,
        default="utf-8",
    )
    parser.add_argument(
        "-p", "--port", help="Port to talk to. Defaults to 80", type=int, default=80
    )
    parser.add_argument(
        "-a",
        "--address",
        help="Address to talk to. Defaults to 127.0.0.1",
        type=str,
        default="127.0.0.1",
    )
    parser.add_argument(
        "-u",
        "--path",
        help="URI that we should post to. Defaults to '/'",
        type=str,
        default="/",
    )
    args = parser.parse_args()

    if args.infile == "-":
        # Load from stdin
        packet = sys.stdin.buffer.read()
    else:
        with open(args.infile, mode="rb") as myfile:
            packet = myfile.read()
            myfile.close

    # Add an XML special node to force encoding (will be overwritten if there
    # is one in the packet).
    packet = b"".join(
        [
            f'<?xml encoding="{args.encoding}"?>'.encode(args.encoding),
            packet,
        ]
    )

    # Attempt to decode it
    proto = EAmuseProtocol()
    tree = proto.decode(
        None,
        None,
        packet,
    )

    if tree is None:
        # Can't decode, exit
        raise Exception("Unable to decode packet!")

    model = tree.attribute("model")
    module = tree.children[0].name
    method = tree.children[0].attribute("method")

    server = Protocol(args.address, args.port, False, False, False)
    server.exchange(
        f"{args.path}?model={model}&module={module}&method={method}",
        tree,
    )


if __name__ == "__main__":
    main()
