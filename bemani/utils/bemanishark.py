from typing import Optional
import argparse

from bemani.sniff import Sniffer
from bemani.protocol import EAmuseProtocol, EAmuseException
from bemani.common import HTTP


def mainloop(
    address: Optional[str] = None, port: int = 80, verbose: bool = False
) -> None:
    """
    Main loop of BEMANIShark. Starts an instance of Sniffer and EAmuseProtocol and does a
    lazy job of banging them together with the above HTTP.parse. Will loop trying to decode
    packets forever.

    Arguments:
        address - A string representing an IP of interest
        port - An integer representing a port of interest
    """
    sniffer = Sniffer(address=address, port=port)
    parser = EAmuseProtocol()

    while True:
        packets = sniffer.recv_stream()

        inbound = HTTP.parse(packets["inbound"], request=True)
        outbound = HTTP.parse(packets["outbound"], response=True)

        if inbound is not None:
            if inbound["data"] is None:
                in_req = None
            else:
                try:
                    in_req = parser.decode(
                        inbound["headers"].get("x-compress"),
                        inbound["headers"].get("x-eamuse-info"),
                        inbound["data"],
                    )
                except EAmuseException:
                    in_req = None

            print(
                f"Inbound request (from {packets['source_address']}:{packets['source_port']} to {packets['destination_address']}:{packets['destination_port']}):"
            )
            if verbose:
                print(f"HTTP {inbound['method']} request for URI {inbound['uri']}")
                print(f"Compression is {inbound['headers'].get('x-compress', 'none')}")
                print(
                    f"Encryption key is {inbound['headers'].get('x-eamuse-info', 'none')}"
                )
            if in_req is None:
                print("Inbound request was not parseable")
            else:
                print(in_req)

        if outbound is not None:
            if outbound["data"] is None:
                out_req = None
            else:
                try:
                    out_req = parser.decode(
                        outbound["headers"].get("x-compress"),
                        outbound["headers"].get("x-eamuse-info"),
                        outbound["data"],
                    )
                except EAmuseException:
                    out_req = None

            print(
                f"Outbound response (from {packets['destination_address']}:{packets['destination_port']} to {packets['source_address']}:{packets['source_port']}):"
            )
            if verbose:
                print(f"Compression is {outbound['headers'].get('x-compress', 'none')}")
                print(
                    f"Encryption key is {outbound['headers'].get('x-eamuse-info', 'none')}"
                )
            if out_req is None:
                print("Outbound response was not parseable")
            else:
                print(out_req)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A utility to sniff packets and decode them as eAmusement packets. Should probably be run as root."
    )
    parser.add_argument(
        "-p", "--port", help="Port to sniff on. Defaults to 80", type=int, default=80
    )
    parser.add_argument(
        "-a",
        "--address",
        help="Address to sniff on. Defaults to all addresses",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-v", "--verbose", help="Show extra packet information", action="store_true"
    )
    args = parser.parse_args()

    mainloop(address=args.address, port=args.port, verbose=args.verbose)


if __name__ == "__main__":
    main()
