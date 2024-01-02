import socket
import struct
from typing import Any, Dict, List, Optional, Tuple
from typing_extensions import Final


class InvalidPacketException(Exception):
    """
    Exception thrown when a packet has invalid information in it that doesn't
    confirm to the spec.
    """


class UnknownPacketException(Exception):
    """
    Exception thrown when a packet is valid, but we don't include support for
    decoding it.
    """


class TCPStream:
    """
    A very rudimentary TCP stream reassembler. Assumes well-formed TCP streams with a
    SYN -> SYNACK -> ACK flow followed by some data followed by a FIN -> FINACK -> ACK
    flow. Luckily, this is exactly what most HTTP requests look like.
    """

    INBOUND: Final[str] = "inbound"
    OUTBOUND: Final[str] = "outbound"

    def __init__(self, packet: Dict[str, Any]) -> None:
        """
        Initialize a new stream with a packet that belongs in this stream. Expects a packet
        dictionary as returned by Sniffer.recv_raw().
        """
        self.source_address = packet["ip_header"]["source_address"]
        self.source_port = packet["tcp_header"]["source_port"]
        self.destination_address = packet["ip_header"]["destination_address"]
        self.destination_port = packet["tcp_header"]["destination_port"]

        self.packets = [(TCPStream.INBOUND, packet)]

    def add_packet(self, packet: Dict[str, Any]) -> bool:
        """
        Add a packet that potentially belongs to this stream. Expects a packet dictionary as
        returned by Sniffer.recv_raw().

        Returns:
            True - If this packet indeed belonged and was added.
            False - If this packet doesn't belong and should go elsewhere.
        """
        if (
            packet["tcp_header"]["source_port"] == self.source_port
            and packet["tcp_header"]["destination_port"] == self.destination_port
            and packet["ip_header"]["source_address"] == self.source_address
            and packet["ip_header"]["destination_address"] == self.destination_address
        ):
            self.packets.append((TCPStream.INBOUND, packet))
            return True

        if (
            packet["tcp_header"]["source_port"] == self.destination_port
            and packet["tcp_header"]["destination_port"] == self.source_port
            and packet["ip_header"]["source_address"] == self.destination_address
            and packet["ip_header"]["destination_address"] == self.source_address
        ):
            self.packets.append((TCPStream.OUTBOUND, packet))
            return True

        return False

    def reassemble(self) -> Optional[Dict[str, Any]]:
        """
        Attempt to reassemble this stream. If this was successful, you should receive a dictionary containing the
        following keys. If it was not successful, you should receive None. When there is overlapping data, packets
        that were received later will take precidence over packets received earlier.

        Returns:
            None - This stream can't be reassembled.
            Dictionary:
                - source_address - A string representing the IPv4 address of the source
                - destination_address - A string representing the IPv4 address of the destination
                - source_port - An integer representing the TCP source address
                - destination_port - An integer representing the TCP destination address
                - inbound - A binary blob representing inbound traffic, reassembled
                - outbound - A binary blob representing outbound traffic, reassembled
        """
        # This is really crude, just make sure that we get a SYN -> SYN/AC -> ACK, then a FIN -> FIN/ACK -> ACK
        state: Dict[str, Dict[str, Optional[str]]] = {
            TCPStream.INBOUND: {
                "syn": None,
                "fin": None,
            },
            TCPStream.OUTBOUND: {
                "syn": None,
                "fin": None,
            },
        }
        sequence = {
            TCPStream.INBOUND: 0,
            TCPStream.OUTBOUND: 0,
        }

        def other_direction(direction: str) -> str:
            if direction == TCPStream.INBOUND:
                return TCPStream.OUTBOUND
            else:
                return TCPStream.INBOUND

        # Crude state machine to ensure that every SYN was ack'd and every FIN was ack'd. Should probably
        # also check that SYNs are ack'd before FINs but whatever, it works well enough for now.
        for packet in self.packets:
            direction = packet[0]
            other = other_direction(direction)
            syn = packet[1]["tcp_header"]["flags"]["syn"]
            fin = packet[1]["tcp_header"]["flags"]["fin"]
            ack = packet[1]["tcp_header"]["flags"]["ack"]
            seq = packet[1]["tcp_header"]["sequence"]

            if syn:
                if state[direction]["syn"] is None:
                    state[direction]["syn"] = "sent"
                    sequence[direction] = seq
            if fin:
                if state[direction]["fin"] is None:
                    state[direction]["fin"] = "sent"
            if ack:
                if state[other]["syn"] == "sent":
                    state[other]["syn"] = "ackd"
                if state[other]["fin"] == "sent":
                    state[other]["fin"] = "ackd"

        if (
            state[TCPStream.INBOUND]["syn"] == "ackd"
            and state[TCPStream.INBOUND]["fin"] == "ackd"
            and state[TCPStream.OUTBOUND]["syn"] == "ackd"
            and state[TCPStream.OUTBOUND]["fin"] == "ackd"
        ):
            # This stream is finished, can be reassembled
            data = {
                TCPStream.INBOUND: b"",
                TCPStream.OUTBOUND: b"",
            }

            def add_data(packet: bytes, data: bytes, offset: int) -> bytes:
                length = len(data)

                if len(packet) < offset:
                    # Pad out, then add
                    packet = packet + b"\0" * (offset - len(packet))
                    return packet + data
                if len(packet) == offset:
                    # Add to end
                    return packet + data
                if len(packet) > offset and len(packet) <= (offset + length):
                    # Truncate, then add
                    packet = packet[:offset]
                    return packet + data
                if len(packet) > (offset + length):
                    before = packet[:offset]
                    after = packet[offset + length :]
                    return before + data + after

                raise Exception("Logic error!")

            for packet in self.packets:
                dir = packet[0]
                syn = packet[1]["tcp_header"]["flags"]["syn"]
                fin = packet[1]["tcp_header"]["flags"]["fin"]
                ack = packet[1]["tcp_header"]["flags"]["ack"]
                seq = packet[1]["tcp_header"]["sequence"]

                if syn:
                    continue

                # Figure out what this packet has
                length = len(packet[1]["data"])
                position = seq - sequence[dir] - 1

                if length > 0:
                    data[dir] = add_data(data[dir], packet[1]["data"], position)

            return {
                "source_address": self.source_address,
                "destination_address": self.destination_address,
                "source_port": self.source_port,
                "destination_port": self.destination_port,
                TCPStream.INBOUND: data[TCPStream.INBOUND],
                TCPStream.OUTBOUND: data[TCPStream.OUTBOUND],
            }

        return None


class Sniffer:
    """
    A generic python sniffer. Listens to all raw traffic on the machine and parses packets
    down to TCP chunks to be reassembled.
    """

    RECEIVE_SIZE: Final[int] = 1048576
    ETH_HEADER_LENGTH: Final[int] = 14
    IP_HEADER_LENGTH: Final[int] = 20
    TCP_HEADER_LENGTH: Final[int] = 20

    def __init__(self, address: Optional[str] = None, port: Optional[int] = None) -> None:
        """
        Initialize the sniffer. Can be told to filter by address, port or both. If address or
        port is not provided, it defaults to all addresses or ports.

        Parameters:
            address - A string representing an IPv4 address to filter on.
            port - An integer representing a port to filter on.
        """
        self.address = address
        self.port = port
        self.streams: List[TCPStream] = []

        self.sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003),
        )

    def __process_ethframe(self, eth_header: bytes) -> Dict[str, Any]:
        """
        Given a raw binary packet, extract the ethernet frame header and return as a dictionary.

        Parameters:
            eth_header - Raw bytes to be parsed, should include at least ETH_HEADER_LENGTH bytes.

        Returns:
            Dictionary:
                - header_length - The actual length in bytes of this header as an integer
                - protocol - An integer representing the protocol encapsulated in this header
        """
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        return {
            "header_length": Sniffer.ETH_HEADER_LENGTH,
            "protocol": eth_protocol,
        }

    def __process_ipframe(self, ip_header: bytes) -> Dict[str, Any]:
        """
        Given a raw binary packet, extract the IP header and return as a dictionary.

        Parameters:
            ip_header - Raw bytes to be parsed, should include at least IP_HEADER_LENGTH bytes.

        Returns:
            Dictionary:
                - header_length - The actual length in bytes of this header as an integer
                - version - Integer IP version, should always be 4
                - length - Integer length of packet including this header
                - ttl - Integer time to live for packet
                - protocol - An integer representing the protocol encapsulated in this header
                - source_address - A string representing the source IPv4 address
                - destination_address - A string representing the destination IPv4 address
        """
        # Extract the 20 bytes IP header, ignoring the IP options
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version = (iph[0] >> 4) & 0xF
        length = iph[2]
        ihl = (iph[0] & 0xF) * 4
        ttl = iph[5]
        proto = iph[6]

        if ihl < Sniffer.IP_HEADER_LENGTH:
            raise InvalidPacketException(
                f"Invalid IP length {ihl}",
            )

        if version != 4:
            raise UnknownPacketException(
                f"Unknown IP version {version}",
            )

        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        return {
            "header_length": ihl,
            "version": version,
            "length": length,
            "ttl": ttl,
            "protocol": proto,
            "source_address": s_addr,
            "destination_address": d_addr,
        }

    def __process_flags(self, flags: int) -> Dict[str, bool]:
        """
        Given an integer bitmask, parse as a TCP flag set, returning a dictionary keyed
        by the flag name who's value is True if set and False otherwise.
        """
        return {
            "ns": bool(flags & 0x100),
            "cwr": bool(flags & 0x080),
            "ece": bool(flags & 0x040),
            "urg": bool(flags & 0x020),
            "ack": bool(flags & 0x010),
            "psh": bool(flags & 0x008),
            "rst": bool(flags & 0x004),
            "syn": bool(flags & 0x002),
            "fin": bool(flags & 0x001),
        }

    def __process_address(self, address: Tuple[int, int, int, int, int]) -> Dict[str, int]:
        """
        Given an address tuple from Linux's recvfrom syscall, return a dict which represents this
        address.

        Parameters:
            address - A tuple as returned by recvfrom()

        Returns:
            Dictionary:
                - interface - The eth interface that this packet was received on
                - protocol - The protocol used to receive this packet
                - type - The packet type, as defined by linux kernel headers
                - hardware_Type - The hardware that received this as an integer
                - address - The hardware address that received this
        """
        return {
            "interface": address[0],
            "protocol": address[1],
            "type": address[2],
            "hardware_type": address[3],
            "address": address[4],
        }

    def __process_tcpframe(self, tcp_header: bytes) -> Dict[str, Any]:
        """
        Given a raw binary packet, extract the TCP header and return as a dictionary.

        Parameters:
            tcp_header - Raw bytes to be parsed, should include at least TCP_HEADER_LENGTH bytes.

        Returns:
            Dictionary:
                - header_length - The actual length in bytes of this header as an integer
                - source_port - An integer representing the source port of this packet
                - destination_port - An integer respresenting the destination port of this packet
                - sequence - An integer representing the current sequence number of this packet
                - acknowledgement - An integer representing the current acknowledgement of this packet
                - flags - A dictionary as defined in Sniffer.__process_flags()
        """
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)

        # Normal stuff
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        tcphl = (tcph[4] >> 4) * 4

        # TCP flags
        flags = ((tcph[4] & 1) << 8) | tcph[5]

        return {
            "header_length": tcphl,
            "source_port": source_port,
            "destination_port": dest_port,
            "sequence": sequence,
            "acknowledgement": acknowledgement,
            "flags": self.__process_flags(flags),
        }

    def __recv_frame(self) -> Dict[str, Any]:
        """
        Grab a packet from the kernel, parse it and return a dictionary representing the parsed
        packet.

        Returns:
            Dictionary:
                - ip_header - A dictionary defined by Sniffer.__process_ipframe()
                - tcp_header - A dictionary defined by Sniffer.__process_tcipframe()
                - data - Raw bytes representing payload of this packet
                - address - A dictionary defined by Sniffer.__process_address()
        """
        # Grab a packet
        packets = self.sock.recvfrom(Sniffer.RECEIVE_SIZE)
        address = self.__process_address(packets[1])
        packet = packets[0]
        offset = 0

        # Make sure its a valid packet
        eth_header = self.__process_ethframe(packet[offset : (offset + Sniffer.ETH_HEADER_LENGTH)])
        offset = offset + eth_header["header_length"]

        if eth_header["protocol"] != 8:
            # Not IP
            raise UnknownPacketException(f'Unknown frame {eth_header["protocol"]}')

        # Get the IP header
        ip_header = self.__process_ipframe(packet[offset : (offset + Sniffer.IP_HEADER_LENGTH)])
        offset = offset + ip_header["header_length"]

        if ip_header["protocol"] != 6:
            # Not TCP
            raise UnknownPacketException(
                f'Unknown protocol {ip_header["protocol"]}',
            )

        # Get TCP header
        tcp_header = self.__process_tcpframe(packet[offset : (offset + Sniffer.TCP_HEADER_LENGTH)])
        offset = offset + tcp_header["header_length"]

        # Get payload length
        payload_length = ip_header["length"] - ip_header["header_length"] - tcp_header["header_length"]

        # Get payload
        data = packet[offset : offset + payload_length]

        return {
            "ip_header": ip_header,
            "tcp_header": tcp_header,
            "data": data,
            "address": address,
        }

    def recv_raw(self) -> Dict[str, Any]:
        """
        Receive the next packet that fits the filter criteria defined by the Sniffer constructor.

        Returns:
            Dictionary defined by Sniffer.__recv_frame()
        """
        while True:
            try:
                packet = self.__recv_frame()
            except UnknownPacketException:
                continue

            # Hack for sniffing on localhost
            if packet["address"]["interface"] == "lo" and packet["address"]["type"] != 4:
                continue

            if self.address and self.port:
                if (
                    packet["ip_header"]["source_address"] == self.address
                    and packet["tcp_header"]["source_port"] == self.port
                ):
                    return packet
                if (
                    packet["ip_header"]["destination_address"] == self.address
                    and packet["tcp_header"]["destination_port"] == self.port
                ):
                    return packet
            elif self.address:
                if (
                    packet["ip_header"]["source_address"] == self.address
                    or packet["ip_header"]["destination_address"] == self.address
                ):
                    return packet
            elif self.port:
                if (
                    packet["tcp_header"]["source_port"] == self.port
                    or packet["tcp_header"]["destination_port"] == self.port
                ):
                    return packet
            else:
                return packet

    def recv_stream(self) -> Dict[str, Any]:
        """
        Receive the next TCP stream that fits the filter criteria defined by the Sniffer constructor.

        Returns:
            Dictionary defined by TCPStream.reassemble()
        """
        while True:
            # Try to reassemble and return a stream
            for i in range(len(self.streams)):
                tcp = self.streams[i].reassemble()

                if tcp:
                    del self.streams[i]
                    return tcp

            # Receive the next packet
            packet = self.recv_raw()

            # Add to the correct stream
            new = True
            for stream in self.streams:
                if stream.add_packet(packet):
                    new = False
                    break

            # See if this is a new TCP stream
            if new:
                self.streams.append(TCPStream(packet))
