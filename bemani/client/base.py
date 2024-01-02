import time
from typing import Optional, Dict, List, Tuple, Any
from typing_extensions import Final

from bemani.client.common import random_hex_string
from bemani.client.protocol import ClientProtocol
from bemani.protocol import Node


class BaseClient:
    """
    The base client that all client emulators subclass from. This includes
    a lot of functionality to create cards, exchange packets, verify responses
    and verify some basic packets that are always expected to work.
    """

    CARD_OK: Final[int] = 0
    CARD_NEW: Final[int] = 112
    CARD_BAD_PIN: Final[int] = 116
    CARD_NOT_ALLOWED: Final[int] = 110

    CORRECT_PASSWORD: Final[str] = "1234"
    WRONG_PASSWORD: Final[str] = "4321"

    def __init__(self, proto: ClientProtocol, pcbid: str, config: Dict[str, Any]) -> None:
        self.__proto = proto
        self.pcbid = pcbid
        self.config = config

    def random_card(self) -> str:
        return "E004" + random_hex_string(12, caps=True)

    def call_node(self) -> Node:
        call = Node.void("call")
        call.set_attribute("model", self.config["model"])
        call.set_attribute("srcid", self.pcbid)
        call.set_attribute("tag", random_hex_string(8))
        return call

    def exchange(self, path: str, tree: Node) -> Node:
        module = tree.children[0].name
        method = tree.children[0].attribute("method")

        return self.__proto.exchange(
            f'{path}?model={self.config["model"]}&module={module}&method={method}',
            tree,
        )

    def __assert_path(self, root: Node, path: str) -> bool:
        parts = path.split("/")
        children = [root]
        node: Optional[Node] = None

        for part in parts:
            if part[0] == "@":
                # Verify attribute, should be last part in chain so
                # assume its the first node
                if node is None:
                    return False
                if part[1:] not in node.attributes:
                    return False
                else:
                    return True
            else:
                # Verify node name, might be last in chain
                found = False
                for child in children:
                    if child.name == part:
                        # This is a valid node, set to children and keep going
                        children = child.children
                        node = child
                        found = True
                        break

                if not found:
                    # Didn't find a noce named this
                    return False

        # Traversed whole chain
        return True

    def assert_path(self, root: Node, path: str) -> None:
        """
        Given a root node and a path string such as a/b/node or a/b/@attr,
        validate that the root node has decendents that match the path.
        As a convenience, you can check an attribute on a node with @attr
        format, where <attr> is the string name of the attribute.
        """

        if not self.__assert_path(root, path):
            raise Exception(f"Path '{path}' not found in root node:\n{root}")

    def verify_services_get(self, expected_services: List[str] = [], include_net: bool = False) -> None:
        call = self.call_node()

        # Construct node
        services = Node.void("services")
        call.add_child(services)
        services.set_attribute("method", "get")

        if self.config["avs"] is not None:
            # Some older games don't include this info
            info = Node.void("info")
            services.add_child(info)

            info.add_child(Node.string("AVS2", self.config["avs"]))

        if include_net:
            net = Node.void("net")
            services.add_child(net)
            iface = Node.void("if")
            net.add_child(iface)
            iface.add_child(Node.u8("id", 0))
            iface.add_child(Node.bool("valid", True))
            iface.add_child(Node.u8("type", 1))
            iface.add_child(Node.u8_array("mac", [1, 2, 3, 4, 5, 6]))
            iface.add_child(Node.ipv4("addr", "10.0.0.100"))
            iface.add_child(Node.ipv4("bcast", "10.0.0.255"))
            iface.add_child(Node.ipv4("netmask", "255.255.255.0"))
            iface.add_child(Node.ipv4("gateway", "10.0.0.1"))
            iface.add_child(Node.ipv4("dhcp", "10.0.0.1"))

        # Swap with server
        resp = self.exchange("core/services", call)

        # Verify that response is correct
        self.assert_path(resp, "response/services")
        items = resp.child("services").children

        returned_services = []
        for item in items:
            # Make sure it is an item with a url component
            self.assert_path(item, "item/@url")

            # Get list of services provided
            returned_services.append(item.attribute("name"))

        for service in expected_services:
            if service not in returned_services:
                raise Exception(f"Service '{service}' expected but not returned")

    def verify_pcbtracker_alive(self, ecflag: int = 1) -> bool:
        call = self.call_node()

        # Construct node
        pcbtracker = Node.void("pcbtracker")
        call.add_child(pcbtracker)
        pcbtracker.set_attribute("accountid", self.pcbid)
        pcbtracker.set_attribute("ecflag", str(ecflag))
        pcbtracker.set_attribute("hardid", "01000027584F6D3A")
        pcbtracker.set_attribute("method", "alive")
        pcbtracker.set_attribute("softid", "00010203040506070809")

        # Swap with server
        resp = self.exchange("core/pcbtracker", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcbtracker/@ecenable")

        # Print out setting
        enable = int(resp.child("pcbtracker").attribute("ecenable"))
        if enable != 0:
            return True
        return False

    def verify_message_get(self) -> None:
        call = self.call_node()

        # Construct node
        message = Node.void("message")
        call.add_child(message)
        message.set_attribute("method", "get")

        # Swap with server
        resp = self.exchange("core/message", call)

        # Verify that response is correct
        self.assert_path(resp, "response/message/@status")

    def verify_dlstatus_progress(self) -> None:
        call = self.call_node()

        # Construct node
        dlstatus = Node.void("dlstatus")
        call.add_child(dlstatus)
        dlstatus.set_attribute("method", "progress")
        dlstatus.add_child(Node.s32("progress", 0))

        # Swap with server
        resp = self.exchange("core/dlstatus", call)

        # Verify that response is correct
        self.assert_path(resp, "response/dlstatus/@status")

    def verify_package_list(self) -> None:
        call = self.call_node()

        # Construct node
        package = Node.void("package")
        call.add_child(package)
        package.set_attribute("method", "list")
        package.set_attribute("pkgtype", "all")

        # Swap with server
        resp = self.exchange("core/package", call)

        # Verify that response is correct
        self.assert_path(resp, "response/package")

    def verify_facility_get(self, encoding: str = "SHIFT_JIS") -> str:
        call = self.call_node()

        # Construct node
        facility = Node.void("facility")
        call.add_child(facility)
        facility.set_attribute("encoding", encoding)
        facility.set_attribute("method", "get")

        # Swap with server
        resp = self.exchange("core/facility", call)

        # Verify that response is correct
        self.assert_path(resp, "response/facility/location/id")
        self.assert_path(resp, "response/facility/line")
        self.assert_path(resp, "response/facility/portfw")
        self.assert_path(resp, "response/facility/public")
        self.assert_path(resp, "response/facility/share")

        return resp.child_value("facility/location/id")

    def verify_pcbevent_put(self) -> None:
        call = self.call_node()

        # Construct node
        pcbevent = Node.void("pcbevent")
        call.add_child(pcbevent)
        pcbevent.set_attribute("method", "put")
        pcbevent.add_child(Node.time("time", int(time.time())))
        pcbevent.add_child(Node.u32("seq", 0))

        item = Node.void("item")
        pcbevent.add_child(item)
        item.add_child(Node.string("name", "boot"))
        item.add_child(Node.s32("value", 1))
        item.add_child(Node.time("time", int(time.time())))

        # Swap with server
        resp = self.exchange("core/pcbevent", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcbevent")

    def verify_cardmng_inquire(self, card_id: str, msg_type: str, paseli_enabled: bool) -> Optional[str]:
        call = self.call_node()

        # Construct node
        cardmng = Node.void("cardmng")
        call.add_child(cardmng)
        cardmng.set_attribute("cardid", card_id)
        cardmng.set_attribute("cardtype", "1")
        cardmng.set_attribute("method", "inquire")
        cardmng.set_attribute("update", "0")
        if msg_type == "new" and "old_profile_model" in self.config:
            cardmng.set_attribute("model", self.config["old_profile_model"])

        # Swap with server
        resp = self.exchange("core/cardmng", call)

        if msg_type == "unregistered":
            # Verify that response is correct
            self.assert_path(resp, "response/cardmng/@status")

            # Verify that we weren't found
            status = int(resp.child("cardmng").attribute("status"))
            if status != self.CARD_NEW:
                raise Exception(f"Card '{card_id}' returned invalid status '{status}'")

            # Nothing to return
            return None
        elif msg_type == "new":
            # Verify that response is correct
            self.assert_path(resp, "response/cardmng/@refid")
            self.assert_path(resp, "response/cardmng/@binded")
            self.assert_path(resp, "response/cardmng/@newflag")
            self.assert_path(resp, "response/cardmng/@ecflag")

            binded = int(resp.child("cardmng").attribute("binded"))
            newflag = int(resp.child("cardmng").attribute("newflag"))
            ecflag = int(resp.child("cardmng").attribute("ecflag"))

            if binded != 0:
                raise Exception(f"Card '{card_id}' returned invalid binded value '{binded}'")
            if newflag != 1:
                raise Exception(f"Card '{card_id}' returned invalid newflag value '{newflag}'")
            if ecflag != (1 if paseli_enabled else 0):
                raise Exception(f"Card '{card_id}' returned invalid ecflag value '{newflag}'")

            # Return the refid
            return resp.child("cardmng").attribute("refid")
        elif msg_type == "query":
            # Verify that response is correct
            self.assert_path(resp, "response/cardmng/@refid")
            self.assert_path(resp, "response/cardmng/@binded")
            self.assert_path(resp, "response/cardmng/@newflag")
            self.assert_path(resp, "response/cardmng/@ecflag")

            binded = int(resp.child("cardmng").attribute("binded"))
            newflag = int(resp.child("cardmng").attribute("newflag"))
            ecflag = int(resp.child("cardmng").attribute("ecflag"))

            if binded != 1:
                raise Exception(f"Card '{card_id}' returned invalid binded value '{binded}'")
            if newflag != 0:
                raise Exception(f"Card '{card_id}' returned invalid newflag value '{newflag}'")
            if ecflag != (1 if paseli_enabled else 0):
                raise Exception(f"Card '{card_id}' returned invalid ecflag value '{newflag}'")

            # Return the refid
            return resp.child("cardmng").attribute("refid")
        else:
            raise Exception(f"Unrecognized message type '{msg_type}'")

    def verify_cardmng_getrefid(self, card_id: str) -> str:
        call = self.call_node()

        # Construct node
        cardmng = Node.void("cardmng")
        call.add_child(cardmng)
        cardmng.set_attribute("cardid", card_id)
        cardmng.set_attribute("cardtype", "1")
        cardmng.set_attribute("method", "getrefid")
        cardmng.set_attribute("newflag", "0")
        cardmng.set_attribute("passwd", self.CORRECT_PASSWORD)

        # Swap with server
        resp = self.exchange("core/cardmng", call)

        # Verify that response is correct
        self.assert_path(resp, "response/cardmng/@refid")

        return resp.child("cardmng").attribute("refid")

    def verify_cardmng_authpass(self, ref_id: str, correct: bool) -> None:
        call = self.call_node()

        # Construct node
        cardmng = Node.void("cardmng")
        call.add_child(cardmng)
        cardmng.set_attribute("method", "authpass")
        cardmng.set_attribute("pass", self.CORRECT_PASSWORD if correct else self.CORRECT_PASSWORD[::-1])
        cardmng.set_attribute("refid", ref_id)

        # Swap with server
        resp = self.exchange("core/cardmng", call)

        # Verify that response is correct
        self.assert_path(resp, "response/cardmng/@status")

        status = int(resp.child("cardmng").attribute("status"))
        if status != (self.CARD_OK if correct else self.CARD_BAD_PIN):
            raise Exception(f"Ref ID '{ref_id}' returned invalid status '{status}'")

    def verify_eacoin_checkin(self, card_id: str) -> Tuple[str, int]:
        call = self.call_node()

        # Construct node
        eacoin = Node.void("eacoin")
        call.add_child(eacoin)
        eacoin.set_attribute("method", "checkin")
        eacoin.add_child(Node.string("cardtype", "1"))
        eacoin.add_child(Node.string("cardid", card_id))
        eacoin.add_child(Node.string("passwd", self.CORRECT_PASSWORD))
        eacoin.add_child(Node.string("ectype", "1"))

        # Swap with server
        resp = self.exchange("core/eacoin", call)

        # Verify that response is correct
        self.assert_path(resp, "response/eacoin/sessid")
        self.assert_path(resp, "response/eacoin/balance")

        return (
            resp.child("eacoin").child_value("sessid"),
            resp.child("eacoin").child_value("balance"),
        )

    def verify_eacoin_consume(self, sessid: str, balance: int, amount: int) -> None:
        call = self.call_node()

        # Construct node
        eacoin = Node.void("eacoin")
        call.add_child(eacoin)
        eacoin.set_attribute("method", "consume")
        eacoin.add_child(Node.string("sessid", sessid))
        eacoin.add_child(Node.s16("sequence", 0))
        eacoin.add_child(Node.s32("payment", amount))
        eacoin.add_child(Node.s32("service", 0))
        eacoin.add_child(Node.string("itemtype", "0"))
        eacoin.add_child(Node.string("detail", "/eacoin/start_pt1"))

        # Swap with server
        resp = self.exchange("core/eacoin", call)

        # Verify that response is correct
        self.assert_path(resp, "response/eacoin/balance")

        newbalance = resp.child("eacoin").child_value("balance")
        if balance - amount != newbalance:
            raise Exception(f"Expected to get back balance {balance - amount} but got {newbalance}")

    def verify_eacoin_checkout(self, session: str) -> None:
        call = self.call_node()

        # Construct node
        eacoin = Node.void("eacoin")
        call.add_child(eacoin)
        eacoin.set_attribute("method", "checkout")
        eacoin.add_child(Node.string("sessid", session))

        # Swap with server
        resp = self.exchange("core/eacoin", call)

        # Verify that response is correct
        self.assert_path(resp, "response/eacoin/@status")

    def verify(self, cardid: Optional[str]) -> None:
        raise Exception("Override in subclass!")
