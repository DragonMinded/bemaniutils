import socket

from bemani.backend.base import Base
from bemani.protocol import Node
from bemani.common import ID, RegionConstants


class CoreHandler(Base):
    """
    Implements the core packets that are shared across all games.
    """

    def handle_services_get_request(self, request: Node) -> Node:
        """
        Handles a game request for services.get. This should return the URL of
        each server which handles a particular service. For us, this is always
        our URL since we serve everything.
        """

        def item(name: str, url: str) -> Node:
            node = Node.void("item")
            node.set_attribute("name", name)
            node.set_attribute("url", url)
            return node

        url = f'{"https" if self.config.server.https else "http"}://{self.config.server.address}:{self.config.server.port}/'
        root = Node.void("services")
        root.set_attribute("expire", "600")
        # This can be set to 'operation', 'debug', 'test', and 'factory'.
        root.set_attribute("mode", "operation")
        root.set_attribute("product_domain", "1")

        root.add_child(item("cardmng", url))
        root.add_child(item("dlstatus", url))
        root.add_child(item("eacoin", url))
        root.add_child(item("facility", url))
        root.add_child(item("lobby", url))
        root.add_child(item("local", url))
        root.add_child(item("message", url))
        root.add_child(item("package", url))
        root.add_child(item("pcbevent", url))
        root.add_child(item("pcbtracker", url))
        root.add_child(item("pkglist", url))
        root.add_child(item("posevent", url))
        for srv in self.extra_services:
            root.add_child(item(srv, url))

        root.add_child(item("ntp", "ntp://pool.ntp.org/"))

        # Translate keepalive to a raw IP because we can't give out a host here
        keepalive = socket.gethostbyname(self.config.server.keepalive)
        root.add_child(
            item(
                "keepalive",
                f"http://{keepalive}/core/keepalive?pa={keepalive}&ia={keepalive}&ga={keepalive}&ma={keepalive}&t1=2&t2=10",
            )
        )
        return root

    def handle_pcbtracker_alive_request(self, request: Node) -> Node:
        """
        Handle a PCBTracker.alive request. The only method of note is the 'alive' method
        which returns whether PASELI should be active or not for this session.
        """
        # Reports that a machine is booting. Overloaded to enable/disable paseli
        root = Node.void("pcbtracker")
        root.set_attribute(
            "ecenable",
            "1" if (self.supports_paseli and self.config.paseli.enabled) else "0",
        )
        root.set_attribute("expire", "600")
        return root

    def handle_pcbevent_put_request(self, request: Node) -> Node:
        """
        Handle a PCBEvent request. We do nothing for this aside from logging the event.
        """
        for item in request.children:
            if item.name == "item":
                name = item.child_value("name")
                value = item.child_value("value")
                timestamp = item.child_value("time")
                self.data.local.network.put_event(
                    "pcbevent",
                    {
                        "name": name,
                        "value": value,
                        "model": str(self.model),
                        "pcbid": self.config.machine.pcbid,
                        "ip": self.config.client.address,
                    },
                    timestamp=timestamp,
                )

        return Node.void("pcbevent")

    def handle_package_list_request(self, request: Node) -> Node:
        """
        Handle a Package request. This is for supporting downloading of updates.
        We don't support this at the moment.
        """
        # List all available update packages on the server
        root = Node.void("package")
        root.set_attribute("expire", "600")
        return root

    def handle_message_get_request(self, request: Node) -> Node:
        """
        I have absolutely no fucking idea what this does, but it might be for
        operator messages?
        """
        root = Node.void("message")
        root.set_attribute("expire", "600")
        return root

    def handle_dlstatus_progress_request(self, request: Node) -> Node:
        """
        I have absolutely no fucking idea what this does either, download
        status reports maybe?
        """
        return Node.void("dlstatus")

    def handle_facility_get_request(self, request: Node) -> Node:
        """
        Handle a facility request. The only method of note is the 'get' request,
        which expects to return a bunch of information about the arcade this
        cabinet is in, as well as some settings for URLs and the name of the cab.
        """
        machine = self.get_machine()
        if machine.arcade is None:
            region = self.config.server.region
            area = self.config.server.area
        else:
            arcade = self.data.local.machine.get_arcade(machine.arcade)
            region = arcade.region
            area = arcade.area

        if region == RegionConstants.HONG_KONG:
            country = "HK"
            regionstr = ""
        elif region == RegionConstants.TAIWAN:
            country = "TW"
            regionstr = ""
        elif region == RegionConstants.KOREA:
            country = "KR"
            regionstr = ""
        elif region == RegionConstants.USA:
            country = "US"
            regionstr = ""
        elif region == RegionConstants.THAILAND:
            country = "TH"
            regionstr = ""
        elif region == RegionConstants.INDONESIA:
            country = "ID"
            regionstr = ""
        elif region == RegionConstants.SINGAPORE:
            country = "SG"
            regionstr = ""
        elif region == RegionConstants.PHILLIPINES:
            country = "PH"
            regionstr = ""
        elif region == RegionConstants.MACAO:
            country = "MO"
            regionstr = ""
        elif region >= RegionConstants.MIN_PREF and region <= RegionConstants.MAX_PREF:
            country = "JP"
            regionstr = f"JP-{region}"
        elif region == RegionConstants.EUROPE:
            # Pick a random country in the "Europe" category.
            country = "GB"
            regionstr = ""
        else:
            # Pick a random nonsensical code.
            country = "XX"
            regionstr = ""

        root = Node.void("facility")
        root.set_attribute("expire", "600")
        location = Node.void("location")
        location.add_child(Node.string("id", ID.format_machine_id(machine.id, region=country)))
        location.add_child(Node.string("country", country))
        location.add_child(Node.string("region", regionstr))
        location.add_child(Node.string("name", machine.name))
        location.add_child(Node.u8("type", 0))
        if area is not None:
            location.add_child(Node.string("regionname", area))
            location.add_child(Node.string("regionjname", area))

        line = Node.void("line")
        line.add_child(Node.string("id", "."))
        line.add_child(Node.u8("class", 0))

        portfw = Node.void("portfw")
        portfw.add_child(Node.ipv4("globalip", self.config.client.address))
        portfw.add_child(Node.u16("globalport", machine.port))
        portfw.add_child(Node.u16("privateport", machine.port))

        public = Node.void("public")
        public.add_child(Node.u8("flag", 1))
        public.add_child(Node.string("name", "."))
        public.add_child(Node.string("latitude", "0"))
        public.add_child(Node.string("longitude", "0"))

        share = Node.void("share")
        eacoin = Node.void("eacoin")
        eacoin.add_child(Node.s32("notchamount", 3000))
        eacoin.add_child(Node.s32("notchcount", 3))
        eacoin.add_child(Node.s32("supplylimit", 10000))

        eapass = Node.void("eapass")
        eapass.add_child(Node.u16("valid", 365))

        url = Node.void("url")
        url.add_child(Node.string("eapass", self.config.server.uri or "www.ea-pass.konami.net"))
        url.add_child(Node.string("arcadefan", self.config.server.uri or "www.konami.jp/am"))
        url.add_child(Node.string("konaminetdx", self.config.server.uri or "http://am.573.jp"))
        url.add_child(Node.string("konamiid", self.config.server.uri or "https://id.konami.net"))
        url.add_child(Node.string("eagate", self.config.server.uri or "http://eagate.573.jp"))

        share.add_child(eacoin)
        share.add_child(url)
        share.add_child(eapass)
        root.add_child(location)
        root.add_child(line)
        root.add_child(portfw)
        root.add_child(public)
        root.add_child(share)
        return root
