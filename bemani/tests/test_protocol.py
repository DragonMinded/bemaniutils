# vim: set fileencoding=utf-8
import unittest

from bemani.protocol import EAmuseProtocol, Node


class TestProtocol(unittest.TestCase):
    # Define a function that just encrypts/decrypts and encode/decodes, verify
    # that we can get the same thing back.
    def assertLoopback(self, root: Node) -> None:
        proto = EAmuseProtocol()

        for encoding in [
            EAmuseProtocol.BINARY,
            EAmuseProtocol.BINARY_DECOMPRESSED,
            EAmuseProtocol.XML,
        ]:
            if encoding == EAmuseProtocol.BINARY:
                loop_name = "binary"
            elif encoding == EAmuseProtocol.BINARY_DECOMPRESSED:
                loop_name = "decompressed binary"
            elif encoding == EAmuseProtocol.XML:
                loop_name = "xml"
            else:
                raise Exception("Logic error!")

            binary = proto.encode(
                None,
                None,
                root,
                text_encoding=EAmuseProtocol.SHIFT_JIS,
                packet_encoding=encoding,
            )
            newroot = proto.decode(None, None, binary)
            self.assertEqual(
                newroot,
                root,
                f"Round trip with {loop_name} and no encryption/compression doesn't match!",
            )

            binary = proto.encode(
                None,
                "1-abcdef-0123",
                root,
                text_encoding=EAmuseProtocol.SHIFT_JIS,
                packet_encoding=encoding,
            )
            newroot = proto.decode(None, "1-abcdef-0123", binary)
            self.assertEqual(
                newroot,
                root,
                f"Round trip with {loop_name}, encryption and no compression doesn't match!",
            )

            binary = proto.encode(
                "none",
                None,
                root,
                text_encoding=EAmuseProtocol.SHIFT_JIS,
                packet_encoding=encoding,
            )
            newroot = proto.decode("none", None, binary)
            self.assertEqual(
                newroot,
                root,
                f"Round trip with {loop_name}, encryption and no compression doesn't match!",
            )

            binary = proto.encode(
                "lz77",
                None,
                root,
                text_encoding=EAmuseProtocol.SHIFT_JIS,
                packet_encoding=encoding,
            )
            newroot = proto.decode("lz77", None, binary)
            self.assertEqual(
                newroot,
                root,
                f"Round trip with {loop_name}, no encryption and lz77 compression doesn't match!",
            )

    def test_game_packet1(self) -> None:
        root = Node.void("call")
        root.set_attribute("model", "M39:J:B:A:2014061900")
        root.set_attribute("srcid", "012010000000DEADBEEF")
        root.set_attribute("tag", "1d0cbcd5")

        pcbevent = Node.void("pcbevent")
        root.add_child(pcbevent)
        pcbevent.set_attribute("method", "put")

        pcbevent.add_child(Node.time("time", 1438375918))
        pcbevent.add_child(Node.u32("seq", value=0))

        item = Node.void("item")
        pcbevent.add_child(item)

        item.add_child(Node.string("name", "boot"))
        item.add_child(Node.s32("value", 1))
        item.add_child(Node.time("time", 1438375959))

        self.assertLoopback(root)

    def test_game_packet2(self) -> None:
        root = Node.void("call")
        root.set_attribute("model", "LDJ:A:A:A:2015060700")
        root.set_attribute("srcid", "012010000000DEADBEEF")
        root.set_attribute("tag", "9yU+HH4q")

        eacoin = Node.void("eacoin")
        root.add_child(eacoin)
        eacoin.set_attribute("esdate", "2015-08-01T02:09:23")
        eacoin.set_attribute(
            "esid", "177baae4bdf0085f1f3da9b6fed02223ee9b482f62b83a28af704a9c7893a370"
        )
        eacoin.set_attribute("method", "consume")

        eacoin.add_child(Node.string("sessid", "5666-5524"))
        eacoin.add_child(Node.s16("sequence", 0))
        eacoin.add_child(Node.s32("payment", 420))
        eacoin.add_child(Node.s32("service", 0))
        eacoin.add_child(Node.string("itemtype", "0"))
        eacoin.add_child(Node.string("detail", "/eacoin/premium_free_1p_3"))

        self.assertLoopback(root)

    def test_game_packet3(self) -> None:
        root = Node.void("response")
        root.add_child(Node.void("music"))

        self.assertLoopback(root)

    def test_game_packet4(self) -> None:
        root = Node.void("response")
        game = Node.void("game")
        root.add_child(game)
        game.set_attribute("image_no", "1")
        game.set_attribute("no", "1")

        game.add_child(Node.s32("ir_phase", 0))

        game.add_child(Node.s32("personal_event_phase", 10))
        game.add_child(Node.s32("shop_event_phase", 6))
        game.add_child(Node.s32("netvs_phase", 0))
        game.add_child(Node.s32("card_phase", 9))
        game.add_child(Node.s32("other_phase", 9))
        game.add_child(Node.s32("music_open_phase", 8))
        game.add_child(Node.s32("collabo_phase", 8))
        game.add_child(Node.s32("local_matching_enable", 1))
        game.add_child(Node.s32("n_maching_sec", 60))
        game.add_child(Node.s32("l_matching_sec", 60))
        game.add_child(Node.s32("is_check_cpu", 0))
        game.add_child(Node.s32("week_no", 0))
        game.add_child(Node.s16_array("sel_ranking", [-1, -1, -1, -1, -1]))
        game.add_child(Node.s16_array("up_ranking", [-1, -1, -1, -1, -1]))

        self.assertLoopback(root)

    def test_game_packet5(self) -> None:
        root = Node.void("call")
        root.set_attribute("model", "LDJ:A:A:A:2015060700")
        root.set_attribute("srcid", "012010000000DEADBEEF")
        root.set_attribute("tag", "9yU+HH4q")

        iidx22pc = Node.void("IIDX22pc")
        root.add_child(iidx22pc)
        iidx22pc.set_attribute("bookkeep", "0")
        iidx22pc.set_attribute("cltype", "0")
        iidx22pc.set_attribute("d_achi", "0")
        iidx22pc.set_attribute("d_disp_judge", "0")
        iidx22pc.set_attribute("d_exscore", "0")
        iidx22pc.set_attribute("d_gno", "0")
        iidx22pc.set_attribute("d_gtype", "0")
        iidx22pc.set_attribute("d_hispeed", "0.000000")
        iidx22pc.set_attribute("d_judge", "0")
        iidx22pc.set_attribute("d_judgeAdj", "-3")
        iidx22pc.set_attribute("d_largejudge", "0")
        iidx22pc.set_attribute("d_lift", "0")
        iidx22pc.set_attribute("d_notes", "0.000000")
        iidx22pc.set_attribute("d_opstyle", "0")
        iidx22pc.set_attribute("d_pace", "0")
        iidx22pc.set_attribute("d_sdlen", "0")
        iidx22pc.set_attribute("d_sdtype", "0")
        iidx22pc.set_attribute("d_sorttype", "0")
        iidx22pc.set_attribute("d_timing", "0")
        iidx22pc.set_attribute("d_tune", "0")
        iidx22pc.set_attribute("dp_opt", "0")
        iidx22pc.set_attribute("dp_opt2", "0")
        iidx22pc.set_attribute("gpos", "0")
        iidx22pc.set_attribute("iidxid", "56665524")
        iidx22pc.set_attribute("lid", "US-3")
        iidx22pc.set_attribute("method", "save")
        iidx22pc.set_attribute("mode", "6")
        iidx22pc.set_attribute("pmode", "0")
        iidx22pc.set_attribute("rtype", "0")
        iidx22pc.set_attribute("s_achi", "4428")
        iidx22pc.set_attribute("s_disp_judge", "1")
        iidx22pc.set_attribute("s_exscore", "0")
        iidx22pc.set_attribute("s_gno", "1")
        iidx22pc.set_attribute("s_gtype", "2")
        iidx22pc.set_attribute("s_hispeed", "2.302647")
        iidx22pc.set_attribute("s_judge", "0")
        iidx22pc.set_attribute("s_judgeAdj", "-3")
        iidx22pc.set_attribute("s_largejudge", "0")
        iidx22pc.set_attribute("s_lift", "60")
        iidx22pc.set_attribute("s_notes", "29.483595")
        iidx22pc.set_attribute("s_opstyle", "1")
        iidx22pc.set_attribute("s_pace", "0")
        iidx22pc.set_attribute("s_sdlen", "203")
        iidx22pc.set_attribute("s_sdtype", "1")
        iidx22pc.set_attribute("s_sorttype", "0")
        iidx22pc.set_attribute("s_timing", "2")
        iidx22pc.set_attribute("s_tune", "5")
        iidx22pc.set_attribute("sp_opt", "8194")

        pyramid = Node.void("pyramid")
        pyramid.set_attribute("point", "408")
        iidx22pc.add_child(pyramid)

        achievements = Node.void("achievements")
        iidx22pc.add_child(achievements)
        achievements.set_attribute("last_weekly", "0")
        achievements.set_attribute("pack_comp", "0")
        achievements.set_attribute("pack_flg", "0")
        achievements.set_attribute("pack_id", "349")
        achievements.set_attribute("play_pack", "0")
        achievements.set_attribute("visit_flg", "1125899906842624")
        achievements.set_attribute("weekly_num", "0")

        achievements.add_child(
            Node.s64_array(
                "trophy",
                [
                    648333697107365824,
                    120628451491823,
                    281475567654912,
                    0,
                    1069547520,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1125899906842624,
                    4294967296,
                    60348585478096,
                    1498943592322,
                    0,
                    256,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    -4294967296,
                    0,
                    0,
                    4294967704,
                    858608469,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    5,
                    2,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        deller = Node.void("deller")
        iidx22pc.add_child(deller)
        deller.set_attribute("deller", "450")

        self.assertLoopback(root)

    def test_game_packet6(self) -> None:
        root = Node.void("response")
        facility = Node.void("facility")
        root.add_child(facility)

        location = Node.void("location")
        facility.add_child(location)

        location.add_child(Node.string("id", "US-6"))
        location.add_child(Node.string("country", "US"))
        location.add_child(Node.string("region", "."))
        location.add_child(Node.string("name", ""))
        location.add_child(Node.u8("type", 0))

        line = Node.void("line")
        facility.add_child(line)

        line.add_child(Node.string("id", "."))
        line.add_child(Node.u8("class", 0))

        portfw = Node.void("portfw")
        facility.add_child(portfw)

        portfw.add_child(Node.ipv4("globalip", "10.0.0.1"))
        portfw.add_child(Node.u16("globalport", 20000))
        portfw.add_child(Node.u16("privateport", 20000))

        public = Node.void("public")
        facility.add_child(public)

        public.add_child(Node.u8("flag", 1))
        public.add_child(Node.string("name", "."))
        public.add_child(Node.string("latitude", "0"))
        public.add_child(Node.string("longitude", "0"))

        share = Node.void("share")
        facility.add_child(share)

        eacoin = Node.void("eacoin")
        share.add_child(eacoin)

        eacoin.add_child(Node.s32("notchamount", 0))
        eacoin.add_child(Node.s32("notchcount", 0))
        eacoin.add_child(Node.s32("supplylimit", 1000000))

        url = Node.void("url")
        share.add_child(url)

        url.add_child(Node.string("eapass", "http://some.dummy.net/"))
        url.add_child(Node.string("arcadefan", "http://some.dummy.net/"))
        url.add_child(Node.string("konaminetdx", "http://some.dummy.net/"))
        url.add_child(Node.string("konamiid", "http://some.dummy.net/"))
        url.add_child(Node.string("eagate", "http://some.dummy.net/"))

        self.assertLoopback(root)

    def test_packet1(self) -> None:
        root = Node.void("test")
        root.set_attribute("test", "test string value")

        # Regular nodes
        root.add_child(Node.void("void_node"))
        root.add_child(Node.s8("s8_node", -1))
        root.add_child(Node.u8("u8_node", 245))
        root.add_child(Node.s16("s16_node", -8000))
        root.add_child(Node.u16("u16_node", 65000))
        root.add_child(Node.s32("s32_node", -2000000000))
        root.add_child(Node.u32("u32_node", 4000000000))
        root.add_child(Node.s64("s64_node", -1234567890000))
        root.add_child(Node.u64("u64_node", 1234567890000))
        root.add_child(Node.binary("bin_node", b"DEADBEEF"))
        root.add_child(Node.string("str_node", "this is a string!"))
        root.add_child(Node.ipv4("ip4_node", "192.168.1.24"))
        root.add_child(Node.time("time_node", 1234567890))
        root.add_child(Node.float("float_node", 2.5))
        root.add_child(Node.fouru8("4u8_node", [0x20, 0x21, 0x22, 0x23]))
        root.add_child(Node.bool("bool_true_node", True))
        root.add_child(Node.bool("bool_false_node", False))

        # Array nodes
        root.add_child(Node.s8_array("s8_array_node", [-1, -2, 3, 4, -5]))
        root.add_child(Node.u8_array("u8_array_node", [245, 2, 0, 255, 1]))
        root.add_child(Node.s16_array("s16_array_node", [-8000, 8000]))
        root.add_child(Node.u16_array("u16_array_node", [65000, 1, 2, 65535]))
        root.add_child(Node.s32_array("s32_array_node", [-2000000000, -1]))
        root.add_child(Node.u32_array("u32_array_node", [4000000000, 0, 1, 2]))
        root.add_child(Node.s64_array("s64_array_node", [-1234567890000, -1, 1, 1337]))
        root.add_child(
            Node.u64_array("u64_array_node", [1234567890000, 123, 456, 7890])
        )
        root.add_child(Node.time_array("time_array_node", [1234567890, 98765432]))
        root.add_child(Node.float_array("float_array_node", [2.5, 0.0, 5.0, 20.5]))
        root.add_child(Node.bool_array("bool_array_node", [False, True, True, False]))

        # XML escaping
        escape = Node.string(
            "escape_test",
            "\r\n<testing> & 'thing' \"thing\" \r\nthing on new line\r\n    ",
        )
        escape.set_attribute("test", "<testing> & 'thing' \"thing\" \r\n thing")
        root.add_child(escape)

        # Unicode
        unicode_node = Node.string("unicode", "今日は")
        unicode_node.set_attribute("unicode_attr", "わたし")
        root.add_child(unicode_node)

        self.assertLoopback(root)
