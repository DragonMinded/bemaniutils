import base64
import random
import time
from typing import Optional, Dict, List, Tuple, Any

from bemani.client.base import BaseClient
from bemani.common import ID, Time
from bemani.protocol import Node


def b64str(string: str) -> str:
    return base64.b64encode(string.encode()).decode("ascii")


class DDRAceClient(BaseClient):
    NAME = "TEST"

    def verify_eventlog_write(self, location: str) -> None:
        call = self.call_node()

        # Construct node
        eventlog = Node.void("eventlog")
        call.add_child(eventlog)
        eventlog.set_attribute("method", "write")
        eventlog.add_child(Node.u32("retrycnt", 0))
        data = Node.void("data")
        eventlog.add_child(data)
        data.add_child(Node.string("eventid", "S_PWRON"))
        data.add_child(Node.s32("eventorder", 0))
        data.add_child(Node.u64("pcbtime", int(time.time() * 1000)))
        data.add_child(Node.s64("gamesession", -1))
        data.add_child(Node.string("strdata1", b64str("2.4.0")))
        data.add_child(Node.string("strdata2", ""))
        data.add_child(Node.s64("numdata1", 1))
        data.add_child(Node.s64("numdata2", 0))
        data.add_child(Node.string("locationid", location))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/eventlog/gamesession")
        self.assert_path(resp, "response/eventlog/logsendflg")
        self.assert_path(resp, "response/eventlog/logerrlevel")
        self.assert_path(resp, "response/eventlog/evtidnosendflg")

    def verify_system_convcardnumber(self, cardno: str) -> None:
        call = self.call_node()

        # Construct node
        system = Node.void("system")
        call.add_child(system)
        system.set_attribute("method", "convcardnumber")
        info = Node.void("info")
        system.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        system.add_child(data)
        data.add_child(Node.string("card_id", cardno))
        data.add_child(Node.s32("card_type", 1))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/system/data/card_number")
        self.assert_path(resp, "response/system/result")

    def verify_playerdata_usergamedata_advanced_usernew(self, refid: str) -> int:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_advanced")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("mode", "usernew"))
        data.add_child(Node.string("shoparea", "."))
        data.add_child(Node.s64("gamesession", 123456))
        data.add_child(Node.string("refid", refid))
        data.add_child(Node.string("dataid", refid))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.string("pcbid", self.pcbid))
        data.add_child(Node.void("record"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/playerdata/seq")
        self.assert_path(resp, "response/playerdata/code")
        self.assert_path(resp, "response/playerdata/shoparea")
        self.assert_path(resp, "response/playerdata/result")

        return resp.child_value("playerdata/code")

    def verify_playerdata_usergamedata_advanced_ghostload(self, refid: str, ghostid: int) -> Dict[str, Any]:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_advanced")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("mode", "ghostload"))
        data.add_child(Node.s32("ghostid", ghostid))
        data.add_child(Node.s64("gamesession", 123456))
        data.add_child(Node.string("refid", refid))
        data.add_child(Node.string("dataid", refid))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.string("pcbid", self.pcbid))
        data.add_child(Node.void("record"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/playerdata/ghostdata/code")
        self.assert_path(resp, "response/playerdata/ghostdata/mcode")
        self.assert_path(resp, "response/playerdata/ghostdata/notetype")
        self.assert_path(resp, "response/playerdata/ghostdata/ghostsize")
        self.assert_path(resp, "response/playerdata/ghostdata/ghost")

        return {
            "extid": resp.child_value("playerdata/ghostdata/code"),
            "id": resp.child_value("playerdata/ghostdata/mcode"),
            "chart": resp.child_value("playerdata/ghostdata/notetype"),
            "ghost": resp.child_value("playerdata/ghostdata/ghost"),
        }

    def verify_playerdata_usergamedata_advanced_rivalload(self, refid: str, loadflag: int) -> None:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_advanced")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("mode", "rivalload"))
        data.add_child(Node.u64("targettime", Time.now() * 1000))
        data.add_child(Node.string("shoparea", "."))
        data.add_child(Node.bool("isdouble", False))
        data.add_child(Node.s32("loadflag", loadflag))
        data.add_child(Node.s32("ddrcode", 0))
        data.add_child(Node.s64("gamesession", 123456))
        data.add_child(Node.string("refid", refid))
        data.add_child(Node.string("dataid", refid))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.string("pcbid", self.pcbid))
        data.add_child(Node.void("record"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/playerdata/data/recordtype")
        if loadflag != 2:
            # As implemented, its possible for a machine not in an arcade to have scores.
            # So, if the test PCBID we're using isn't in an arcade, we won't fetch scores
            # for area records (flag 2), so don't check for these in that case.
            self.assert_path(resp, "response/playerdata/data/record/mcode")
            self.assert_path(resp, "response/playerdata/data/record/notetype")
            self.assert_path(resp, "response/playerdata/data/record/rank")
            self.assert_path(resp, "response/playerdata/data/record/clearkind")
            self.assert_path(resp, "response/playerdata/data/record/flagdata")
            self.assert_path(resp, "response/playerdata/data/record/name")
            self.assert_path(resp, "response/playerdata/data/record/area")
            self.assert_path(resp, "response/playerdata/data/record/code")
            self.assert_path(resp, "response/playerdata/data/record/score")
            self.assert_path(resp, "response/playerdata/data/record/ghostid")

        if resp.child_value("playerdata/data/recordtype") != loadflag:
            raise Exception("Invalid record type returned!")

    def verify_playerdata_usergamedata_advanced_userload(self, refid: str) -> Tuple[bool, List[Dict[str, Any]]]:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_advanced")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("mode", "userload"))
        data.add_child(Node.s64("gamesession", 123456))
        data.add_child(Node.string("refid", refid))
        data.add_child(Node.string("dataid", refid))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.string("pcbid", self.pcbid))
        data.add_child(Node.void("record"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/playerdata/result")
        self.assert_path(resp, "response/playerdata/is_new")

        music = []
        for child in resp.child("playerdata").children:
            if child.name != "music":
                continue

            songid = child.child_value("mcode")
            chart = 0
            for note in child.children:
                if note.name != "note":
                    continue

                if note.child_value("count") != 0:
                    # Actual song
                    music.append(
                        {
                            "id": songid,
                            "chart": chart,
                            "rank": note.child_value("rank"),
                            "halo": note.child_value("clearkind"),
                            "score": note.child_value("score"),
                            "ghostid": note.child_value("ghostid"),
                        }
                    )

                chart = chart + 1

        return (
            resp.child_value("playerdata/is_new"),
            music,
        )

    def verify_playerdata_usergamedata_advanced_inheritance(self, refid: str, locid: str) -> None:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_advanced")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("mode", "inheritance"))
        data.add_child(Node.string("locid", locid))
        data.add_child(Node.s64("gamesession", 123456))
        data.add_child(Node.string("refid", refid))
        data.add_child(Node.string("dataid", refid))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.string("pcbid", self.pcbid))
        data.add_child(Node.void("record"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/playerdata/InheritanceStatus")
        self.assert_path(resp, "response/playerdata/result")

    def verify_playerdata_usergamedata_advanced_usersave(
        self,
        refid: str,
        extid: int,
        locid: str,
        score: Dict[str, Any],
        scorepos: int = 0,
    ) -> None:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_advanced")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("mode", "usersave"))
        data.add_child(Node.string("name", self.NAME))
        data.add_child(Node.s32("ddrcode", extid))
        data.add_child(Node.s32("playside", 1))
        data.add_child(Node.s32("playstyle", 0))
        data.add_child(Node.s32("area", 58))
        data.add_child(Node.s32("weight100", 0))
        data.add_child(Node.string("shopname", "gmw="))
        data.add_child(Node.bool("ispremium", False))
        data.add_child(Node.bool("iseapass", True))
        data.add_child(Node.bool("istakeover", False))
        data.add_child(Node.bool("isrepeater", False))
        data.add_child(Node.bool("isgameover", scorepos < 0))
        data.add_child(Node.string("locid", locid))
        data.add_child(Node.string("shoparea", "."))
        data.add_child(Node.s64("gamesession", 123456))
        data.add_child(Node.string("refid", refid))
        data.add_child(Node.string("dataid", refid))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.string("pcbid", self.pcbid))
        data.add_child(Node.void("record"))

        for i in range(5):
            if i == scorepos:
                # Fill in score here
                note = Node.void("note")
                data.add_child(note)
                note.add_child(Node.u8("stagenum", i + 1))
                note.add_child(Node.u32("mcode", score["id"]))
                note.add_child(Node.u8("notetype", score["chart"]))
                note.add_child(Node.u8("rank", score["rank"]))
                note.add_child(Node.u8("clearkind", score["halo"]))
                note.add_child(Node.s32("score", score["score"]))
                note.add_child(Node.s32("exscore", 0))
                note.add_child(Node.s32("maxcombo", 0))
                note.add_child(Node.s32("life", 0))
                note.add_child(Node.s32("fastcount", 0))
                note.add_child(Node.s32("slowcount", 0))
                note.add_child(Node.s32("judge_marvelous", 0))
                note.add_child(Node.s32("judge_perfect", 0))
                note.add_child(Node.s32("judge_great", 0))
                note.add_child(Node.s32("judge_good", 0))
                note.add_child(Node.s32("judge_boo", 0))
                note.add_child(Node.s32("judge_miss", 0))
                note.add_child(Node.s32("judge_ok", 0))
                note.add_child(Node.s32("judge_ng", 0))
                note.add_child(Node.s32("calorie", 0))
                note.add_child(Node.s32("ghostsize", len(score["ghost"])))
                note.add_child(Node.string("ghost", score["ghost"]))
                note.add_child(Node.u8("opt_speed", 0))
                note.add_child(Node.u8("opt_boost", 0))
                note.add_child(Node.u8("opt_appearance", 0))
                note.add_child(Node.u8("opt_turn", 0))
                note.add_child(Node.u8("opt_dark", 0))
                note.add_child(Node.u8("opt_scroll", 0))
                note.add_child(Node.u8("opt_arrowcolor", 0))
                note.add_child(Node.u8("opt_cut", 0))
                note.add_child(Node.u8("opt_freeze", 0))
                note.add_child(Node.u8("opt_jump", 0))
                note.add_child(Node.u8("opt_arrowshape", 0))
                note.add_child(Node.u8("opt_filter", 0))
                note.add_child(Node.u8("opt_guideline", 0))
                note.add_child(Node.u8("opt_gauge", 0))
                note.add_child(Node.u8("opt_judgepriority", 0))
                note.add_child(Node.u8("opt_timing", 0))
                note.add_child(Node.string("basename", ""))
                note.add_child(Node.string("title_b64", ""))
                note.add_child(Node.string("artist_b64", ""))
                note.add_child(Node.u16("bpmMax", 0))
                note.add_child(Node.u16("bpmMin", 0))
                note.add_child(Node.u8("level", 0))
                note.add_child(Node.u8("series", 0))
                note.add_child(Node.u32("bemaniFlag", 0))
                note.add_child(Node.u32("genreFlag", 0))
                note.add_child(Node.u8("limited", 0))
                note.add_child(Node.u8("region", 0))
                note.add_child(Node.s32("gr_voltage", 0))
                note.add_child(Node.s32("gr_stream", 0))
                note.add_child(Node.s32("gr_chaos", 0))
                note.add_child(Node.s32("gr_freeze", 0))
                note.add_child(Node.s32("gr_air", 0))
                note.add_child(Node.bool("share", False))
                note.add_child(Node.u64("endtime", 0))
                note.add_child(Node.s32("folder", 0))
            else:
                note = Node.void("note")
                data.add_child(note)
                note.add_child(Node.u8("stagenum", 0))
                note.add_child(Node.u32("mcode", 0))
                note.add_child(Node.u8("notetype", 0))
                note.add_child(Node.u8("rank", 0))
                note.add_child(Node.u8("clearkind", 0))
                note.add_child(Node.s32("score", 0))
                note.add_child(Node.s32("exscore", 0))
                note.add_child(Node.s32("maxcombo", 0))
                note.add_child(Node.s32("life", 0))
                note.add_child(Node.s32("fastcount", 0))
                note.add_child(Node.s32("slowcount", 0))
                note.add_child(Node.s32("judge_marvelous", 0))
                note.add_child(Node.s32("judge_perfect", 0))
                note.add_child(Node.s32("judge_great", 0))
                note.add_child(Node.s32("judge_good", 0))
                note.add_child(Node.s32("judge_boo", 0))
                note.add_child(Node.s32("judge_miss", 0))
                note.add_child(Node.s32("judge_ok", 0))
                note.add_child(Node.s32("judge_ng", 0))
                note.add_child(Node.s32("calorie", 0))
                note.add_child(Node.s32("ghostsize", 0))
                note.add_child(Node.string("ghost", ""))
                note.add_child(Node.u8("opt_speed", 0))
                note.add_child(Node.u8("opt_boost", 0))
                note.add_child(Node.u8("opt_appearance", 0))
                note.add_child(Node.u8("opt_turn", 0))
                note.add_child(Node.u8("opt_dark", 0))
                note.add_child(Node.u8("opt_scroll", 0))
                note.add_child(Node.u8("opt_arrowcolor", 0))
                note.add_child(Node.u8("opt_cut", 0))
                note.add_child(Node.u8("opt_freeze", 0))
                note.add_child(Node.u8("opt_jump", 0))
                note.add_child(Node.u8("opt_arrowshape", 0))
                note.add_child(Node.u8("opt_filter", 0))
                note.add_child(Node.u8("opt_guideline", 0))
                note.add_child(Node.u8("opt_gauge", 0))
                note.add_child(Node.u8("opt_judgepriority", 0))
                note.add_child(Node.u8("opt_timing", 0))
                note.add_child(Node.string("basename", ""))
                note.add_child(Node.string("title_b64", ""))
                note.add_child(Node.string("artist_b64", ""))
                note.add_child(Node.u16("bpmMax", 0))
                note.add_child(Node.u16("bpmMin", 0))
                note.add_child(Node.u8("level", 0))
                note.add_child(Node.u8("series", 0))
                note.add_child(Node.u32("bemaniFlag", 0))
                note.add_child(Node.u32("genreFlag", 0))
                note.add_child(Node.u8("limited", 0))
                note.add_child(Node.u8("region", 0))
                note.add_child(Node.s32("gr_voltage", 0))
                note.add_child(Node.s32("gr_stream", 0))
                note.add_child(Node.s32("gr_chaos", 0))
                note.add_child(Node.s32("gr_freeze", 0))
                note.add_child(Node.s32("gr_air", 0))
                note.add_child(Node.bool("share", False))
                note.add_child(Node.u64("endtime", 0))
                note.add_child(Node.s32("folder", 0))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/playerdata/result")

    def verify_usergamedata_send(self, ref_id: str, ext_id: int, msg_type: str, send_only_common: bool = False) -> None:
        call = self.call_node()

        # Set up profile write
        profiledata = {
            "COMMON": [
                b"1",
                b"0",  # shoparea spot, filled in below
                b"3c880f8",
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"ffffffffffffffff",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",  # Name spot, filled in below
                ID.format_extid(ext_id).encode("ascii"),
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "OPTION": [
                b"0",
                b"3",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"3",
                b"0",
                b"0",
                b"0",
                b"0",
                b"1",
                b"2",
                b"0",
                b"0",
                b"0",
                b"10.000000",
                b"10.000000",
                b"10.000000",
                b"10.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "LAST": [
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "RIVAL": [
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
        }

        if msg_type == "new":
            # New profile gets blank name, because we save over it at the end of the round.
            profiledata["COMMON"][1] = b"0"
            profiledata["COMMON"][25] = b""

        elif msg_type == "existing":
            # Exiting profile gets our hardcoded name saved.
            profiledata["COMMON"][1] = b"3a"
            profiledata["COMMON"][25] = self.NAME.encode("shift-jis")

        else:
            raise Exception(f"Unknown message type {msg_type}!")

        if send_only_common:
            profiledata = {"COMMON": profiledata["COMMON"]}

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_send")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("refid", ref_id))
        data.add_child(Node.string("dataid", ref_id))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.u32("datanum", len(profiledata.keys())))
        record = Node.void("record")
        data.add_child(record)
        for ptype in profiledata:
            profile = [b"ffffffff", ptype.encode("ascii")] + profiledata[ptype]
            d = Node.string("d", base64.b64encode(b",".join(profile)).decode("ascii"))
            record.add_child(d)
            d.add_child(Node.string("bin1", ""))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")

    def verify_usergamedata_recv(self, ref_id: str) -> str:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_recv")
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("refid", ref_id))
        data.add_child(Node.string("dataid", ref_id))
        data.add_child(Node.string("gamekind", "MDX"))
        data.add_child(Node.u32("recv_num", 4))
        data.add_child(
            Node.string(
                "recv_csv",
                "COMMON,3fffffffff,OPTION,3fffffffff,LAST,3fffffffff,RIVAL,3fffffffff",
            )
        )

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")
        self.assert_path(resp, "response/playerdata/player/record/d/bin1")
        self.assert_path(resp, "response/playerdata/player/record_num")

        profiles = 0
        name = ""
        for child in resp.child("playerdata/player/record").children:
            if child.name != "d":
                continue

            if profiles == 0:
                bindata = child.value
                profiledata = base64.b64decode(bindata).split(b",")
                name = profiledata[25].decode("ascii")

            profiles = profiles + 1

        if profiles != 4:
            raise Exception("Didn't receive all four profiles in the right order!")

        return name

    def verify(self, cardid: Optional[str]) -> None:
        # Verify boot sequence is okay
        self.verify_services_get(
            expected_services=[
                "pcbtracker",
                "pcbevent",
                "local",
                "message",
                "facility",
                "cardmng",
                "package",
                "posevent",
                "pkglist",
                "dlstatus",
                "eacoin",
                "lobby",
                "ntp",
                "keepalive",
            ]
        )
        paseli_enabled = self.verify_pcbtracker_alive()
        self.verify_message_get()
        self.verify_package_list()
        location = self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_eventlog_write(location)

        # Verify the game-wide packets Ace insists on sending before profile load
        is_new, music = self.verify_playerdata_usergamedata_advanced_userload("X0000000000000000000000000123456")
        if not is_new:
            raise Exception("Fake profiles should be new!")
        if len(music) > 0:
            raise Exception("Fake profiles should have no scores associated!")

        # Verify card registration and profile lookup
        if cardid is not None:
            card = cardid
        else:
            card = self.random_card()
            print(f"Generated random card ID {card} for use.")

        if cardid is None:
            self.verify_cardmng_inquire(card, msg_type="unregistered", paseli_enabled=paseli_enabled)
            self.verify_system_convcardnumber(card)
            ref_id = self.verify_cardmng_getrefid(card)
            if len(ref_id) != 16:
                raise Exception(f"Invalid refid '{ref_id}' returned when registering card")
            if ref_id != self.verify_cardmng_inquire(card, msg_type="new", paseli_enabled=paseli_enabled):
                raise Exception(f"Invalid refid '{ref_id}' returned when querying card")
            extid = self.verify_playerdata_usergamedata_advanced_usernew(ref_id)
            self.verify_usergamedata_send(ref_id, extid, "new")
            self.verify_playerdata_usergamedata_advanced_inheritance(ref_id, location)
            name = self.verify_usergamedata_recv(ref_id)
            if name != "":
                raise Exception("Name stored on profile we just created!")
            self.verify_usergamedata_send(ref_id, extid, "existing", send_only_common=True)
            name = self.verify_usergamedata_recv(ref_id)
            if name != self.NAME:
                raise Exception("Name stored on profile is incorrect!")
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        if cardid is None:
            is_new, music = self.verify_playerdata_usergamedata_advanced_userload(ref_id)
            if is_new:
                raise Exception("Profile should not be new!")
            if len(music) > 0:
                raise Exception("Created profile should have no scores associated!")

            # Verify score saving and updating
            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 10,
                            "chart": 3,
                            "rank": 5,
                            "halo": 6,
                            "score": 765432,
                            "ghost": "765432",
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 10,
                            "chart": 2,
                            "rank": 2,
                            "halo": 8,
                            "score": 876543,
                            "ghost": "876543",
                        },
                        # A bad score on a hard chart
                        {
                            "id": 479,
                            "chart": 2,
                            "rank": 11,
                            "halo": 6,
                            "score": 654321,
                            "ghost": "654321",
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 479,
                            "chart": 1,
                            "rank": 15,
                            "halo": 6,
                            "score": 123456,
                            "ghost": "123456",
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 10,
                            "chart": 3,
                            "rank": 4,
                            "halo": 7,
                            "score": 888888,
                            "ghost": "888888",
                        },
                        # A worse score on another same chart
                        {
                            "id": 10,
                            "chart": 2,
                            "rank": 3,
                            "halo": 7,
                            "score": 654321,
                            "ghost": "654321",
                            "expected_score": 876543,
                            "expected_halo": 8,
                            "expected_rank": 2,
                            "expected_ghost": "876543",
                        },
                    ]

                pos = 0
                for dummyscore in dummyscores:
                    self.verify_playerdata_usergamedata_advanced_usersave(
                        ref_id,
                        extid,
                        location,
                        dummyscore,
                        pos,
                    )
                    pos = pos + 1

                is_new, scores = self.verify_playerdata_usergamedata_advanced_userload(ref_id)
                if is_new:
                    raise Exception("Profile should not be new!")
                if len(scores) == 0:
                    raise Exception("Expected some scores after saving!")

                for expected in dummyscores:
                    actual = None
                    for received in scores:
                        if received["id"] == expected["id"] and received["chart"] == expected["chart"]:
                            actual = received
                            break

                    if actual is None:
                        raise Exception(f"Didn't find song {expected['id']} chart {expected['chart']} in response!")

                    if "expected_score" in expected:
                        expected_score = expected["expected_score"]
                    else:
                        expected_score = expected["score"]
                    if "expected_rank" in expected:
                        expected_rank = expected["expected_rank"]
                    else:
                        expected_rank = expected["rank"]
                    if "expected_halo" in expected:
                        expected_halo = expected["expected_halo"]
                    else:
                        expected_halo = expected["halo"]

                    if actual["score"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got score \'{actual["score"]}\''
                        )
                    if actual["rank"] != expected_rank:
                        raise Exception(
                            f'Expected a rank of \'{expected_rank}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got rank \'{actual["rank"]}\''
                        )
                    if actual["halo"] != expected_halo:
                        raise Exception(
                            f'Expected a halo of \'{expected_halo}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got halo \'{actual["halo"]}\''
                        )

                    # Now verify that the ghost for this score is what we saved
                    ghost = self.verify_playerdata_usergamedata_advanced_ghostload(ref_id, received["ghostid"])
                    if "expected_ghost" in expected:
                        expected_ghost = expected["expected_ghost"]
                    else:
                        expected_ghost = expected["ghost"]

                    if ghost["id"] != received["id"]:
                        raise Exception(
                            f'Wrong song ID \'{ghost["id"]}\' returned for ghost, expected ID \'{received["id"]}\''
                        )
                    if ghost["chart"] != received["chart"]:
                        raise Exception(
                            f'Wrong song chart \'{ghost["chart"]}\' returned for ghost, expected chart \'{received["chart"]}\''
                        )
                    if ghost["ghost"] != expected_ghost:
                        raise Exception(
                            f'Wrong ghost data \'{ghost["ghost"]}\' returned for ghost, expected \'{expected_ghost}\''
                        )
                    if ghost["extid"] != extid:
                        raise Exception(f'Wrong extid \'{ghost["extid"]}\' returned for ghost, expected \'{extid}\'')

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)

            # Simulate game over conditions
            self.verify_playerdata_usergamedata_advanced_usersave(
                ref_id,
                extid,
                location,
                {},
                -1,
            )
        else:
            print("Skipping score checks for existing card")

        # Verify global scores now that we've inserted some
        self.verify_playerdata_usergamedata_advanced_rivalload("X0000000000000000000000000123456", 1)
        self.verify_playerdata_usergamedata_advanced_rivalload("X0000000000000000000000000123456", 2)
        self.verify_playerdata_usergamedata_advanced_rivalload("X0000000000000000000000000123456", 4)

        # Verify paseli handling
        if paseli_enabled:
            print("PASELI enabled for this PCBID, executing PASELI checks")
        else:
            print("PASELI disabled for this PCBID, skipping PASELI checks")
            return

        sessid, balance = self.verify_eacoin_checkin(card)
        if balance == 0:
            print("Skipping PASELI consume check because card has 0 balance")
        else:
            self.verify_eacoin_consume(sessid, balance, random.randint(0, balance))
        self.verify_eacoin_checkout(sessid)
