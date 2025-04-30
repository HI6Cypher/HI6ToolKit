#!/usr/bin/python3
import sys
import asyncio
sys.path.append("../")
from hi6toolkit import Sniff


igmp_tests = [
    {
        "dgram" : b"\x12\x14\x02?\xe0\x00\x00\x01",
        "typ" : 0x12,
        "mrt" : 20,
        "csm" : 0x23f,
        "gad" : "224.0.0.1"
        },
    {
        "dgram" : b"\x17\xa0\x02_\xf4\x00\x01\x01",
        "typ" : 0x17,
        "mrt" : 160, #for testing handle_codes() coroutine
        "csm" : 0x25f,
        "gad" : "244.0.1.1"
        },
    {
        "dgram" : b"\x11\xa0\x02\x7f\xf4\x01\x01\x01\t\xa0\x00\x05{{{{\x15\x15\x15\x15----\x7f\x00\x00\x01\xc0\xa8+\x01",
        "typ" : 0x11,
        "mrt" : 160,
        "csm" : 0x27f,
        "gad" : "244.1.1.1",
        "srp" : 1,
        "qrv" : 1,
        "qic" : 160,
        "nos" : 5,
        "src_addrs" : [
            "123.123.123.123",
            "21.21.21.21",
            "45.45.45.45",
            "127.0.0.1",
            "192.168.43.1"
            ]
        },
    {
        "dgram" : b'"\x14\x02\x9f\x00\x00\x00\x02\x01\x00\x00\x03\xf4\x01\x01\x04\x7f\x00\x00\x01ACDE{\x86\x9c\xb2\x06\x00\x00\x04\xf4\x01\x01\x04\xc0\xa8HH\xc0\xa8\x01\x01\x04\x02\x02\x04\x01\x01\x01\x01',
        "typ" : 0x22,
        "csm" : 0x29f,
        "nog" : 2,
        "group_1" : {
            "rtp" : 1,
            "rtp_name" : "MODE_IS_INCLUDE",
            "adl" : 0,
            "nos" : 3,
            "mad" : "244.1.1.4",
            "src_addrs" : [
                "127.0.0.1",
                "65.67.68.69",
                "123.134.156.178"
                ]
            },
        "group_2" : {
            "rtp" : 6,
            "rtp_name" : "BLOCK_OLD_SOURCES",
            "adl" : 0,
            "nos" : 4,
            "mad" : "244.1.1.4",
            "src_addrs" : [
                "192.168.72.72",
                "192.168.1.1",
                "4.2.2.4",
                "1.1.1.1"
                ]
            }
        }
    ]


class Sniff_igmp_Test :
    def __init__(self, loop : "aync_event_loop", tests : list[dict]) -> "Sniff_igmp_Test_class" :
        self.sniff = Sniff(None, "wlo1", False, None, None, 65535)
        self.tests = tests

    async def test_parser_type_12(self) -> None :
        typ, mrt, csm, gad = await self.sniff.igmp_header(self.tests[0]["dgram"])
        assert self.tests[0]["typ"] == typ
        assert self.tests[0]["mrt"] == mrt
        assert self.tests[0]["csm"] == csm
        assert self.tests[0]["gad"] == gad
        print("PASSED")
        return

    async def test_parser_type_17(self) -> None :
        typ, mrt, csm, gad = await self.sniff.igmp_header(self.tests[1]["dgram"])
        assert self.tests[1]["typ"] == typ
        assert self.tests[1]["mrt"] == mrt
        assert self.tests[1]["csm"] == csm
        assert self.tests[1]["gad"] == gad
        return

    async def test_parser_type_11(self) -> None :
        typ, mrt, csm, gad, srp, qrv, qic, nos, src_addrs = await self.sniff.igmp_header(self.tests[2]["dgram"])
        assert self.tests[2]["typ"] == typ
        assert self.tests[2]["mrt"] == mrt
        assert self.tests[2]["csm"] == csm
        assert self.tests[2]["gad"] == gad
        assert self.tests[2]["srp"] == srp
        assert self.tests[2]["qrv"] == qrv
        assert self.tests[2]["qic"] == qic
        assert self.tests[2]["nos"] == nos
        assert self.tests[2]["src_addrs"] == src_addrs
        print("PASSED")
        return

    async def test_parser_type_22(self) -> None :
        typ, csm, nog, group_records = await self.sniff.igmp_header(self.tests[3]["dgram"])
        assert self.tests[3]["typ"] == typ
        assert self.tests[3]["csm"] == csm
        assert self.tests[3]["nog"] == nog
        for i, record in enumerate(group_records, start = 1) :
            rtp, adl, nos, mad, src_addrs, data = record
            assert self.tests[3]["group_" + str(i)]["rtp"] == rtp
            assert self.tests[3]["group_" + str(i)]["adl"] == adl
            assert self.tests[3]["group_" + str(i)]["nos"] == nos
            assert self.tests[3]["group_" + str(i)]["mad"] == mad
            assert self.tests[3]["group_" + str(i)]["src_addrs"] == src_addrs
        print("PASSED")
        return

    async def test_visual_type_12(self) -> None :
        parsed_igmp = await self.sniff.parse_igmp_header(self.tests[0]["dgram"])
        print(parsed_igmp.expandtabs(4))
        result = input("[Y/N]")
        assert result.lower() == "y"
        return

    async def test_visual_type_17(self) -> None :
        parsed_igmp = await self.sniff.parse_igmp_header(self.tests[1]["dgram"])
        print(parsed_igmp.expandtabs(4))
        result = input("[Y/N]")
        assert result.lower() == "y"
        return

    async def test_visual_type_11(self) -> None :
        parsed_igmp = await self.sniff.parse_igmp_header(self.tests[2]["dgram"])
        print(parsed_igmp.expandtabs(4))
        result = input("[Y/N]")
        assert result.lower() == "y"
        return

    async def test_visual_type_22(self) -> None :
        parsed_igmp = await self.sniff.parse_igmp_header(self.tests[3]["dgram"])
        print(parsed_igmp.expandtabs(4))
        result = input("[Y/N]")
        assert result.lower() == "y"
        return


async def main() -> None :
    loop = asyncio.get_event_loop()
    sniff_test = Sniff_igmp_Test(loop, igmp_tests)
    tasks = list()
    for test in filter(lambda x : x.startswith("test_"), dir(sniff_test)) :
        exec(compile(f"tasks.append(asyncio.create_task(sniff_test.{test}()))", "main", "single"))
    else :
        try :
            [await task for task in tasks]
        except AssertionError as error :
            for i in error : print(i)
        except Exception : print("ERROR")
if __name__ == "__main__" :
    asyncio.run(main())

