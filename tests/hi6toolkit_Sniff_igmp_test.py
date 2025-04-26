#!/usr/bin/python3
import unittest
import asyncio
from hi6toolkit import Sniff

loop = asyncio.get_event_loop()
igmp_tests = [
    {
        "dgram" : b"",
        "typ" : 0x12,
        "mrt" : 20,
        "csm" : ...,
        "gad" : ...
        },
    {
        "dgram" : b"",
        "typ" : 0x17,
        "mrt" : 160, #for testing handle_mrtc() coroutine
        "csm" : ...,
        "gad" : ...
        },
    {
        "dgram" : b"",
        "typ" : 0x11,
        "mrt" : 1600,
        "csm" : ...,
        "gad" : ...,
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
        "dgram" : b"",
        "typ" : 0x22,
        "csm" : ...,
        "nog" : 2,
        "group_1" : {
            "rtp" : 1,
            "rtp_name" : "MODE_IS_INCLUDE",
            "adl" : 2,
            "nos" : 3,
            "mad" : 244.1.1.4,
            "src_addrs" : [
                "127.0.0.1",
                "65.67.68.69",
                "123.134.156.178"
                ],
            "data" : "testing_packet_for_Sniff_class_of_hi6toolkit"
            },
        "group_2" : {
            "rtp" : 6,
            "rtp_name" : "BLOCK_OLD_SOURCES",
            "adl" : 2,
            "nos" : 4,
            "mad" : "244.1.1.4",
            "src_addrs" : [
                "192.168.72.72",
                "192.168.1.1",
                "4.2.2.4",
                "1.1.1.1"
                ],
            "data" : "testing_packet_for_Sniff_class_of_hi6toolkit"
            }
        }
    ]


class Sniff_igmp_Test(unittest.TestCase) :
    sniff = Sniff(loop, "wlo1", False, None, None, 65535)
    async def test_parser_type_12(self) -> None :
        typ, mrt, csm, gad = await sniff.igmp_header(igmp_tests[0]["dgram"])
        self.assertEqual(igmp_tests[0]["typ"], typ)
        self.assertEqual(igmp_tests[0]["mrt"], mrt)
        self.assertEqual(igmp_tests[0]["csm"], csm)
        self.assertEqual(igmp_tests[0]["gad"], gad)
        return

    async def test_parser_type_17(self) -> None :
        typ, mrt, csm, gad = await sniff.igmp_header(igmp_tests[1]["dgram"])
        self.assertEqual(igmp_tests[1]["typ"], typ)
        self.assertEqual(igmp_tests[1]["mrt"], 512) # (160 -> 512) calculated with https://www.rfc-editor.org/rfc/rfc3376#section-4.1.1 instructions
        self.assertEqual(igmp_tests[1]["csm"], csm)
        self.assertEqual(igmp_tests[1]["gad"], gad)
        return

    async def test_parser_type_11(self) -> None :
        typ, mrt, csm, gad, srp, qrv, qic, nos, src_addrs = await sniff.igmp_header(igmp_tests[2]["dgram"])
        self.assertEqual(igmp_tests[2]["typ"], typ)
        self.assertEqual(igmp_tests[2]["mrt"], 2048) # (1600 -> 2048) calculated with https://www.rfc-editor.org/rfc/rfc3376#section-4.1.1 instructions
        self.assertEqual(igmp_tests[2]["csm"], csm)
        self.assertEqual(igmp_tests[2]["gad"], gad)
        self.assertEqual(igmp_tests[2]["srp"], srp)
        self.assertEqual(igmp_tests[2]["qrv"], qrv)
        self.assertEqual(igmp_tests[2]["qic"], qic)
        self.assertEqual(igmp_tests[2]["nos"], nos)
        self.assertEqual(igmp_tests[2]["src_addrs"], src_addrs)
        return

    async def test_parsed_type_22(self) -> None :
        typ, csm, nog, group_records = await sniff.igmp_header(igmp_tests[3]["dgram"])
        self.assertEqual(igmp_tests[3]["typ"], typ)
        self.assertEqual(igmp_tests[3]["csm"], csm)
        self.assertEqual(igmp_tests[3]["nog"], nog)
        for i, record in enumerate(group_records, start = 1) :
            rtp, adl, nos, mad, src_addrs = record
            self.assertEqual(igmp_tests[3]["group_" + str(i)]["rtp"], rtp)
            self.assertEqual(igmp_tests[3]["group_" + str(i)]["adl"], adl)
            self.assertEqual(igmp_tests[3]["group_" + str(i)]["nos"], nos)
            self.assertEqual(igmp_tests[3]["group_" + str(i)]["mad"], mad)
            self.assertEqual(igmp_tests[3]["group_" + str(i)]["src_addrs"], src_addrs)
        return

    async def test_visual_type_12(self) -> None :
        parsed_igmp = await sniff.parse_igmp_header(igmp_tests[0]["dgram"])
        print(parsed_igmp)
        result = input("[Y/N]")
        self.assertEqual(result.lower(), "y")
        return

    async def test_visual_type_17(self) -> None :
        parsed_igmp = await sniff.parse_igmp_header(igmp_tests[1]["dgrams"])
        print(parsed_igmp)
        result = input("[Y/N]")
        self.assertEqual(result.lower(), "y")
        return

    async def test_visual_type_11(self) -> None :
        parsed_igmp = await sniff.parse_igmp_header(igmp_tests[2]["dgrams"])
        print(parsed_igmp)
        result = input("[Y/N]")
        self.assertEqual(result.lower(), "y")
        return

    async def test_visual_type_22(self) -> None :
        parsed_igmp = await sniff.parse_igmp_header(igmp_tests[3]["dgrams"])
        print(parsed_igmp)
        result = input("[Y/N]")
        self.assertEqual(result.lower(), "y")
        return

if __name__ == "__main__" :
    unittest.main()
