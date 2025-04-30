#!/usr/bin/python3
import scapy.contrib.igmp as igmp
import scapy.contrib.igmpv3 as igmpv3

dgram_typ_12 = igmp.IGMP(type = 0x12, mrcode = 20, chksum = 0x23f, gaddr = "224.0.0.1")
print(dgram_typ_12.build())

dgram_typ_17 = igmp.IGMP(type = 0x17, mrcode = 160, chksum = 0x25f, gaddr = "244.0.1.1")
print(dgram_typ_17.build())

dgram_typ_11_raw = igmpv3.IGMPv3(type = 0x11, mrcode = 160, chksum = 0x27f).build()
mq_dgram = igmpv3.IGMPv3mq(
        gaddr = "244.1.1.1",
        s = 1,
        qrv = 1,
        qqic = 160,
        numsrc = 5,
        srcaddrs = [
            "123.123.123.123",
            "21.21.21.21",
            "45.45.45.45",
            "127.0.0.1",
            "192.168.43.1"
            ]
        ).build()
print(dgram_typ_11_raw + mq_dgram)

dgram_typ_22_record_1 = igmpv3.IGMPv3gr(rtype = 1, auxdlen = 0, numsrc = 3, maddr = "244.1.1.4", srcaddrs = ["127.0.0.1", "65.67.68.69", "123.134.156.178"])
dgram_typ_22_record_2 = igmpv3.IGMPv3gr(rtype = 6, auxdlen = 0, numsrc = 4, maddr = "244.1.1.4", srcaddrs = ["192.168.72.72", "192.168.1.1", "4.2.2.4", "1.1.1.1"])
dgram_typ_22 = igmpv3.IGMPv3(type = 0x22, chksum = 0x29f).build()
mr_dgram = igmpv3.IGMPv3mr(numgrp = 2, records = [dgram_typ_22_record_1, dgram_typ_22_record_2]).build()
print(dgram_typ_22 + mr_dgram)


