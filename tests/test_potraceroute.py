#!/usr/bin/env python2.7

import unittest

import platform
import socket
import sys
sys.path.append('./')
sys.path.append('../')
from potraceroute import *

knownhost = "google-public-dns-a.google.com."
knownip = socket.gethostbyname(knownhost)
knownportname = "ssh"
knownport = 22

class TestPoTracerouteClasses(unittest.TestCase):

    def test_ipparse(self):
        hopeful_result = {
            'source_port': 22,
            'dest_port': 1024,
            'udp_length': 6,
            'udp_checksum': 3085,
            '_parsed_length': 8,
            'payload': '012345',
        }
        self.assertEqual(hopeful_result, IPParse.parse_udp("\x00\x16\x04\x00\x00\x06\x0c\x0d\x30\x31\x32\x33\x34\x35"), "UDP parse not working properly")
        packet = "45002f0019770000fe014e2fa6540159a654071203035235000000004500002700000000021163b3a6540712a6540159eadf001900131d07756470207061796c6f6164".decode("hex")
        ipfields = IPParse.parse_ip(packet)
        icmpfields = IPParse.parse_icmp(ipfields['payload'])
        rp_ipfields = IPParse.parse_ip(icmpfields['payload'])
        rp_udpfields = IPParse.parse_udp(rp_ipfields['payload'])

        self.assertEqual(icmpfields['icmp_type'], 3, "ICMP type parse failure")
        self.assertEqual(icmpfields['icmp_code'], 3, "ICMP code parse failure")
        self.assertEqual(icmpfields['icmp_id'], 0, "ICMP ID parse failure")
        self.assertEqual(icmpfields['payload'], "E\x00\x00'\x00\x00\x00\x00\x02\x11c\xb3\xa6T\x07\x12\xa6T\x01Y\xea\xdf\x00\x19\x00\x13\x1d\x07udp payload", "ICMP payload parse failure")
        self.assertEqual({'_parsed_length': 8, 'udp_length': 19, 'source_port': 60127, 'udp_checksum': 7431, 'payload': 'udp payload', 'dest_port': 25}, rp_udpfields)
        nested = IPPacket(ICMPPacket(IPPacket(packet).payload).payload)
        self.assertEqual(nested.ip_ttl, 2, "nested packet parsing failure - ttl")
        self.assertTrue(nested.payload.endswith("udp payload"), "nested packet parsing failure - payload")

    def test_icmp_fields(self):
        self.assertEqual(ICMPFields.UnreachableCode(3), 'Port Unreachable')
        self.assertEqual(ICMPFields.UnreachableCode(14), str(14))
        self.assertEqual(ICMPFields.Type(11), 'TTL Exceeded')
        self.assertEqual(ICMPFields.Type(31), str(31))

    def test_protocol_numbers(self):
        i = IPProtocol.number("icmp")
        t = IPProtocol.number("TCP")
        u = IPProtocol.number("udP")
        self.assertEqual(i, 1)
        self.assertEqual(t, 6)
        self.assertEqual(u, 17)
        with self.assertRaises(KeyError) as testoops:
            IPProtocol.number("frog is not a protocol")

    def test_misc_traceroute_class(self):
        (options, args) = parse_options(["--port", knownportname, knownhost])
        t = Traceroute(options, knownhost)
        self.assertEqual(t.portnumber_of("http"), 80)
        self.assertEqual(t.portnumber_of(123), 123)
        with self.assertRaises(ValueError) as testoops:
            t.portnumber_of("frog is not a service name")

    def test_traceroute_init_tcp(self):
        (options, args) = parse_options(["--port", knownportname, knownhost])
        t = Traceroute(options, knownhost)
        self.assertEqual(t.port, knownport)
        self.assertEqual(t.destination_addr, knownip)
        self.assertEqual(t.proto, "TCP")

    def test_traceroute_hop_class(self):
        (options, args) = parse_options(["--port", knownportname, knownhost])
        t = Traceroute(options, knownhost)
        h = TracerouteHop(t, 5, "test object", rxpacket="45c048008fa800003a017ee7d155f295a65407120b00b2a80000000045800040000040000106bbc2a654071208080808ffa10035ad0ce22d00000000b002800069750000020405b401030303040201010101080a0000000100000000".decode("hex"))
        self.assertEqual(str(h), "5\t209.85.242.149 (209.85.242.149) test object", "hop __repr__ not working as expected")

    def runConnectivityTest(self, opts, hostname, reachable=True, finalSuffix=None, mustContain=None):
        (options, args) = parse_options(opts + [hostname])
        t = Traceroute(options, hostname)
        if reachable:
            h = t.probe(250)
            self.assertTrue(h.reached, "could not reach {host} with options: {opts}".format(host=hostname, opts=opts))
            self.assertTrue(h.final, "reached host {host} with options: {opts} but was not marked final".format(host=hostname, opts=opts))
            if finalSuffix is not None:
                self.assertTrue(str(h).endswith(finalSuffix), "expected a reachable traceroute to host {host} with options {opts} to have a status message ending in '{finalSuffix}' but message was '{msg}'".format(host=hostname, opts=opts, finalSuffix=finalSuffix, msg=str(h)))
            if mustContain is not None:
                self.assertIn(mustContain, str(h), "expected reachable traceroute to host {host} with options {opts} to have status message containing '{mustContain}' but message was '{msg}'".format(host=hostname, opts=opts, mustContain=mustContain, msg=str(h)))
        if not hostname.startswith("127."): # localhost is only one hop away
            h = t.probe(1)
            self.assertFalse(h.reached, "did not expect to reach with one hop host {host} with options {opts}".format(host=hostname, opts=opts))
            self.assertFalse(h.final, "non-reachable hop should not be marked final")
        if not reachable:
            h = t.probe(250)
            self.assertFalse(h.reached, "did not expect to reach supposedly unreachable host {host} with options {opts}".format(host=hostname, opts=opts))
            if finalSuffix is not None:
                 self.assertTrue(str(h).endswith(finalSuffix), "expected an unreachable traceroute to host {host} with options {opts} to have a status message ending in '{finalSuffix}' but message was '{msg}'".format(host=hostname, opts=opts, finalSuffix=finalSuffix, msg=str(h)))

        return t # in case caller wants to run further tests

    def test_connectivity_to_known_places(self):
        # ASSUMPTIONS:
        # Assumes google.com can be reached via port 80 and ICMP
        # Assumes 8.8.8.8 can be reached via port 53 UDP
        # Assumes 8.8.8.1 is not reachable and will time out
        # Assumes localhost port 1 TCP will refuse connections
        # Assumes smtp.gmail.com exists and answers with a banner
        
        self.runConnectivityTest(["--port", "http"], "google.com", reachable=True, finalSuffix="TCP port 80 connection successful. [Reached Destination]")
        if platform.system() not in ['AIX', 'NetBSD']:
            self.runConnectivityTest(["--icmp"], "google.com", reachable=True, finalSuffix=") ICMP echo reply [Reached Destination]")
        self.runConnectivityTest(["--udp", "--port", "53"], "8.8.8.8", reachable=True, finalSuffix="\\x13google-public-dns-a\\x06google\\x03com\\x00'", mustContain="UDP port 53 responded, received data:")
        if platform.system() not in ['AIX', 'NetBSD']:
            self.runConnectivityTest(["--icmp"], "8.8.8.1", reachable=False, finalSuffix="*\ttimed out")
        if platform.system() not in ['Windows', 'NetBSD'] and not platform.system().startswith("CYGWIN"):
            self.runConnectivityTest(["--port", "1"], "127.0.0.1", reachable=True, finalSuffix="TCP port 1 connection refused [Reached Destination]")
        self.runConnectivityTest(["--port", "25"], "smtp.gmail.com", reachable=True, mustContain="TCP port 25 connection successful, received data: '")

if __name__ == "__main__":
    if is_android() and os.getuid() != 0:
        qpython_invocation(script=__file__)
    unittest.main()
   

# test scenario - asssumes 1.0.0.99 is not a local router
# provoke local unreachable error when writing to ping socket
# tested on MacOS
#  694  sudo  route add -host 8.8.8.1 1.0.0.99
#  695  sudo ./potraceroute.py 8.8.8.1  -I
#  696  sudo  route delete  -host 8.8.8.1 1.0.0.99

# test scenario
# create blackhole route (Linux route? Mac ipfw? Linux iptables?)
# so we can test ICMP 3/xxx returns
