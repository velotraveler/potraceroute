#!/usr/bin/env python
'''
Multi-platform TCP/UDP/ICMP traceroute utility
https://github.com/velotraveler/potraceroute/
License is GPL 3.0, see LICENSE file in repository
'''

from binascii import a2b_hex as decode_hex
import errno
import optparse
import os
import platform
import pprint
import re
import select
import socket
import struct
import subprocess
import sys
import time

if sys.version_info[0] == 2:  # python2 compatibility
    class ConnectionRefusedError(Exception):
        pass

class IPProtocol(object):
    ''' Android doesn't have a /etc/protocols file, so getprotobyname()
        fails in that environment
    '''
    protocolnumbers = {'ICMP': 1, 'TCP': 6, 'UDP': 17}

    @staticmethod
    def number(protocolname):
        try:
            return IPProtocol.protocolnumbers[protocolname.upper()]
        except KeyError:
            raise KeyError("Unrecognized protocol string - known names are: {help}".format(help=", ".join(IPProtocol.protocolnumbers.keys())))

class ICMPFields(object):

    unreachableSubtypes = {
        0: 'Net Unreachable',
        1: 'Host Unreachable',
        2: 'Protocol Unreachable',
        3: 'Port Unreachable',
        4: 'Fragmentation Needed & DF Set',
        5: 'Source Route Failed',
        6: 'Destination Network Unknown',
        7: 'Destination Host Unknown',
        8: 'Source Host Isolated',
        9: 'Network Administratively Prohibited',
        10: 'Host Administratively Prohibited',
        11: 'Network Unreachable for TOS',
        12: 'Host Unreachable for TOS',
        13: 'Communication Administratively Prohibited',
    }

    icmpTypes = {
        0: 'Echo Reply',
        3: 'Network Unreachable',
        4: 'Source Quench',
        5: 'Network Redirect',
        8: 'Echo Request',
        9: 'Router Advertisement',
        11: 'TTL Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp',
        14: 'Timestamp Reply',
        15: 'Information Request',
        16: 'Information Reply',
        17: 'Address Mask Request',
        18: 'Address Mask Reply',
        30: 'Traceroute',
    }

    @staticmethod
    def UnreachableCode(value):
        try:
            return ICMPFields.unreachableSubtypes[value]
        except KeyError:
            return str(value)

    @staticmethod
    def Type(value):
        try:
            return ICMPFields.icmpTypes[value]
        except KeyError:
            return str(value)

    @staticmethod
    def CodeString(typenum, codenum, verbose=False):
        typeformat = "ICMP {type}/{code}"
        if not verbose:
            return typeformat.format(type=typenum, code=codenum)
        return typeformat.format(type=ICMPFields.Type(typenum), code=ICMPFields.UnreachableCode(codenum) if typenum == 3 else str(codenum))

class IPParse(object):

    @staticmethod
    def _bytes2ipstr(octets): # 4-byte string to printable IP address
        if type(octets[0]) is int:
            return ".".join([str(x) for x in octets]) # python3
        else:
            return ".".join([str(ord(x)) for x in octets]) # python2

    @staticmethod
    def inet_checksum(packet):
        csum = 0
        countTo = (len(packet) // 2) * 2

        count = 0
        while count < countTo:
            thisVal = packet[count+1] * 256 + packet[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(packet):
            csum = csum + packet[-1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum

        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    ip_parsetab = [
        {'name': 'ip_header_length', 'format': 'B', 'unpack_function': lambda x: (x & 0xf) * 4},
        {'name': 'ip_tos', 'format': 'B'},
        {'name': 'ip_total_length', 'format': 'H'},
        {'name': 'ip_id', 'format': 'H'},
        {'name': 'ip_offset', 'format': 'H', 'unpack_function': lambda x: x & 0x1fff},
        {'name': 'ip_ttl', 'format': 'B'},
        {'name': 'ip_protocol', 'format': 'B'},
        {'name': 'ip_checksum', 'format': 'H'},
        {'name': 'ip_source_address', 'format': '4s', 'unpack_function': _bytes2ipstr.__func__},
        {'name': 'ip_dest_address', 'format': '4s', 'unpack_function': _bytes2ipstr.__func__},
    ]

    icmp_parsetab = [
        {'name': 'icmp_type',     'format': 'B'},
        {'name': 'icmp_code',     'format': 'B'},
        {'name': 'icmp_checksum', 'format': 'H'},
        {'name': 'icmp_id',       'format': 'H'},
        {'name': 'icmp_seq',      'format': 'H'},
    ]

# we only parse the first 8 bytes of UDP and TCP packets as that's
# all you get in the ICMP TTL Exceeded message
    udp_parsetab = [
        {'name': 'source_port',  'format': 'H'},
        {'name': 'dest_port',    'format': 'H'},
        {'name': 'udp_length',   'format': 'H'},
        {'name': 'udp_checksum', 'format': 'H'},
    ]

    tcp_parsetab = [
        {'name': 'source_port',  'format': 'H'},
        {'name': 'dest_port',    'format': 'H'},
        {'name': 'tcp_seq',      'format': 'L'},
    ]


    @staticmethod
    def _parse_generic(parse_table, packet):
        pack_format = "!" + "".join([x['format'] for x in parse_table])
        format_length = struct.calcsize(pack_format)
        fields = struct.unpack(pack_format, packet[0:format_length])
        parsed_result = {}
        for i in range(len(fields)):
            parse_tags = parse_table[i].keys()
            if 'name' in parse_tags:
                this_tag = parse_table[i]['name']
                if 'unpack_function' in parse_tags:
                    parsed_result[this_tag] = parse_table[i]['unpack_function'](fields[i])
                else:
                    parsed_result[this_tag] = fields[i]
        parsed_result['_parsed_length'] = format_length
        parsed_result['payload'] = packet[format_length:]
        return parsed_result

    @staticmethod
    def _pack_generic(parse_table, **kwargs):
        pack_format = "!" + "".join([x['format'] for x in parse_table])
        kw_fields = set(kwargs.keys())
        table_fields = set([x['name'] for x in parse_table])
        if kw_fields != table_fields:
            raise ValueError("missing or extra keywords in call - got {kw} but expected {table}".format(kw=kw_fields, table=table_fields))
        values = []
        for i in range(len(parse_table)):
            values.append(kwargs[parse_table[i]['name']])
        result = struct.pack(pack_format, *values)
        return result

    @staticmethod
    def parse_udp(packet):
        return IPParse._parse_generic(IPParse.udp_parsetab, packet)

    @staticmethod
    def parse_tcp(packet):
        return IPParse._parse_generic(IPParse.tcp_parsetab, packet)
        # enough to return port numbers, we're not looking at the payload

    @staticmethod
    def parse_ip(packet):
        fields = IPParse._parse_generic(IPParse.ip_parsetab, packet)
        # options are optional, adjust payload as needed
        fields['ip_options'] = packet[fields['_parsed_length']:fields['ip_header_length']-fields['_parsed_length']]
        fields['payload'] = packet[fields['ip_header_length']:]
        return fields

    @staticmethod
    def parse_icmp(packet):
        return IPParse._parse_generic(IPParse.icmp_parsetab, packet)

    @staticmethod
    def pack_icmp(payload, **kwargs):
        packet = IPParse._pack_generic(IPParse.icmp_parsetab, **kwargs) + payload
        if kwargs['icmp_checksum'] == 0:
            checksum = IPParse.inet_checksum(bytearray(packet))
            kwargs['icmp_checksum'] = checksum
            packet = IPParse._pack_generic(IPParse.icmp_parsetab, **kwargs) + payload
        assert IPParse.inet_checksum(bytearray(packet)) == 0
        return packet

class IPPacket(object):
    def __init__(self, thebytes, parse_function=IPParse.parse_ip):
        self.packet = thebytes
        self.fields = parse_function(self.packet)
        for field in self.fields.keys():
            if not field.startswith('_'):
                setattr(self, field, self.fields[field])
    def __repr__(self):
        return str(self.fields)

class ICMPPacket(IPPacket):
    def __init__(self, thebytes):
        IPPacket.__init__(self, thebytes, IPParse.parse_icmp)

class TCPPacket(IPPacket):
    def __init__(self, thebytes):
        IPPacket.__init__(self, thebytes, IPParse.parse_tcp)

class UDPPacket(IPPacket):
    def __init__(self, thebytes):
        IPPacket.__init__(self, thebytes, IPParse.parse_udp)

class TracerouteHop(object):
    '''
    object to represent (and evaluate) the result of a traceroute probe

    tobject - Traceroute object related to this probe
    ttl - TTL for the probe
    msg - user message of status
    final - true if no need to probe again with higher TTL
    reached - true if destination was reached
    rxdata - layer 3 data to add to representation (UDP or TCP response)
    rxpacket - ICMP packet to parse

    if rxpacket is provided, we parse the ICMP packet (and if it is a
    TTL Expired packet, also its payload which should contain the IP header
    and first 8 bytes of our probe packet)
    '''
    def __init__(self, tobject, ttl, msg="Status Unknown", final=False, rxdata=None, rxpacket=None, reached=False):
        self.tobject = tobject
        self.ttl = ttl
        self.msg = msg
        self.final = final
        self.reached = reached
        self.rxdata = rxdata
        self.rxpacket = rxpacket
        if self.rxpacket is not None:
            self.ipfields = IPPacket(rxpacket)
            if self.ipfields.ip_protocol == IPProtocol.number("ICMP"):
                self.icmpfields = ICMPPacket(self.ipfields.payload)
                if self.icmpfields.icmp_type in (3, 11):
                    self.rp_ipfields = IPPacket(self.icmpfields.payload)
                    if self.rp_ipfields.ip_protocol == IPProtocol.number('UDP'):
                        self.rp_datafields = UDPPacket(self.rp_ipfields.payload)
                    elif self.rp_ipfields.ip_protocol == IPProtocol.number('TCP'):
                        self.rp_datafields = TCPPacket(self.rp_ipfields.payload)
                    elif self.rp_ipfields.ip_protocol == IPProtocol.number('ICMP'):
                        self.rp_datafields = ICMPPacket(self.rp_ipfields.payload)
            if self.tobject.options.debug:
                if self.ipfields.ip_protocol == IPProtocol.number("ICMP"):
                    print("ICMP {type}/{code} from {rxip}: {packet}".format(type=self.icmpfields.icmp_type, code=self.icmpfields.icmp_code, rxip=self.ipfields.ip_source_address, packet=self.rxpacket.encode("hex")))
                else:
                    print("IP packet data: {packet}".format(packet=self.ippfields))

    def ignorable(self):
        '''
        true if the ICMP packet recieved is not a response to our probe
        '''
        rx_icmp_typeswanted = (3, 11, 0) if self.tobject.icmp() else (3, 11)
        if self.icmpfields.icmp_type not in rx_icmp_typeswanted:
            if self.tobject.options.debug:
                print("...ignoring ICMP response, type {t} is not one of ICMP types {list} ".format(t=self.icmpfields.icmp_type, list=rx_icmp_typeswanted))
            return True
        if self.icmpfields.icmp_type == 0: # echo reply
            if self.ipfields.ip_source_address != self.tobject.destination_addr:
                if self.tobject.options.debug:
                    print("...ignoring ICMP echo reply from unexpected host {ip}".format(ip=self.ipfields.ip_source_address))
                return True
            if self.icmpfields.icmp_id == self.tobject.icmp_id and self.icmpfields.icmp_seq == self.ttl:
                return False # reached destination
        if self.rp_ipfields.ip_protocol != IPProtocol.number(self.tobject.proto) or self.rp_ipfields.ip_dest_address != self.tobject.destination_addr:
            if self.tobject.options.debug:
                print("...ignoring non-matching proto or dest ip response in returned packet: {proto}/{ip} ".format(proto=self.rp_ipfields.ip_protocol, ip=self.rp_ipfields.ip_protocol))
            return True
        if self.tobject.tcp() or self.tobject.udp():
            if self.rp_datafields.source_port != self.tobject.source_port or self.rp_datafields.dest_port != self.tobject.port:
                if self.tobject.options.debug:
                    print("ignoring non-matching TCP/UDP source or dest port number(s) in returned packet: {srcport}/{dstport}".format(srcport=self.rp_datafields.source_port, dstport=self.rp_datafields.dest_port))
                return True
        return False # this reply sure looks like an answer to our probe

    def __repr__(self):
        if self.rxpacket is not None:
            reachmsg = "Unreachable" if self.icmpfields.icmp_type == 3 else "Reached Destination"
            summary = "{ttl}\t{hostinfo} {msg}{reached}".format( \
                ttl=self.ttl, \
                hostinfo=self.tobject.hostname_of(self.ipfields.ip_source_address), \
                msg=self.msg, \
                reached=" [{msg}]".format(msg=reachmsg) if self.reached else "")
        else:
            summary = "{ttl}\t{msg}{banner}{reached}".format( \
                ttl=self.ttl, \
                msg=self.msg, \
                banner=", received data: {rxdata}".format(rxdata=pprint.pformat(str(self.rxdata), width=1000)) if self.rxdata else "", \
                reached=" [Reached Destination]" if self.reached and not self.rxdata else "")
        return summary


class Traceroute(object):
    '''
    traceroute "session" object where we store data re-used by each probe
    constructor returns ValueError for any conficting options
    '''

    def __init__(self, options, destination):
        self.options = options
        self.port = self.options.port
        if self.options.udp and self.options.icmp:
            raise ValueError("Cannot specify UDP and ICMP options together")
        if self.options.payload is not None:
            try:
                decode_hex(options.payload)
            except TypeError:
                raise(ValueError("the --payload argument must be a valid hex string"))
        if self.options.icmp and self.options.port is not None:
            raise(ValueError("the --port option is not meaningful for ICMP traceroute"))
        if self.options.udp:
            self.proto = "UDP"
        elif self.options.icmp:
            if platform.system() in ["AIX", "NetBSD"]:
                raise ValueError("ICMP mode not supported in AIX or NetBSD")
            self.proto = "ICMP"
            self.port = None
        else:
            self.proto = "TCP"
        if self.port is None:
            if self.options.udp:
                self.port = 33434 # default UDP port
            elif not options.icmp:
                self.port = 80    # default TCP port
        else:
            self.port = self.portnumber_of(self.port)
        if self.proto in ["TCP", "UDP"]:
            self.port = int(self.port)
        self.source_port = None
        if (is_windows() or is_cygwin()) and self.options.source_ip is None:
            self.windows_main_ip = get_windows_main_ip()
        else:
            self.windows_main_ip = None
        self.icmp_id = None
        self.icmp_socket = None
        self.send_tcp_socket = None
        self.send_udp_socket = None
        self.slist = []

        self.destination_str = destination
        try:
            self.destination_addr = socket.gethostbyname(destination)
        except socket.gaierror as oops:
            raise ValueError("The specified host name cannot be found: {oops}".format(oops=oops))
        portinfo = "" if self.proto == "ICMP" else " port {port}".format(port=self.port)
        self.header = "{proto} traceroute to {dest_name} [{dest_addr}]{portinfo}".format(proto=self.proto, dest_name=destination, dest_addr=self.destination_addr, portinfo=portinfo)

    def udp(self):
        return self.proto == "UDP"

    def tcp(self):
        return self.proto == "TCP"

    def icmp(self):
        return self.proto == "ICMP"

    def hostname_of(self, curr_ip):
        curr_name = curr_ip
        if not self.options.no_dns:
            try: # see if hostname exists for intermediate hop IP
                curr_name = socket.gethostbyaddr(curr_ip)[0]
            except socket.error:
                pass
        return "{name} ({ip})".format(name=curr_name, ip=curr_ip)

    def portnumber_of(self, port):
        try:
            port = int(port)
            if  port in range(0, 65536):
                return port
            raise socket.error("TCP port {p} is not a 16-bit positive integer".format(p=port))
        except ValueError:
            try:
                portnumber = socket.getservbyname(port)
                return portnumber
            except socket.error:
                raise ValueError("Unrecognized service name: {p}".format(p=port))

    def send_ping_packet(self, seq, data=""):
        packet = IPParse.pack_icmp(data, icmp_type=8, icmp_code=0, icmp_checksum=0, icmp_id=self.icmp_id, icmp_seq=seq)
        self.icmp_socket.sendto(packet, (self.destination_addr, 1))

    def probe(self, ttl):
        '''
        send a packet of the desired protocol with a crafted TTL
        and parse the ICMP TTL Exceeded response that (hopefully) comes
        back, or detect timeout or successfully contact with the remote host
        '''
        deadline = time.time() + self.options.wait_time
        sleep_interval = 0.05

        try:
            self._setup_sockets(ttl)
        except socket.error as oops:
            return TracerouteHop(self, ttl, "Unexpected local socket error: {oops}".format(oops=oops), final=True)

        banner_retries = self.options.banner_wait // sleep_interval

        # loop until an interesting packet arrives or timeout
        while time.time() < deadline:
            time.sleep(sleep_interval)
            try:
                if self.udp() and len(self.slist):
                    readable, writeable, exceptional = select.select(self.slist, self.slist, [], 0)
                    if len(readable):
                        rxdata = self.send_udp_socket.recv(120)
                        if len(rxdata):
                            self._close_sockets()
                            return TracerouteHop(self, ttl, "UDP port {port} responded".format(port=self.port), final=True, reached=True, rxdata=rxdata)
            except socket.error:
                pass

            if self.tcp() and len(self.slist):
                readable, writeable, exceptional = select.select(self.slist, self.slist, [], 0)
                if len(readable):
                    try:
                        rxdata = self.send_tcp_socket.recv(120)
                        # no exception, but is there data to read?
                        if len(rxdata):
                            self._close_sockets()
                            return TracerouteHop(self, ttl, "TCP port {port} connection successful".format(port=self.port), final=True, reached=True, rxdata=rxdata)
                    except ConnectionRefusedError:
                        self._close_sockets()
                        return TracerouteHop(self, ttl, "TCP port {port} connection refused".format(port=self.port), final=True, reached=True)
                    except socket.error as oops:
                        self.slist = []
                        if oops[0] == errno.ECONNREFUSED:
                            self._close_sockets()
                            return TracerouteHop(self, ttl, "TCP port {port} connection refused".format(port=self.port), final=True, reached=True)
                        # any other error uninteresting, keep waiting
                elif len(writeable):
                    if banner_retries > 0: # extra sleep in case banner shows up
                        banner_retries -= 1
                        continue
                    self._close_sockets()
                    return TracerouteHop(self, ttl, "TCP port {port} connection successful.".format(port=self.port), final=True, reached=True)
            try:
                rx_packet, rx_ip = self.icmp_socket.recvfrom(512)
                rx_ip = rx_ip[0]        # address returns as tuple
                hop = TracerouteHop(self, ttl, msg="received ICMP response", rxpacket=rx_packet)
                if hop.ignorable():
                    continue
                if self.icmp() and hop.icmpfields.icmp_type == 0:
                    hop.msg = "ICMP echo reply"
                    hop.final = True
                    hop.reached = True
                    self._close_sockets()
                    return hop
                if (self.udp() or self.tcp()) and hop.icmpfields.icmp_type == 3:
                    hop.final = True  # destination unreachable, game over
                    if hop.ipfields.ip_source_address == self.destination_addr:
                        hop.reached = True
                hop.msg = " " + ICMPFields.CodeString(hop.icmpfields.icmp_type, hop.icmpfields.icmp_code, verbose=self.options.verbose)
                self._close_sockets()
                return hop
            except socket.error:
                time.sleep(sleep_interval)
                continue
        self._close_sockets()
        return TracerouteHop(self, ttl, "*\ttimed out")

    def _bind_source_info(self, sock, is_icmp_socket=False):
        if self.windows_main_ip is not None:
            sip = self.windows_main_ip
        else:
            sip = self.options.source_ip if self.options.source_ip is not None else ''
        sport = self.portnumber_of(self.options.source_port) if self.options.source_port is not None else 0
        if (sip, sport) == ('', 0):
            return
        sock.bind( (sip, sport if not is_icmp_socket else 0) )
        # if using Python for Windows, turn on raw socket "promiscuous" mode
        # this allows UDP traceroute to work
        # Cygwin doesn't support socket.ioctl and only ICMP mode works
        if is_windows() and is_icmp_socket and sip is not '':
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def _setup_sockets(self, ttl):
        '''
        create sockets needed for the traceroute and send the probe packet
        '''
        try:
            socket.setdefaulttimeout(self.options.wait_time)
            self.icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.icmp_socket.setblocking(0) # non-blocking
            self.icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except socket.error as oops:
            if oops[0] == errno.EPERM:
                platforminfo = " or run with a Python interpreter that has CAP_NET_RAW" if platform.system() == "Linux" else ""
                raise IOError("Permission denied.  Try again as a privileged user" + platforminfo + ". Error was {oops}".format(oops=oops))
            else:
                raise EnvironmentError("Unexpected socket error: {error}: {oops}".format(error=sys.exc_info()[1], oops=oops))
        if self.proto == "UDP":
            self.send_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, IPProtocol.number("UDP"))
            self._bind_source_info(self.send_udp_socket)
            self.send_udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            self.send_udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        elif self.proto == "TCP":
            self.send_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.send_tcp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            self.send_tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.send_tcp_socket.settimeout(self.options.wait_time)
            self.send_tcp_socket.setblocking(0) # non-blocking
            self._bind_source_info(self.send_tcp_socket)

        self._bind_source_info(self.icmp_socket, is_icmp_socket=True)
        if self.tcp():
            self.send_tcp_socket.connect_ex((self.destination_addr, self.port))
            # we don't expect a non-blocking socket to connect immediately
            # so we ignore result and will come back later
            self.slist = [self.send_tcp_socket]
            self.source_port = self.send_tcp_socket.getsockname()[1]
        elif self.udp():
            self.slist = [self.send_udp_socket]
            if self.port == 53 and self.options.payload is None:
                # default UDP DNS payload: reverse lookup of 8.8.8.8
                payload = decode_hex("945a01000001000000000000013801380138013807696e2d61646472046172706100000c0001")
            else:
                payload = decode_hex(self.options.payload) if self.options.payload else bytearray('udp payload', 'ascii')
            self.send_udp_socket.sendto(payload, (self.destination_addr, self.port))
            self.source_port = self.send_udp_socket.getsockname()[1]
        elif self.icmp():
            self.icmp_id = os.getpid() & 0xffff
            payload = decode_hex(self.options.payload) if self.options.payload is not None else bytearray('icmp payload', 'ascii')
            self.send_ping_packet(ttl, payload)
        else:
            raise EnvironmentError("self doesn't know what protocol to use")

    def _close_sockets(self):
        if self.proto == "TCP":
            self.send_tcp_socket.close()
        if self.proto == "UDP":
            self.send_udp_socket.close()
        self.icmp_socket.close()


def parse_options(argv=None):
    parser = optparse.OptionParser(usage="%prog [-p PORT] [other options] hostname")
    parser.add_option("-f", "--first-hop", dest="first_hop",
                      help="Starting hop (ttl) value [default: %default]",
                      default=1, type="int")
    parser.add_option("-m", "--max-hops",
                      help="Max hops before giving up [default: %default]",
                      default=30, type="int")
    parser.add_option("-n", "--no-dns",
                      help="do not lookup hostnames of IP addresses",
                      action="store_true", default=False)
    parser.add_option("-p", "--port", type="str", default=None,
                      help="port number or service name for UDP or TCP")
    parser.add_option("-s", "--source-ip", type="str", default=None,
                      help="interface IP to send probe traffic from")
    parser.add_option("-S", "--source-port", type="str", default=None,
                      help="source port for TCP/UDP probes")
    parser.add_option("-w", "--wait-time", default=2, type="int",
                  help="Timeout in seconds for each hop [default: %default]")
    parser.add_option("--banner-wait", default=0.5, type="int",
                  help="How long to wait for possible TCP banner output [default: %default]")
    parser.add_option("-U", "--udp", help="Use UDP protocol [default: TCP]",
                      action="store_true", default=False)
    parser.add_option("-I", "--icmp", help="Use ICMP protocol [default: TCP]",
                      action="store_true", default=False)
    parser.add_option("-P", "--payload", type="str", default=None,
                  help="hex string to use as data in UDP or ICMP probe packet")
    parser.add_option("-D", "--debug",
                      help="dump packets and other debugging info",
                      action="store_true", default=False)
    parser.add_option("-v", "--verbose", action="store_true", default=False, help="verbose output")
    options, args = parser.parse_args(argv)

    if len(args) != 1:
        parser.error("missing destination address, please see the --help option")

    return (options, args)

def android_args():
    try:
        import androidhelper as android
    except ImportError:
        import android

    protocols = ['TCP', 'UDP', 'ICMP']
    host = None
    port = None
    droid = android.Android()
    droid.dialogCreateInput(title='Destination Host', message='Hostname or IP', inputType='text')
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogShow()
    host = droid.dialogGetResponse().result['value']

    droid.dialogCreateAlert(title='Protocol', message='Choose the traceroute protocol')
    droid.dialogSetSingleChoiceItems(protocols)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogShow()
    proceed = droid.dialogGetResponse().result['which']
    protoindex = droid.dialogGetSelectedItems().result[0]

    if protoindex != 2:
        droid.dialogCreateInput(title='Port Number', message='Port', inputType='number', defaultText='80')
        droid.dialogSetPositiveButtonText('OK')
        droid.dialogShow()
        port = droid.dialogGetResponse().result['value']
    else:
        port = ''

    proto = protocols[protoindex].lower()
    results = []
    if proto in ["icmp", "udp"]:
        results.append("--" + proto)
    if proto != "icmp":
        results.extend(["--port", port])
    results.append(host)
    return results

def is_android():
    ''' lame way to detect Android platform '''
    return "ANDROID_STORAGE" in os.environ

def is_windows():
    ''' detect Windows platform '''
    return platform.system() == "Windows"

def is_cygwin():
    ''' Cygwin under Windows, raw sockets don't work as well '''
    return platform.system().startswith("CYGWIN")

def get_windows_main_ip():
    '''
    Windows raw sockets must be bound to an interface, and you bind to
    an interface by specifying the interface IP address. If the Windows
    caller did not use the --source-ip option then we will assume they
    want to use the "main" interface, the first one with a default route.
    '''
    routeinfo = str(subprocess.check_output(["netstat", "-rn"]))
    try:
        return re.search(r'\b0\.0\.0\.0\s+0\.0\.0\.0\s+\S+\s+(\S+)', routeinfo).group(1).strip()
    except (IndexError, AttributeError):
        raise EnvironmentError('unable to parse "netstat -rn" output to determine the IP of the interface with the default route')

def qpython_invocation(script=__file__):
    # are we in the Android QPython normal user environment?
    # if so, we'll need to become root
    qpbin = '/data/user/0/org.qpython.qpy/files/bin/'
    args =sys.argv[1:]
    if os.getuid() != 0:
        rc = os.system('su root sh -c "source {qpbin}/init.sh; {qpbin}/python-android5 {myname} {args}"'.format(qpbin=qpbin, myname=script, args=' '.join(args)))
        sys.exit(rc)
    if len(args) == 0:
            args = android_args()  # proto, host, port
            sys.exit(main(args))

def main(cmdline=sys.argv[1:]):
    (options, args) = parse_options(cmdline)
    try:
        trace = Traceroute(options, args[0])
        print(trace.header)
        ttl = options.first_hop
        while ttl <= max(options.max_hops, options.first_hop):
            thishop = trace.probe(ttl)
            print(thishop)
            if thishop.final:
                break
            ttl += 1
        print("{reachmsg} destination".format(reachmsg="Successfully reached" if thishop.reached else "Could not reach"))
        return 0 if thishop.reached else 1
    except (ValueError, IOError) as oops:
        print("invalid parameters: {oops}".format(oops=oops))
        return 2


if __name__ == "__main__":
    try:
        if is_cygwin():
            print("Warning: this code does not fully function under Cygwin")
        if is_android():
            qpython_invocation()
        else:
            sys.exit(main())
    except KeyboardInterrupt:
        print("...interrupted...")
        sys.exit(30)
