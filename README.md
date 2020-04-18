potraceroute - a portable Python TCP/UDP/ICMP traceroute tool
=============================================================

This project grew out of my experience as a system/network administrator
in a heavily firewalled environment. TCP traceroute was the best
way to check if a connection was being blocked by a firewall,
but the Windows, Solaris, and AIX hosts on our network only supported
UDP or ICMP traceroute.  Installing binaries on the hosts I was asked to
troubleshoot was not an option, so I wrote a traceroute utility in Python
that could be easily copied onto the target computer, via copy/paste if
necessary.

## FEATURES
* single Python file runs on Linux, MacOS, NetBSD, FreeBSD, OpenBSD, Solaris,
Windows 10, Android (root access needed, tested on LineageOS 14.1 with
QPython 2.5.0) and AIX.
* supports TCP/UDP/ICMP traceroute
* runs under Python 2.7 or Python 3
* says what kind of traceroute is being run and to what port, so there's
less chance of misinterpreting the output compared to standard traceroute
* shows clearly whether the destination host was reached, and whether
the TCP connection was accepted or refused
* displays the banner printed by a TCP service like SSH or SMTP if the
connection was successful
* lets you specify a custom payload in the probe packets
* default payload for UDP port 53 elicits a DNS response
* debug mode displays received ICMP packets
* can be used as a module - code can send probes for individual traceroute
hops and inspect the results (see below for examples)

## COMMAND-LINE OPTIONS
```
  -f FIRST_HOP, --first-hop=FIRST_HOP
                        Starting hop (ttl) value [default: 1]
  -m MAX_HOPS, --max-hops=MAX_HOPS
                        Max hops before giving up [default: 30]
  -n, --no-dns          do not lookup hostnames of IP addresses
  -p PORT, --port=PORT  port number or service name for UDP or TCP
  -s SOURCE_IP, --source-ip=SOURCE_IP
                        interface IP to send probe traffic from
  -S SOURCE_PORT, --source-port=SOURCE_PORT
                        source port for TCP/UDP probes
  -w WAIT_TIME, --wait-time=WAIT_TIME
                        Timeout in seconds for each hop [default: 2]
  --banner-wait=BANNER_WAIT
                        How long to wait for possible TCP banner output
                        [default: 0.5]
  -U, --udp             Use UDP protocol [default: TCP]
  -I, --icmp            Use ICMP protocol [default: TCP]
  -P PAYLOAD, --payload=PAYLOAD
                        hex string to use as data in UDP or ICMP probe packet
  -D, --debug           dump packets and other debugging info
  -v, --verbose         verbose output
```

## COMMAND-LINE EXAMPLES
* UDP traceroute on port 53 to a DNS server:
```
sudo ./potraceroute.py 8.8.8.8 --udp --port 53
Password:
UDP traceroute to 8.8.8.8 [8.8.8.8] port 53
1	192.168.1.1 (192.168.1.1)  ICMP 11/0
2	*	timed out
3	be56.nycvnyjj01h.nyc.rr.com (68.173.202.56)  ICMP 11/0
4	agg110.nyclnyrg01r.nyc.rr.com (68.173.198.112)  ICMP 11/0
5	bu-ether29.nwrknjmd67w-bcr00.tbone.rr.com (107.14.19.24)  ICMP 11/0
6	66.109.5.138 (66.109.5.138)  ICMP 11/0
7	0.ae2.pr0.nyc20.tbone.rr.com (107.14.19.147)  ICMP 11/0
8	ix-ae-10-0.tcore1.n75-new-york.as6453.net (66.110.96.13)  ICMP 11/0
9	72.14.195.232 (72.14.195.232)  ICMP 11/0
10	74.125.251.231 (74.125.251.231)  ICMP 11/0
11	216.239.62.149 (216.239.62.149)  ICMP 11/0
12	UDP port 53 responded, received data: '\x94Z\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x018\x018\x018\x018\x07in-addr\x04arpa\x00\x00\x0c\x00\x01\xc0\x0c\x00\x0c\x00\x01\x00\x002\x1b\x00 \x13google-public-dns-a\x06google\x03com\x00'
Successfully reached destination
```
* TCP traceroute to an SMTP server:
```
$ sudo ./potraceroute.py smtp.gmail.com -p 25
TCP traceroute to smtp.gmail.com [173.194.208.108] port 25
1	192.168.1.1 (192.168.1.1)  ICMP 11/0
2	*	timed out
3	be56.nycvnyjj02h.nyc.rr.com (68.173.202.58)  ICMP 11/0
4	agg110.nyquny9101r.nyc.rr.com (68.173.198.114)  ICMP 11/0
5	bu-ether25.nycmny837aw-bcr00.tbone.rr.com (107.14.19.22)  ICMP 11/0
6	0.ae2.pr0.nyc20.tbone.rr.com (107.14.19.147)  ICMP 11/0
7	ix-ae-10-0.tcore1.n75-new-york.as6453.net (66.110.96.13)  ICMP 11/0
8	72.14.195.232 (72.14.195.232)  ICMP 11/0
9	*	timed out
10	216.239.62.168 (216.239.62.168)  ICMP 11/0
11	108.170.248.84 (108.170.248.84)  ICMP 11/0
12	216.239.62.196 (216.239.62.196)  ICMP 11/0
13	108.170.236.133 (108.170.236.133)  ICMP 11/0
14	216.239.48.31 (216.239.48.31)  ICMP 11/0
15	72.14.234.238 (72.14.234.238)  ICMP 11/0
16	216.239.54.69 (216.239.54.69)  ICMP 11/0
17	*	timed out
18	*	timed out
19	*	timed out
20	*	timed out
21	*	timed out
22	*	timed out
23	*	timed out
24	*	timed out
25	*	timed out
26	TCP port 25 connection successful, received data: '220 smtp.gmail.com ESMTP 17sm4638913qkg.30 - gsmtp\r\n'
Successfully reached destination
```

## PROGRAMMATIC EXAMPLES
```
from potraceroute import Traceroute, parse_options
import sys
dest = "google.com" if len(sys.argv) != 2 else sys.argv[1]
(options, args) = parse_options(["--port", "443", dest])
t = Traceroute(options, dest)
hop = t.probe(1)
if hop.reached:
    print("we are only one hop away from {dest}".format(dest=dest))
else:
    print("First hop is {ip}".format(ip=hop.ipfields.ip_source_address))

hop = t.probe(32)
print("{r} {dest}.".format(r="reached" if hop.reached else "could not reach", dest=dest))
```
For more examples, see the file tests/test_potraceroute.py

## LIMITATIONS / POSSIBLE FUTURE WORK
* Add MTU detection
* ICMP mode does not work as expected on AIX and NetBSD, the network
stack seems to ignore the TTL setting on raw ICMP sockets.
Should be possible using a raw IP socket instead.
* The state of a successful TCP probe (i.e. connection accepted or
connection refused) is not clearly returned to a programmatic caller
* Specifying options to the Traceroute class is a little clumsy
* TCP traceroute no longer works on Windows 7 (it used to, really!).
The underlying problem (ICMP TTL Expired packets are diverted by the
Windows networking stack and not given to the raw socket) is described at
https://github.com/traviscross/mtr/issues/55#issuecomment-257780611
* On Windows 10, potraceroute works in all modes with Python for Windows
2.7.16, but under Cygwin 10 only ICMP mode works, presumably due to lack of
support for SIO_RCVALL in Cygwin.
* On Windows 10, the default configuration of Windows Defender blocks Python
scripts from receiving the ICMP unreachable responses. The script works
when the firewall is disabled. Custom firewall rules might allow script to
co-exist with the firewall. The default "allow application" rules are not
sufficient as they don't cover incoming ICMP.
* TCP traceroute to 127.0.0.1 does not work on NetBSD 6 (EINVAL error)
* banner-wait option doesn't work if value exceeds wait-time option
* Android interface uses the very limited GUI provided by QPython, ideally
should be packaged as an app with an interface that exposes all the
command-line options.

## SHOUTOUTS AND HAT TIPS
Along with the NetBSD traceroute source code (which includes Van Jacobson's
1988 comment "Don't use this as a coding example"), these two Python
scripts provided useful demonstrations of traceroute:
*  https://github.com/leonidg/Poor-Man-s-traceroute/blob/master/traceroute.py
*  http://www.thomas-guettler.de/scripts/tcptraceroute.py.txt
