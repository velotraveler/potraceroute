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
