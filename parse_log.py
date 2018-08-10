#!/usr/bin/env python3

import itertools
import statistics
import pygeoip
import collections
import datetime
import re
import sys

# Dec  5 16:44:12 PAROUTER kern.warn kernel: DROP IN=vlan1 OUT= MAC=30:85:a9:69:5c:5d:00:76:86:45:e4:1a:08:00:45:00:00:28 SRC=181.138.51.128 DST=24.36.37.202 LEN=40 TOS=0x00 PREC=0x00 TTL=53 ID=43811 PROTO=TCP SPT=44249 DPT=23 SEQ=405022154 ACK=0 WINDOW=64643 RES=0x00 SYN 

def parse_log_file(fd):
    class Packet:
        timestamp = 0
        params = ""
        flags = ""

    fmt = "^(\w+ +\d+ \d+:\d+:\d+) ([\w.]*) .*?: DROP (.*)$"
    packets = []
    for line in fd.readlines():
        m = re.match(fmt, line)
        if (not m): continue

        (date, host, params) = m.groups()
        year = str(datetime.datetime.now().year)
        date = datetime.datetime.strptime(date+" "+year, "%b %d %H:%M:%S %Y")

        #args = [arg.split("=") for arg in params.strip().split(" ")]
        #try:
        #    args = dict(args)
        #except:
        #    print(line)

        packet = Packet()
        packet.timestamp = date.timestamp()
        packet.params = {}
        packet.flags = []
        for param in params.strip().split(" "):
            try:
                key, value = param.split("=")
                packet.params[key] = value
            except ValueError:
                packet.flags.append(param)
        packets.append(packet)

    packets.sort(key=lambda p : p.timestamp)
    return packets

def load_tor_exit_ips(fname):
    lst = []
    for line in open(fname):
        if (line.startswith("ExitAddress")):
            ip = line.split()[1]
            lst.append(ip)
    return lst

###

tor_ips = load_tor_exit_ips("exit-addresses")

gi = pygeoip.GeoIP('/usr/share/GeoIP/GeoLiteCity.dat')

packets = parse_log_file(sys.stdin)

hits_by_ip = collections.Counter()
hits_by_conn = collections.Counter()
hits_by_port = collections.Counter()
hits_by_country = collections.Counter()
hits_by_src_port = collections.Counter()
times_by_conn = collections.defaultdict(list)

for packet in packets:
    ip = packet.params["SRC"]
    port = int(packet.params["DPT"])
    src_port = int(packet.params["SPT"])
    country = gi.country_name_by_addr(ip)
    hits_by_ip[ip] += 1
    hits_by_conn[ip, port] += 1
    hits_by_port[port] += 1
    hits_by_country[country] += 1
    hits_by_src_port[src_port] += 1
    times_by_conn[ip, port].append(packet.timestamp)

print('')
print("*** Connections by host and port ***")
print("")
for (ip, port), hits in hits_by_conn.most_common():
    country = gi.country_name_by_addr(ip)
    rec = gi.record_by_addr(ip)
    lat = rec['latitude']
    lon = rec['longitude']

    times = times_by_conn[ip, port]
    dt = [a-b for a, b in zip(times[1:], times)]
    mean_dt = 0
    stdev_dt = 0
    if (len(dt) > 0):
        mean_dt = statistics.mean(dt)
        if (len(dt) > 1):
            stdev_dt = statistics.stdev(dt)

    if (ip in tor_ips):
        extra = " (TOR)"
    else:
        extra = ""

    print("%15s -> %5s | %3d | %6.1f %6.1f | %s%s" % (
        ip, port, hits, 
        mean_dt/60.0, stdev_dt/60.0,
        country, extra))

print('')
print("*** Connections by host ***")
print("")
for ip, hits in hits_by_ip.most_common():
    country = gi.country_name_by_addr(ip)
    rec = gi.record_by_addr(ip)
    lat = rec['latitude']
    lon = rec['longitude']

    print("%15s -- %3d (%s)" % (ip, hits, country))

print('')
print("*** Connections by country ***")
print("")
for country, hits in hits_by_country.most_common():
    print("%-20s -- %-3d" % (country, hits))

print("")
print("*** Connection by port ***")
print("")
for port in sorted(hits_by_port):
    print("%5s -- %3d" % (port, hits_by_port[port]))

print("")
print("*** Connection by source port ***")
print("")
for port in sorted(hits_by_src_port):
    print("%5s -- %3d" % (port, hits_by_src_port[port]))

print("")
print("*** Top popular ports ***")
print("")
total_hits = sum(hits_by_port.values())
for port, hits in hits_by_port.most_common():
    if (hits/total_hits < 0.01):
        break
    print("%5s -- %3d" % (port, hits))
