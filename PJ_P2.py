import dpkt

import socket
from dpkt.compat import compat_ord
def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
        
f = open('project1_part2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
device = [0]*256
print(pcap)
for ts, buf in pcap:
    
    eth = dpkt.ethernet.Ethernet(buf)
    
    
    if not isinstance(eth.data, dpkt.ip.IP) :

        continue
    ip = eth.data
    print(inet_to_str(ip.src))

    
    
    
    