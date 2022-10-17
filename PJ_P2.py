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
device_sent = [0]*256
device_recieved = [0]*256


for ts, buf in pcap:
    
    eth = dpkt.ethernet.Ethernet(buf)
    
    
    if not isinstance(eth.data, dpkt.ip.IP) :

        continue
    ip = eth.data
    ipa_src = str(inet_to_str(ip.src))
    ipa_Sections = [""] *4
    ipa_Sections_integers = [0]*4
    i =0 
    j = 0
    while i < len(ipa_src):
        if ipa_src[i] == '.':
            j += 1
            i = i+1
        ipa_Sections[j] += ipa_src[i]
        i += 1

    ipa_Sections_integers[0] = int(ipa_Sections[0])
    ipa_Sections_integers[1] = int(ipa_Sections[1])
    ipa_Sections_integers[2] = int(ipa_Sections[2])
    ipa_Sections_integers[3] = int(ipa_Sections[3])
    if ipa_Sections_integers[0] == 10 and ipa_Sections_integers[1] == 42 and ipa_Sections_integers[2] == 0 and ipa_Sections_integers[3] > 1 and ipa_Sections_integers[3] < 256:
        device_sent[ipa_Sections_integers[3]] += 1

    ipa_dst = str(inet_to_str(ip.dst))
    ipa_Sections= [""] *4
    ipa_Sections_integers = [0]*4
    i =0 
    j = 0
    while i < len(ipa_dst):
        if ipa_dst[i] == '.':
            j += 1
            i = i+1
        ipa_Sections[j] += ipa_dst[i]
        i += 1

    ipa_Sections_integers[0] = int(ipa_Sections[0])
    ipa_Sections_integers[1] = int(ipa_Sections[1])
    ipa_Sections_integers[2] = int(ipa_Sections[2])
    ipa_Sections_integers[3] = int(ipa_Sections[3])
    if ipa_Sections_integers[0] == 10 and ipa_Sections_integers[1] == 42 and ipa_Sections_integers[2] == 0 and ipa_Sections_integers[3] > 1 and ipa_Sections_integers[3] < 256:
        device_recieved[ipa_Sections_integers[3]] += 1

devices = 0

for i in range(0,256):
    if device_sent[i] > 0:
        devices = devices + 1

print("Devices:",devices)

most_packets_sent = max(device_sent)
index_of_most_packets_sent = device_sent.index(most_packets_sent)

print("IP adress of device with most sent packets is :10.42.0." + str(index_of_most_packets_sent))

most_packets_recieved = max(device_recieved)
index_of_most_packets_recieved = device_recieved.index(most_packets_recieved)

print("IP adress of device with most recieved packets is: 10.42.0." + str(index_of_most_packets_recieved))
    
f.close()
    
    
