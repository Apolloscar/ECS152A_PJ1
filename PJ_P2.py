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


endpoint_printed = []

device_dest = [[] for Null in range(256)]


for ts, buf in pcap:
    
    eth = dpkt.ethernet.Ethernet(buf)
    
    
    if not isinstance(eth.data, dpkt.ip.IP) :

        continue
    ip = eth.data
    ipa_src = str(inet_to_str(ip.src))
    ipa_Sections_src = [""] *4
    ipa_Sections_integers_src = [0]*4
    i =0 
    j = 0
    while i < len(ipa_src):
        if ipa_src[i] == '.':
            j += 1
            i = i+1
        ipa_Sections_src[j] += ipa_src[i]
        i += 1

    ipa_Sections_integers_src[0] = int(ipa_Sections_src[0])
    ipa_Sections_integers_src[1] = int(ipa_Sections_src[1])
    ipa_Sections_integers_src[2] = int(ipa_Sections_src[2])
    ipa_Sections_integers_src[3] = int(ipa_Sections_src[3])

    
    

    ipa_dst = str(inet_to_str(ip.dst))
    ipa_Sections_dst= [""] *4
    ipa_Sections_integers_dst = [0]*4
    i =0 
    j = 0
    while i < len(ipa_dst):
        if ipa_dst[i] == '.':
            j += 1
            i = i+1
        ipa_Sections_dst[j] += ipa_dst[i]
        i += 1

    ipa_Sections_integers_dst[0] = int(ipa_Sections_dst[0])
    ipa_Sections_integers_dst[1] = int(ipa_Sections_dst[1])
    ipa_Sections_integers_dst[2] = int(ipa_Sections_dst[2])
    ipa_Sections_integers_dst[3] = int(ipa_Sections_dst[3])


    if ipa_Sections_integers_src[0] == 10 and ipa_Sections_integers_src[1] == 42 and ipa_Sections_integers_src[2] == 0 and ipa_Sections_integers_src[3] > 1 and ipa_Sections_integers_src[3] < 256:
        device_sent[ipa_Sections_integers_src[3]] += 1

        printer = 1
        for k in endpoint_printed:
            if k == ipa_dst:
                printer = 0
        
        if printer == 1:

            found = 0
            n = 2

    
            while n < len(device_dest) and found == 0:
                
                if n == ipa_Sections_integers_src[3]:
                    n += 1

                if n >= len(device_dest):
                    break

                for m in device_dest[n]:
                    if m == ipa_dst:
                        found = 1
                        break
                n += 1

            if found == 1:
                endpoint_printed.append(ipa_dst)
                
            else:
                device_dest[ipa_Sections_integers_src[3]].append(ipa_dst)
                

          

            

    if ipa_Sections_integers_dst[0] == 10 and ipa_Sections_integers_dst[1] == 42 and ipa_Sections_integers_dst[2] == 0 and ipa_Sections_integers_dst[3] > 1 and ipa_Sections_integers_dst[3] < 256:
        device_recieved[ipa_Sections_integers_dst[3]] += 1

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

print("IP adress that at least two devices have sent to:")

i = 1
for j in endpoint_printed:
    print(str(i) + ".\t" + j)
    i += 1


    
f.close()
