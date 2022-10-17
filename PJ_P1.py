import dpkt

fy = open('youtube.pcap', 'rb')
pcapy = dpkt.pcap.Reader(fy)
you_q1_TCP = 0
you_q1_UDP = 0
you = 0
    
for ts, buf in pcapy:

    eth = dpkt.ethernet.Ethernet(buf)
    you += 1
    if not isinstance(eth.data, dpkt.ip.IP) :
        print('Non IP Packet type not supported %s' % eth.data.__class__.__name__)
        continue

    ip = eth.data
    tcp = ip.data
    if isinstance(tcp, dpkt.tcp.TCP):
        you_q1_TCP += 1
    if isinstance(tcp, dpkt.udp.UDP):
        you_q1_UDP += 1

print("Youtube TCP packets:", you_q1_TCP)
print("Youtube UDP packets:", you_q1_UDP)

################################################################################
fy.close()
fy = open('youtube.pcap', 'rb')
pcapy = dpkt.pcap.Reader(fy)
you = 0
for ts, buf in pcapy:
    
    eth = dpkt.ethernet.Ethernet(buf)
  
    if not isinstance(eth.data, dpkt.ip.IP):
        continue

    ip = eth.data
    tcp = ip.data
    

    """
    else:
              


        if tcp.dport == 80 and len(tcp.data) > 0:
            print('HTTP Request')

            print('Source Port: %s' % tcp.sport)
            print('Destination Port: %s' % tcp.dport)
            if len(tcp.data) > 0:
                try:
                    http = dpkt.http.Request(tcp.data)
                    print(http)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue
        elif tcp.sport == 80 and len(tcp.data) >= 0:
            print('HTTP Response')

            print('Source Port: %s' % tcp.sport)
            print('Destination Port: %s' % tcp.dport)
            if len(tcp.data) > 0:
                try:
                    http = dpkt.http.Response(tcp.data)
                    print(http.body.decode())
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue
        else:

            continue
        """