import dpkt

fy = open('youtube.pcap', 'rb')
pcapy = dpkt.pcap.Reader(fy)
you_q1_TCP = 0
you_q1_UDP = 0

    
for ts,buf in pcapy:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    ans = str(repr(ip.data))
    i = 0
    got = ""
    while i < len(ans) and ans[i] != "(":
        got = got + ans[i]
        i = i +1

    if got == "TCP":
        you_q1_TCP = you_q1_TCP + 1
    if got == "UDP":
        you_q1_UDP = you_q1_UDP + 1
        
print(you_q1_TCP, you_q1_UDP)
################################################################################


