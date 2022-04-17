from scapy.all import *
from scapy.layers.inet import ICMP, IP

def spoof_reply(icmp_request):
    if icmp_request[ICMP].type == 8:
        print('---- ICMP REQUEST ----')
        print('Source IP: ', icmp_request[IP].src)
        print('Destination IP: ', icmp_request[IP].dst)
        print('ICMP Sequence: ', hex(icmp_request[ICMP].seq))
        print('ICMP CheckSum: ', hex(icmp_request[ICMP].chksum))
        #icmp_request.show()

        src = icmp_request[IP].dst
        dst = icmp_request[IP].src
        seq = icmp_request[ICMP].seq
        id = icmp_request[ICMP].id
        load = icmp_request[ICMP].load

        icmp_reply = IP(src=src, dst=dst)/ICMP(type=0, id=id, seq=seq)/load

        print('\n---- ICMP REPLY ----')
        icmp_reply.show2()

        send(icmp_reply)

if __name__ == '__main__':
    icmp_pkts = sniff(filter='icmp', prn=spoof_reply, count=5)
