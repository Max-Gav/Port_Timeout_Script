from scapy.all import *
from scapy.layers.inet import TCP

def packet_callback(packet):
    if packet.haslayer(Raw) and True:
        # print(packet.summary())
        print(packet[TCP].sport)
        print(packet[TCP].dport)
        print("Seq: " + str(packet[TCP].seq) + " ,Ack:" + str(packet[TCP].ack))
        print("\n\n")

sniff(prn=packet_callback, filter="tcp and port 443", store=0)
