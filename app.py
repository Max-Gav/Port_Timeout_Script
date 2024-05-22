import threading
from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

PROXY_PORT = 8080
SERVER_PORT = 1236
PROXY_DELAY = 10
recv_queue = []
sent_queue = []
recv_status = False
sent_status = False
status_mutex = threading.Lock()

def check_queues() -> None:
    print(recv_queue)
    print(sent_queue)
    print("")
    if recv_queue[0]:
        found_flag = False

        for index in range(0, 10):
            if sent_queue[index]:
                found_flag = True
                break

        if not found_flag:
            print("Close Proxy")
        else:
            print("Successful check")

    recv_queue.pop(0)
    sent_queue.pop(0)


def update_status() -> None:
    global recv_status
    global sent_status

    with status_mutex:
        recv_queue.append(recv_status)
        sent_queue.append(sent_status)

        recv_status = False
        sent_status = False


def proxy_check() -> None:
    check_queues()
    update_status()
    threading.Timer(interval=1, function=proxy_check).start()


def packet_callback(packet: Ether) -> None:
    global recv_status
    global sent_status

    if packet[TCP].dport == PROXY_PORT:
        print("Received")
        with status_mutex:
            recv_status = True

    elif packet[TCP].dport == SERVER_PORT:
        print("Sent")
        with status_mutex:
            sent_status = True

    # if packet.haslayer(Raw) and True:
    #     print(packet.summary())
    #     print(packet[TCP].sport)
    #     print(packet[TCP].dport)
    #     print("Seq: " + str(packet[TCP].seq) + " ,Ack:" + str(packet[TCP].ack))
    #     print("\n\n")


def fill_queues() -> None:
    for i in range(0, PROXY_DELAY):
        recv_queue.append(False)
        sent_queue.append(False)


if __name__ == '__main__':
    fill_queues()
    threading.Timer(interval=1, function=proxy_check).start()
    sniff(prn=packet_callback, filter=f'tcp and ( port {PROXY_PORT} or port {SERVER_PORT} )', store=0)
