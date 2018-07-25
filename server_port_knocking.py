from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP
from struct import unpack

from multiprocessing import Process, Queue

# for i in "3" "4" "1"; do nc 127.0.0.1 ${i}; done 


# global
BUFFSIZE = 2048


# config
ports = [3, 4, 1]
timeout = 5 


def get_iph_length(packet_bytes):
        ip_header = packet_bytes[0:20]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        return iph_length


def get_dest_port(iph_length, packet_bytes):
        tcp_header = packet_bytes[iph_length:iph_length+20]
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        dest_port = tcph[1]
        return dest_port


def sniffer(port, queue=None):
    while True:
        packet = s.recvfrom(BUFFSIZE)
        packet_bytes = packet[0]

        iph_length = get_iph_length(packet_bytes)
        dest_port = get_dest_port(iph_length, packet_bytes)

        if dest_port == port:
            print('Port {} OK'.format(port))
            break
    if queue:
        queue.put(None)


def timeout_sniffer(port):
    queue = Queue()
    proc = Process(target=sniffer, args=(port, queue, ))
    proc.start()
    try:
        queue.get(timeout=timeout)
        proc.join()
        return False
    except:
        proc.terminate()
        return True


def check_sequence(s):
    # wait for first port without timeout
    sniffer(ports[0])

    # wait for others ports with timeout
    for port in ports[1:]:
        timeout = timeout_sniffer(port)
        if timeout:
            print('Port {} TIMEOUT'.format(port))
            return False
    return True
 

if __name__ == '__main__':
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    while True:
        print('Listening ports: {} {} {}'.format(*ports)) 
        if check_sequence(s):
            print("SEQUENCE OK")
        else:
            print("SEQUENCE NOK")
    s.close()
