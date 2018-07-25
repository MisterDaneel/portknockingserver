from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP
from struct import unpack

# for i in "3" "4" "1"; do nc 127.0.0.1 ${i}; done 


# global
BUFFSIZE = 2048


# config
ports = [3, 4, 1]


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


def sniffer(port):
    while True:
        packet = s.recvfrom(BUFFSIZE)
        packet_bytes = packet[0]

        iph_length = get_iph_length(packet_bytes)
        dest_port = get_dest_port(iph_length, packet_bytes)

        if dest_port == port:
            print('Port {} OK'.format(port))
            return

if __name__ == '__main__':
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    print('Listening ports: {} {} {}'.format(*ports)) 
    for port in ports:
        sniffer(port)
