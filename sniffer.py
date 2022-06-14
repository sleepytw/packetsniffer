import socket
import struct
import textwrap

'''
Since AF_PACKET doesn't work on windows we have to resort to isolating each packet individually therefore
the ethernet_frame is useless because it will keep sending the wrong info and it will never check for the
right protocol, hence we have to make the ipv4 protocol the main one instead so we can trace packets as 
they are.
'''

ip = socket.gethostbyname(socket.gethostname())
port = 80

def sniff():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((ip, port))

    #sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #sock.connect {TCP}
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) #sock.bind {ANY}

    while True:
        raw_data, addr = sock.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('\tDestination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # eth_proto 8 for ipv4 but its our main one so its useless.
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(raw_data)
        print('\t\n- IPv4 Packet:')
        print('\t\t- Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        print('\t\t\t- Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(raw_data)
            print('\t\n- ICMP Packet:')
            print('\t\t- Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
            print('\t\t- Data:')
            print(format_multi_line('\t\t\t', data))

         # TCP
        elif proto == 6:
            (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
            flag_fin, data) = tcp_segment(raw_data)
            print('\t\n- TCP Segment:')
            print('\t\t- Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
            print('\t\t- Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
            print('\t\t- Flags:')
            print('\t\t\t- URG: {}, ACK: {}, PSH: {}, RST: {}, SYN:{}, FIN: {}'.format(flag_urg, flag_ack, flag_psh,
                                                                                           flag_rst, flag_syn,
                                                                                           flag_fin))
            print('\t\t- Data:')
            print(format_multi_line('\t\t\t', data))

        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(raw_data)
            print('\t\n- UDP Segment:')
            print('\t\t- Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
            print('\t- Data:')
            print('\t\t'+format_multi_line('\t\t', data))

        # Other
        else:
          print('\t- Data:')
          print('\t\t' + format_multi_line('\t\t', data))

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Returns properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Unpack the IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

sniff()