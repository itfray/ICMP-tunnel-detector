import socket
import sys
import net_header
import eth_dix_header
import ipv4header
import icmpheader
import pcap_file
import time
import argparse
import icmp_analyzer
import datetime


def print_message(msg):
    print(f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")}] {msg}')


DEFAULT_TIMEOUT = 10                        # default value, how many minutes will be work sniffer
DEFAULT_PCAP_FILENAME = 'snffed_packets'    # default filename for sniffer's pcap file
DEFAULT_LISTEN_ADDR = socket.gethostbyname_ex(socket.gethostname())[2][-1]

def time_sec_usec()-> tuple:
    t_val = time.time()
    return int(t_val), int((t_val % 1) * 1000000)

class Sniffer:
    def __init__(self, **kwargs):
        self.__sys_platform__ = sys.platform
        self.analyzer = icmp_analyzer.ICMPAnalyzer()
        self.__socket = None
        self.eth_hdr = eth_dix_header.EthDixHeader(hdst_addr=b'\xb2\xad\x8c\xe4\x81\x09',
                                                   hsrc_addr=b'\x3a\x49\x73\x86\xf4\x22',
                                                   htype=0x0800).to_bytes()
        self.__listen_addr = kwargs.get('listen_addr', DEFAULT_LISTEN_ADDR)
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.filename = kwargs.get("filename", DEFAULT_PCAP_FILENAME)
        self.main_pcap_file = pcap_file.EthPCAPFile(self.filename, 'w')
        self.open_socket()

    def open_socket(self):
        if self.__socket is None:
            if self.__sys_platform__ == 'win32':
                self.__socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.__socket.bind((self.__listen_addr, 0))
                self.__socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.__socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.__socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def close_socket(self):
        if self.__socket:
            if self.__sys_platform__ == 'win32':
                self.__socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.__socket.close()
            del self.__socket
            self.__socket = None

    def __del__(self):
        self.close_socket()

    def run(self):
        timeout = self.timeout * 60
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.sniff()

    def sniff(self):
        packet, addr = self.__socket.recvfrom(65565)
        eth_offset = 0
        if self.__sys_platform__ != 'win32':
            eth_offset = eth_dix_header.EthDixHeader.Length
        ip_hdr = ipv4header.IPv4Header()
        ip_hdr.read_bytes_from(packet, eth_offset)

        if ip_hdr.protocol == net_header.PROTO_ICMP:
            if self.__sys_platform__ != 'win32':
                self.main_pcap_file.write(packet, *time_sec_usec())                # write received packet in pcap file
                answ = self.analyzer.analyze(packet, 34)
            else:
                self.main_pcap_file.write(self.eth_hdr + packet, *time_sec_usec())
                answ = self.analyzer.analyze(packet, 20)

            if answ[1] > 0.5:
                print_message(f"Possible tunnel detected: {ip_hdr.src_addr}:{answ[0]} --> {ip_hdr.dst_addr}")
                # print(answ)
                # print()
            # icmph = icmpheader.ICMPHeader()
            # icmph.read_bytes_from(packet, eth_offset + ip_hdr.header_length * 4)
            # print(ip_hdr)
            # print(icmph)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True, description="ICMP-tunneling: sniffer script")

    parser.add_argument('-la', '--listen_addr', dest='listen_addr', type=str, default=DEFAULT_LISTEN_ADDR,
                        help="Specifies the interface's address that listen icmp-traffic")

    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Specifies the timeout for sniffer operation')

    parser.add_argument('-f', '--file', dest='file', type=str, default=DEFAULT_PCAP_FILENAME,
                        help="Specifies the filename for sniffer's pcap file")

    args = parser.parse_args()

    print("start sniffer...")
    print()
    try:
        sniffer = Sniffer(listen_addr=args.listen_addr, timeout=args.timeout, filename=args.file)
        sniffer.run()
    except KeyboardInterrupt:
        print("keyboard interruption!!!")
    except PermissionError:
        print("Permission denied!!! Need run program with superuser privileges!!!")
    except OSError as err:
        print(err)
    print()
    print("stop sniffer...")