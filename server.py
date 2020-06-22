from rfc1071_checksum import checksum
import argparse
import datetime
import socket
import time
import ticmp_connector

DEFAULT_CLIENT_ID = 8191
DEFAULT_SERVER_ID = 9282
DEFAULT_LISTEN_ADDR = socket.gethostbyname_ex(socket.gethostname())[2][-1]
DEFAULT_SCRAMBLER_COEFFS = [1, 3, 5]
DEFAULT_TIMEOUT = 10                            # timeout working network_component


def print_message(msg):
    print(f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")}] {msg}')


class Server(ticmp_connector.TICMPConnector):
    def __init__(self, process_id: int, listen_id: int, listen_addr: str, scr_coeffs: list, timeout: int, debug: bool):
        super().__init__(process_id=process_id, listen_id=listen_id, listen_addr=listen_addr, scr_coeffs=scr_coeffs,
                         debug=debug)
        self.timeout = timeout

    def run(self):
        t0 = time.time()
        timeout = self.timeout * 60
        send_data = recv_data = b'!!!Warning, server not receive message!!!'
        send_addr = recv_addr = ''
        count_send_msg = 0          # number of consecutively sent messages
        while time.time() - t0 < timeout:
            recv_data, recv_addr = self.recvfrom_timeout(5)
            if len(recv_data) > 0:
                send_data = recv_data
                send_addr = recv_addr[0]
                print_message(f"Received {len(recv_data)} bytes from {send_addr}:{self.listen_id()}" +
                     (f", data: {bytes(recv_data[:8])}..., checksum: {hex(checksum(recv_data))}" if self.debug else ''))
                count_send_msg = 0
            else:
                if send_addr != '':
                    self.dec_seq_num()

            if send_addr != '':
                self.sendto(send_data, send_addr)
                print_message(f"Sent {len(send_data)} bytes to {send_addr}:{self.listen_id()}" +
                     (f", data: {bytes(send_data[:8])}..., checksum: {hex(checksum(send_data))}" if self.debug else ''))
                print()
                self.inc_seq_num()
                count_send_msg += 1
            if count_send_msg > 4:
                # client not posted on 5 consecutive messages
                send_addr = ''
                self.set_seq_num(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True, description="ICMP-tunneling: server script")

    parser.add_argument('-pid', '--process_id', dest='process_id', type=int, default=DEFAULT_SERVER_ID,
                        help="Specifies the connection icmp id for server")

    parser.add_argument('-lid', '--listen_id', dest='listen_id', type=int, default=DEFAULT_CLIENT_ID,
                        help="Specifies the connection icmp id for client")

    parser.add_argument('-la', '--listen_addr', dest='listen_addr', type=str,
                        default=DEFAULT_LISTEN_ADDR,
                        help="Specifies the interface's address that listen server")

    parser.add_argument('-c', '--coeff', dest='coeff', type=int, action='append',
                        help="Specifies the one of scrambler coefficients")

    parser.add_argument('-t', '--timeout', dest='timeout', type=int,
                        default=DEFAULT_TIMEOUT,
                        help='Specifies the timeout for server operation')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    args = parser.parse_args()

    print("start server...")
    print()

    try:
        server = Server(args.process_id, args.listen_id, args.listen_addr,
                        args.coeff if args.coeff else DEFAULT_SCRAMBLER_COEFFS, args.timeout, args.debug)
        server.run()
    except KeyboardInterrupt:
        print("keyboard interruption!!!")
    except PermissionError:
        print("Permission denied!!! Need run program with superuser privileges!!!")
    except OSError as err:
        print(err)
    print()
    print("stop server...")
