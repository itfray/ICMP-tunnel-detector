import ticmp_connector
import time
import datetime
from rfc1071_checksum import checksum
import argparse
import socket


DEFAULT_ID = 8191
DEFAULT_LISTEN_ADDR = socket.gethostbyname_ex(socket.gethostname())[2][-1]
DEFAULT_SCRAMBLER_COEFFS = [1, 3, 5]
DEFAULT_TIMEOUT = 10                            # timeout working server in mins


class Server:
    def __init__(self, conn_id, listen_addr, scr_coeffs, timeout, debug):
        self.__connector = ticmp_connector.TICMPConnector(conn_id=conn_id, listen_addr=listen_addr,
                                                          scr_coeffs=scr_coeffs)
        self.timeout = timeout
        self.debug = debug

    def run(self):
        t0 = time.time()
        timeout = self.timeout * 60
        while time.time() - t0 < timeout:
            data, addr = self.__connector.recvfrom()
            msg = f"Received {len(data)} bytes from {addr}"
            if self.debug:
                msg += f", data: 0x{data[:16].hex()}..., checksum: {hex(checksum(data))}"
            self.print_message(msg)
            self.__connector.sendto(data, addr)

    def print_message(self, msg):
        print(f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")}] {msg}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True, description="ICMP-tunneling: server script")

    parser.add_argument('-i', '--id', dest='id', type=int, default=DEFAULT_ID,
                        help="Specifies the connection id for server")

    parser.add_argument('-la', '--listen_addr', dest='listen_addr', type=str, default=DEFAULT_LISTEN_ADDR,
                        help="Specifies the interface's address that listen server")

    parser.add_argument('-c', '--coeff', dest='coeff', type=int, action='append',
                        help="Specifies the one of scrambler coefficients")

    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Specifies the timeout for server operation')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    args = parser.parse_args()
    print(args)
    print("start server...")
    server = Server(args.id, args.listen_addr,
                    args.coeffs if args.coeffs else DEFAULT_SCRAMBLER_COEFFS, args.timeout, args.debug)
    server.run()
    print("stop server...")
