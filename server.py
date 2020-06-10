from network_component import DEFAULT_ID, DEFAULT_TIMEOUT, DEFAULT_LISTEN_ADDR, DEFAULT_SCRAMBLER_COEFFS
from network_component import NetworkComponent, print_message
from rfc1071_checksum import checksum
import argparse
import time


class Server(NetworkComponent):
    def __init__(self, conn_id, listen_addr, scr_coeffs, timeout, debug):
        super().__init__(conn_id, listen_addr, scr_coeffs, timeout, debug)

    def run(self):
        t0 = time.time()
        timeout = self.timeout * 60
        while time.time() - t0 < timeout:
            data, addr = self.connector.recvfrom()
            addr = addr[0]
            msg = f"Received {len(data)} bytes from {addr}"
            if self.debug:
                msg += f", data: 0x{data[:8].hex()}..., checksum: {hex(checksum(data))}"
            print_message(msg)
            self.connector.sendto(data, addr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True, description="ICMP-tunneling: server script")

    parser.add_argument('-i', '--id', dest='id', type=int, default=DEFAULT_ID,
                        help="Specifies the connection id for server")

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
    server = Server(args.id, args.listen_addr,
                    args.coeff if args.coeff else DEFAULT_SCRAMBLER_COEFFS, args.timeout, args.debug)
    server.run()
    print("stop server...")
