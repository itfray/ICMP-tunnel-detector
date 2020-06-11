from network_component import DEFAULT_TIMEOUT, DEFAULT_LISTEN_ADDR, DEFAULT_SCRAMBLER_COEFFS
from network_component import DEFAULT_CLIENT_ID, DEFAULT_SERVER_ID
from network_component import NetworkComponent, print_message
from rfc1071_checksum import checksum
import argparse
import time
import ticmp_connector
import random
import sys
import os


DEFAULT_FILE = 'default_file.txt'


class Client(NetworkComponent):
    def __init__(self, pid: int, lid: int, remote_addr: str, listen_addr: str, scr_coeffs: list,
                 mode: list, timeout: int, filename: str, size_block_file: int, debug: bool):
        super().__init__(pid, lid, listen_addr, scr_coeffs, timeout, debug)
        self.__remote_addr = remote_addr
        self.mode = mode

        self.filename = filename
        self.size_block_file = size_block_file                  # size for block reading file
        self.offset_file = 0                                    # position in file generating data

    def run(self):
        t0 = time.time()
        timeout = self.timeout * 60
        total_data = b''                                        # data for sending
        while time.time() - t0 < timeout:
            if total_data == b'':
                if self.mode[0]:
                    total_data = self.read_random_data()
                elif self.mode[1]:
                    total_data = self.read_input_data()
                else:
                    total_data = self.read_file_data()
                    if len(total_data) == 0:
                        print_message("Error, file generating is empty file!!!")
                        break
            data = total_data
            max_size = ticmp_connector.MAX_DATA_SIZE_v4ICMP - self.scrambler_coeffs()[0]
            if len(data) > max_size:
                data = data[:max_size]
            total_data = total_data[len(data):]             # get part data and send her

            self.sendto(data, self.__remote_addr)
            print_message(f"Sent {len(data)} bytes to {self.__remote_addr}:{self.listen_id()}" +
                          (f", data: 0x{data[:8].hex()}..., checksum: {hex(checksum(data))}" if self.debug else ''))

            recv_data, addr = self.recvfrom()
            addr = addr[0]
            print_message(f"Received {len(recv_data)} bytes from {addr}:{self.listen_id()}" +
                          (f", data: 0x{recv_data[:8].hex()}..., checksum: {hex(checksum(recv_data))}"
                           if self.debug else ''))

            if data != recv_data:
                print_message("Error receiving data!!!")
                break
            self.inc_seq_num()


    def read_file_data(self)->bytes:
        size_file = os.path.getsize(self.filename)
        with open(self.filename, 'rb') as file:
            file.seek(self.offset_file, 0)
            data = file.read(self.size_block_file)
            self.offset_file += len(data)
            if file.tell() == size_file:            # check pointer end of file
                self.offset_file = 0
        return data

    def read_input_data(self)->bytes:
        data = input('>').encode()
        while len(data) < 1:
            data = input('>').encode()
        return data

    def read_random_data(self)->bytes:
        return bytes([random.randint(0, 255)
                      for i in range(random.randint(1,
                      ticmp_connector.MAX_DATA_SIZE_v4ICMP - self.scrambler_coeffs()[0]))])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True, description="ICMP-tunneling: client script")

    parser.add_argument('remote_addr', type=str,
                        help="Specifies the address server")

    parser.add_argument('-pid', '--process_id', dest='process_id', type=int, default=DEFAULT_CLIENT_ID,
                        help="Specifies the connection icmp id for client")

    parser.add_argument('-lid', '--listen_id', dest='listen_id', type=int, default=DEFAULT_SERVER_ID,
                        help="Specifies the connection icmp id for server")

    parser.add_argument('-la', '--listen_addr', dest='listen_addr', type=str, default=DEFAULT_LISTEN_ADDR,
                        help="Specifies the interface's address that listen server")

    parser.add_argument('-c', '--coeff', dest='coeff', type=int, action='append',
                        help="Specifies the one of scrambler coefficients")

    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Specifies the timeout for server operation')

    parser.add_argument('-dr', '--data_rand', dest='data_rand', action="store_true",
                        help='Specifies the mode random generating data')

    parser.add_argument('-di', '--data_inp', dest='data_inp', action="store_true",
                        help='Specifies the mode input generating data')

    parser.add_argument('-df', '--data_file', dest='data_file', action="store_true",
                        help='Specifies the mode file generating data')

    parser.add_argument('-f', '--file', dest='file', type=str, default=DEFAULT_FILE,
                        help='Specifies the filename for mode file generating data')

    parser.add_argument('-sb', '--size_block_file', dest='size_block_file', type=int, default=32,
                        help='Specifies the size for block reading file for mode file generating data')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    args = parser.parse_args()
    if (args.data_rand and args.data_inp) or \
       (args.data_inp and args.data_file) or \
       (args.data_file and args.data_rand):
        print("Should be set only one flag specifies mode generating data!!!")
        sys.exit(0)
    mode = [args.data_rand, args.data_inp, args.data_file]
    if (args.data_rand or args.data_inp or args.data_file) == False:
        mode = [True, False, False]

    print("start client...")
    client = Client(args.process_id, args.listen_id, args.remote_addr, args.listen_addr,
                    args.coeff if args.coeff else DEFAULT_SCRAMBLER_COEFFS, mode, abs(args.timeout),
                    args.file, abs(args.size_block_file),  args.debug)
    client.run()
    print("stop client...")
