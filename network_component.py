import datetime
import socket
import ticmp_connector
import abc


DEFAULT_CLIENT_ID = 8191
DEFAULT_SERVER_ID = 9282
DEFAULT_LISTEN_ADDR = socket.gethostbyname_ex(socket.gethostname())[2][-1]
DEFAULT_SCRAMBLER_COEFFS = [1, 3, 5]
DEFAULT_TIMEOUT = 10                            # timeout working network_component


def print_message(msg):
    print(f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")}] {msg}')


class NetworkComponent(abc.ABC):
    def __init__(self, process_id: int, listen_id: int, listen_addr: str, scr_coeffs: list, timeout: int, debug: bool):
        self.connector = ticmp_connector.TICMPConnector(process_id=process_id,
                                                        listen_id=listen_id,
                                                        listen_addr=listen_addr,
                                                        scr_coeffs=scr_coeffs)
        self.timeout = timeout
        self.debug = debug

    @abc.abstractmethod
    def run(self):
        pass