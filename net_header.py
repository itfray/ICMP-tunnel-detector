import abc


# Protocol numbers
PROTO_ICMP = 1
PROTO_IPv4 = 4
PROTO_IPv6 = 41
PROTO_TCP = 6
PROTO_UDP = 17


# interface for any class network header
class InterfaceNetHeader(abc.ABC):
    @abc.abstractmethod
    def read_bytes_from(self, bs: bytes, offset: int) -> None:
        pass

    @abc.abstractmethod
    def write_bytes_into(self, buf: bytearray, offset: int)-> None:
        pass

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        pass

    @abc.abstractmethod
    def to_bytearray(self) -> bytearray:
        pass

    @abc.abstractmethod
    def __repr__(self):
        pass