import net_header
import struct


class EthDixHeader(net_header.InterfaceNetHeader):
    Length = 14
    def __init__(self, **kwargs):
        bs = kwargs.get("hbytes")
        if bs is None:
            self.dst_addr = kwargs.get("hdst_addr", b'\x00\x00\x00\x00\x00\x00')
            self.src_addr = kwargs.get("hsrc_addr", b'\x00\x00\x00\x00\x00\x00')
            self.type = kwargs.get("htype", 0)
        else:
            self.read_bytes_from(bs)

    def read_bytes_from(self, bs: bytes, offset = 0) -> None:
        self.dst_addr, self.src_addr, self.type = struct.unpack_from('>6s6sH', bs, offset)

    def write_bytes_into(self, buf: bytearray, offset: int)-> None:
        struct.pack_into('>6s6sH', buf, offset, self.dst_addr, self.src_addr, self.type)

    def to_bytes(self) -> bytes:
        struct.pack('>6s6sH', self.dst_addr, self.src_addr, self.type)

    def to_bytearray(self) -> bytearray:
        return bytearray(self.to_bytes())

    def __repr__(self):
        return "[EthDix] {dst_addr: " + self.addr_to_str(self.dst_addr) + \
                ", src_addr: " + self.addr_to_str(self.src_addr) + ", type: " + str(hex(self.type)) + "}"

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def addr_to_str(addr: bytes)-> str:
        assert len(addr) == 6, 'Uncorrect mac-48 address!!!'
        saddr = ""
        for i in range(len(addr)):
            saddr += bytes([addr[i]]).hex()
            if i != len(addr) - 1:
                saddr += ":"
        return saddr

    @staticmethod
    def str_to_addr(saddr: str)-> bytes:
        laddr = saddr.split(':')
        assert len(laddr) == 6, 'Uncorrect mac-48 address!!!'
        addr = bytearray(6)
        for i in range(len(laddr)):
            struct.pack_into('>s', addr, i, bytearray.fromhex(laddr[i]))
        return bytes(addr)


# ///////////////////// DEBUG ///////////////////////
# if __name__ == "__main__":
#     ethh = EthDixHeader(hdst_addr=b'\xff\x02\x03\x04\x05\x06',
#                         hsrc_addr=b'\x06\x05\x04\x03\x02\x01',
#                         htype=0x0800)
#     print(ethh)
#     buf = bytearray(b'\xff\x0f\xf0\x04\x05\x06' + b'\xf1\xf5\xe4\x93\x02\x01' + b'\x18\x0d')
#     ethh.read_bytes_from(buf)
#     print(ethh)
#
#     buf = bytearray(20)
#     ethh.write_bytes_into(buf, 6)
#     print(buf)
# ///////////////////// DEBUG ///////////////////////