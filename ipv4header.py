import struct
import socket

# Packet header for IPv4.
#
# The wire format of an IPv4 header is:
#
# 0               8               16                             31
# +-------+-------+---------------+------------------------------+      ---
# |       |       |               |                              |       ^
# |version|header |    type of    |    total length in bytes     |       |
# |  (4)  | length|    service    |                              |       |
# +-------+-------+---------------+-+-+-+------------------------+       |
# |                               | | | |                        |       |
# |        identification         |0|D|M|    fragment offset     |       |
# |                               | |F|F|                        |       |
# +---------------+---------------+-+-+-+------------------------+       |
# |               |               |                              |       |
# | time to live  |   protocol    |       header checksum        |   20 bytes
# |               |               |                              |       |
# +---------------+---------------+------------------------------+       |
# |                                                              |       |
# |                      source IPv4 address                     |       |
# |                                                              |       |
# +--------------------------------------------------------------+       |
# |                                                              |       |
# |                   destination IPv4 address                   |       |
# |                                                              |       v
# +--------------------------------------------------------------+      ---
# |                                                              |       ^
# |                                                              |       |
# /                        options (if any)                      /    0 - 40
# /                                                              /     bytes
# |                                                              |       |
# |                                                              |       v
# +--------------------------------------------------------------+      ---


class IPv4Header:
    min_length = 20
    max_length = 60
    def __init__(self, **kwargs):
        bs = kwargs.get("hbytes")
        if bs is None:
            self.version = kwargs.get("hversion", 4)
            self.header_length = kwargs.get("hlength", 5)
            self.type_of_service = kwargs.get("htos", 0)
            self.total_length = kwargs.get("htotal_length", 0)
            self.id = kwargs.get("hid", 0)
            self.dont_fragment = kwargs.get("hdf", 0)
            self.more_fragments = kwargs.get("hmf", 0)
            self.fragment_offset = kwargs.get("hoffset", 0)
            self.ttl = kwargs.get("httl", 0)
            self.protocol = kwargs.get("hprotocol", 0)
            self.checksum = kwargs.get("hchecksum", 0)
            self.src_addr = kwargs.get("hsrc_addr", "0.0.0.0")
            self.dst_addr = kwargs.get("hdst_addr", "0.0.0.0")
            self.options_bytes = kwargs.get("hoptions_bytes", bytearray())
        else:
            self.set_bytes(bs)

    def set_bytes(self, bs: bytes)-> None:
        assert self.min_length <= len(bs) <= self.max_length, "Bad ip-header's length!!!"
        hvl, self.type_of_service, self.total_length, self.id, hdmoff = struct.unpack_from('>2B3H', bs)
        self.header_length = hvl & 0x0f
        self.version = hvl >> 4
        self.dont_fragment = int(hdmoff & 0x4000 != 0)
        self.more_fragments = int(hdmoff & 0x2000 != 0)
        self.fragment_offset = hdmoff & 0x1fff
        self.ttl, self.protocol, self.checksum = struct.unpack_from('>2BH', bs, 8)
        self.src_addr, self.dst_addr = socket.inet_ntoa(bs[12:16]), socket.inet_ntoa(bs[16:20])
        len_in_bytes = self.header_length * 4
        if len_in_bytes == len(bs) and len_in_bytes > self.min_length:
            self.options_bytes = bytearray(bs[self.min_length:len_in_bytes])
        else:
            self.options_bytes = bytearray()

    def to_bytes(self)-> bytes:
        hvl = (self.version << 4) + self.header_length
        hdmoff = (0x4000 if self.dont_fragment else 0) + (0x2000 if self.more_fragments else 0) + self.fragment_offset
        bs = struct.pack('>2B3H2BH', hvl, self.type_of_service, self.total_length, self.id, hdmoff,
                           self.ttl, self.protocol, self.checksum) + \
                           socket.inet_aton(self.src_addr) + socket.inet_aton(self.dst_addr) + self.options_bytes
        assert self.min_length <= len(bs) <= self.max_length, "Bad ip-header's length!!!"
        return bs

    def to_bytearray(self)-> bytearray:
        return bytearray(self.to_bytes())
