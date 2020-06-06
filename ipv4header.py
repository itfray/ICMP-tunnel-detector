import struct
import socket
import net_header

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


class IPv4Header(net_header.InterfaceNetHeader):
    MinLength = 20
    MaxLength = 60
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
            self.read_bytes_from(bs)

    def read_bytes_from(self, bs: bytes, offset = 0)-> None:
        hvl, self.type_of_service, self.total_length, self.id, hdmoff = struct.unpack_from('>2B3H', bs, offset)
        self.header_length = hvl & 0x0f
        self.version = hvl >> 4
        self.dont_fragment = int(hdmoff & 0x4000 != 0)
        self.more_fragments = int(hdmoff & 0x2000 != 0)
        self.fragment_offset = hdmoff & 0x1fff
        self.ttl, self.protocol, self.checksum = struct.unpack_from('>2BH', bs, offset + 8)
        self.src_addr = socket.inet_ntoa(bs[offset + 12:offset + 16])
        self.dst_addr = socket.inet_ntoa(bs[offset + 16:offset + 20])
        len_in_bytes = self.header_length * 4
        if len_in_bytes > self.MinLength and len(bs) - offset - len_in_bytes >= 0:
            self.options_bytes = bytearray(bs[offset + self.MinLength:offset + len_in_bytes])
        else:
            self.options_bytes = bytearray()

    def write_bytes_into(self, barr: bytearray, offset = 0)-> None:
        assert len(self.options_bytes) <= self.MaxLength - self.MinLength, "Bad ip-header's length!!!"
        hvl = (self.version << 4) + self.header_length
        hdmoff = (0x4000 if self.dont_fragment else 0) + (0x2000 if self.more_fragments else 0) + self.fragment_offset
        frmt_str = f'>2B3H2BH4s4s{len(self.options_bytes)}s'
        bs = struct.pack_into(frmt_str, barr, offset, hvl, self.type_of_service, self.total_length,
                              self.id, hdmoff, self.ttl, self.protocol, self.checksum,
                              socket.inet_aton(self.src_addr), socket.inet_aton(self.dst_addr),
                              bytes(self.options_bytes))

    def to_bytes(self)-> bytes:
        hvl = (self.version << 4) + self.header_length
        hdmoff = (0x4000 if self.dont_fragment else 0) + (0x2000 if self.more_fragments else 0) + self.fragment_offset
        bs = struct.pack('>2B3H2BH', hvl, self.type_of_service, self.total_length, self.id, hdmoff,
                           self.ttl, self.protocol, self.checksum) + \
                           socket.inet_aton(self.src_addr) + socket.inet_aton(self.dst_addr) + self.options_bytes
        assert self.MinLength <= len(bs) <= self.MaxLength, "Bad ip-header's length!!!"
        return bs

    def to_bytearray(self)-> bytearray:
        return bytearray(self.to_bytes())

    def __repr__(self):
        return "[IPv4] {version: " + str(self.version) + ", hlen: " + str(self.header_length) + \
               ", tos: " + str(self.type_of_service) + ", total_len: " + str(self.total_length) + \
               ", id: " + str(hex(self.id)) + ", df: " + str(self.dont_fragment) + ", mfs: " + str(self.more_fragments) + \
               ", foffset: " + str(self.fragment_offset) + ", ttl: " + str(self.ttl) + \
               ", protocol: " + str(self.protocol) + ", checksum: " + str(hex(self.checksum)) + \
               ", src_addr: " + self.src_addr + ", dst_addr: " + self.dst_addr + "}"

    def __str__(self):
        return self.__repr__()
