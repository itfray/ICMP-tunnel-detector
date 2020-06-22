import struct
import net_header

# ICMP header for both IPv4 and IPv6.
#
# The wire format of an ICMP header is:
#
# 0               8               16                             31
# +---------------+---------------+------------------------------+      ---
# |               |               |                              |       ^
# |     type      |     code      |          checksum            |       |
# |               |               |                              |       |
# +---------------+---------------+------------------------------+    8 bytes
# |                                                              |       |
# |                          header data                         |       |
# |                                                              |       v
# +-------------------------------+------------------------------+      ---

# Types ICMP v4
TYPE_v4EchoReply = 0
TYPE_v4DestinationUnreachable = 3
TYPE_v4SourceQuench = 4
TYPE_v4Redirect = 5
TYPE_v4EchoRequest = 8
TYPE_v4RouterAdvertisement = 9
TYPE_v4RouterSolicitation = 10
TYPE_v4TimeExceeded = 11
TYPE_v4ParameterProblem = 12
TYPE_v4TimestampRequest = 13
TYPE_v4TimestampReply = 14
TYPE_v4InfoRequest = 15
TYPE_v4InfoReply = 16
TYPE_v4AddressMaskRequest = 17
TYPE_v4AddressMaskReply = 18
TYPE_v4ExtendedEchoRequest = 42
TYPE_v4ExtendedEchoReply = 43

# Types ICMP v6
TYPE_v6DestinationUnreachable = 1
TYPE_v6PacketTooBig = 2
TYPE_v6TimeExceeded = 3
TYPE_v6ParameterProblem = 4
TYPE_v6EchoRequest = 128
TYPE_v6EchoReply = 129
TYPE_v6MulticastListenerQuery = 130
TYPE_v6MulticastListenerReport = 131
TYPE_v6MulticastListenerDone = 131
TYPE_v6RouterSolicitation = 133
TYPE_v6RouterAdvertisement = 134
TYPE_v6NeighbourSolicitation = 135
TYPE_v6NeighbourAdvertisement = 136
TYPE_v6RedirectMessage = 137
TYPE_v6RouterRenumbering = 138
TYPE_v6ICMPNodeInfoQuery = 139
TYPE_v6ICMPNodeInfoResponse = 140
TYPE_v6InverseNeighborDiscoverySolicitationMsg = 141
TYPE_v6InverseNeighborDiscoveryAdvertisementMsg = 142
TYPE_v6Version2MulticastListenerReport = 143
TYPE_v6HomeAgentAddressDiscoveryRequest = 144
TYPE_v6HomeAgentAddressDiscoveryReply = 145
TYPE_v6MobilePrefixSolicitation = 146
TYPE_v6MobilePrefixAdvertisement = 147
TYPE_v6CertificationPathSolicitation = 148
TYPE_v6CertificationPathAdvertisement = 149
TYPE_v6MulticastRouterAdvertisement = 151
TYPE_v6MulticastRouterSolicitation = 152
TYPE_v6FMIPv6Messages = 154
TYPE_v6RPLControlMessage = 155
TYPE_v6ILNPv6LocatorUpdateMessage = 156
TYPE_v6DuplicateAddressRequest = 157
TYPE_v6DuplicateAddressConfirmation = 158


class ICMPHeader(net_header.InterfaceNetHeader):
    length = 8
    def __init__(self, **kwargs):
        bs = kwargs.get("hbytes")
        if bs is None:
            self.type = kwargs.get("htype", 0)
            self.code = kwargs.get("hcode", 0)
            self.checksum = kwargs.get("hchecksum", 0)
            self.other_bs = kwargs.get("hother_bytes", bytearray(4))
        else:
            self.read_bytes_from(bs)

    def read_bytes_from(self, bs: bytes, offset = 0)-> None:
        self.type, self.code, self.checksum = struct.unpack_from(">2BH", bs, offset)
        self.other_bs = bytearray(bs[offset + 4:offset + 8])

    def write_bytes_into(self, buf: bytearray, offset):
        struct.pack_into(">2BH4s", buf, offset, self.type, self.code, self.checksum, bytes(self.other_bs))

    def to_bytes(self)-> bytes:
        bs = struct.pack(">2BH", self.type, self.code, self.checksum) + self.other_bs
        assert len(bs) == self.length, "Bad icmp-header's length!!!"
        return bs

    def to_bytearray(self)-> bytearray:
        barr = bytearray(struct.pack(">2BH", self.type, self.code, self.checksum)) + self.other_bs
        assert len(barr) == self.length, "Bad icmp-header's length!!!"
        return barr

    def __repr__(self):
        return "[ICMP] {type: " + str(self.type) + ", code: " + str(self.code) + \
               ", checksum: " + str(hex(self.checksum)) + ", other_bytes: " + self.other_bs.hex() + "}"

    def __str__(self):
        return self.__repr__()


def icmpv4_set_id(icmph, val):
    struct.pack_into('>H', icmph.other_bs, 0, val)

def icmpv4_set_seq_num(icmph, val):
    struct.pack_into('>H', icmph.other_bs, 2, val)

def icmpv4_set_id_and_seq_num(icmph, hid, hseq_num):
    struct.pack_into(">2H", icmph.other_bs, 0, hid, hseq_num)

def icmpv4_id(icmph):
    return struct.unpack_from(">H", icmph.other_bs)[0]

def icmpv4_seq_num(icmph):
    return struct.unpack_from(">H", icmph.other_bs, 2)[0]
