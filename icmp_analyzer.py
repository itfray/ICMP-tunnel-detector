import icmpheader
import ipv4header
import entropy
import struct


MAX_DATA_SIZE_v4ICMP = 65507
MIN_DATA_SIZE_v4ICMP = 1


MIN_DATA_SIZE_v4ICMPErrMsg = 28
MAX_DATA_SIZE_v4ICMPErrMsg = 576


DEFAULT_DEPRECATED_TYPES = tuple([icmpheader.TYPE_v4SourceQuench, 6,
                                 icmpheader.TYPE_v4InfoRequest, icmpheader.TYPE_v4InfoReply,
                                 icmpheader.TYPE_v4AddressMaskRequest, icmpheader.TYPE_v4AddressMaskReply]
                                 + list(range(30, 40)))

DEFAULT_UNASSIGNED_TYPES = tuple([1, 2, 7, 40, 41] + list(range(19, 30)) +
                                 list(range(44, 255)))

DEFAULT_KNOWN_IDENTIFIERS = (1,)
""" 
    1 - utility "ping"
"""

IPV4_POSSIBLE_MASKS = (0, 2147483648, 3221225472, 3758096384,
                        4026531840, 4160749568, 4227858432, 4261412864,
                        4278190080, 4286578688, 4290772992, 4292870144,
                        4293918720, 4294443008, 4294705152, 4294836224,
                        4294901760, 4294934528, 4294950912, 4294959104,
                        4294963200, 4294965248, 4294966272, 4294966784,
                        4294967040, 4294967168, 4294967232, 4294967264,
                        4294967280, 4294967288, 4294967292, 4294967294,
                        4294967295)


class ICMPAnalyzer:
    def __init__(self, **kwargs):
        self.deprecated_types = kwargs.get("deprecated", DEFAULT_DEPRECATED_TYPES)
        self.unassigned_types = kwargs.get("unassigned", DEFAULT_UNASSIGNED_TYPES)
        self.known_ids = kwargs.get("known_ids", DEFAULT_KNOWN_IDENTIFIERS)

    def analyze(self, packet: bytes, offset = 0):
        assert len(packet) <= MAX_DATA_SIZE_v4ICMP + icmpheader.ICMPHeader.Length, "Too big size packet!!!"
        assert len(packet) >= icmpheader.ICMPHeader.Length, "Too little size packet!!!"
        icmph = icmpheader.ICMPHeader()
        icmph.read_bytes_from(packet, offset)

        icmp_pid = 0
        marks = {"encrypted": 0}

        if icmph.type in  (icmpheader.TYPE_v4EchoRequest, icmpheader.TYPE_v4EchoReply):
            icmp_pid = icmpheader.icmpv4_id(icmph)
            marks["encrypted"] = int(entropy.is_encrypted_data(packet, start=offset + icmph.Length))    # check data encrypted?
            if len(packet) - offset - icmph.Length < 32:        # if size field data < 32 then need still checks
                if icmph.code != 0:
                    marks["errs"] = 1
                if icmp_pid not in self.known_ids:
                    marks["unknown_id"] = 1

        elif icmph.type in (icmpheader.TYPE_v4TimestampRequest, icmpheader.TYPE_v4TimestampReply):
            icmp_pid = icmpheader.icmpv4_id(icmph)
            marks["encrypted"] = int(entropy.is_encrypted_data(packet, start=offset + icmph.Length))
            if icmph.code != 0 or len(packet) - offset - icmph.Length != 12:
                marks["errs"] = 1
            if icmp_pid not in self.known_ids:
                marks["unknown_id"] = 1

        elif icmph.type in (icmpheader.TYPE_v4AddressMaskRequest, icmpheader.TYPE_v4AddressMaskReply):
            icmp_pid = icmpheader.icmpv4_id(icmph)
            if icmph.code != 0 or len(packet) - offset - icmph.Length != 4:
                marks["errs"] = 1
            if icmp_pid not in self.known_ids:
                marks["unknown_id"] = 1
            if marks.get("errs", 0) != 1:
                mask_addr = struct.unpack_from('>I', packet, offset + icmph.Length)
                if mask_addr not in IPV4_POSSIBLE_MASKS:
                    marks["errs"] = 1

        elif icmph.type == icmpheader.TYPE_v4ExtendedEchoReply:
            icmp_pid = icmpheader.icmpv4_id(icmph)
            if icmph.code > 4 or len(packet) - offset - icmph.Length != 0:
                marks["errs"] = 1

        elif icmph.type == icmpheader.TYPE_v4ExtendedEchoRequest:
            icmp_pid = icmpheader.icmpv4_id(icmph)
            L = struct.unpack_from('>B', icmph.other_bs, 3)[0] & 0b00000001
            size = len(packet) - offset - icmph.Length
            if size < icmpheader.ICMPExtHeader.Length:
                marks["errs"] = 1
            else:
                exth = icmpheader.ICMPExtHeader()
                exth.read_bytes_from(packet, offset + icmph.Length)
                size -= icmpheader.ICMPExtHeader.Length
                if size < icmpheader.ICMPIntIdObjAddrHeader.Length:
                    marks["errs"] = 1
                else:
                    exthobj = icmpheader.ICMPExtObjHeader()
                    exthobj.read_bytes_from(packet, offset + icmph.Length + exth.Length)
                    size -= exthobj.Length
                    if exthobj.cls_num != 3:
                        marks["errs"] = 1
                    else:
                        if exthobj.c_type == 1:
                            if L == 0:
                                marks["errs"] = 1
                            else:
                                if exthobj.len != 4 + exthobj.Length:
                                    marks["errs"] = 1
                        elif exthobj.c_type == 2:
                            if L == 0:
                                marks["errs"] = 1
                            else:
                                ifname_len = exthobj.len - exthobj.Length
                                if ifname_len == 0:
                                    marks["errs"] = 1
                                else:
                                    marks["encrypted"] = int(entropy.is_encrypted_data(packet, start=offset +
                                                                                       icmph.Length + exth.Length +
                                                                                       exthobj.Length))
                        elif exthobj.c_type == 3:
                            if size < icmpheader.ICMPIntIdObjAddrHeader.Length:
                                marks["errs"] = 1
                            else:
                                id_obj_addrh = icmpheader.ICMPIntIdObjAddrHeader()
                                id_obj_addrh.read_bytes_from(packet, offset + icmph.Length + exth.Length + exthobj.Length)
                                if id_obj_addrh.addr_len == 0:
                                    marks["errs"] = 1
                        else:
                            marks["errs"] = 1

        elif icmph.type == icmpheader.TYPE_v4Redirect:
            if icmph.code not in tuple(range(0, 4)) or len(packet) - offset - icmph.Length != MIN_DATA_SIZE_v4ICMPErrMsg:
                marks["errs"] = 1
            val = struct.unpack_from('>B', packet, offset + icmph.Length)[0]
            v = val >> 4
            if v != 4:
                marks["errs"] = 1
            hl = (val & 0x0f) * 4
            if hl < ipv4header.IPv4Header.MinLength or hl > ipv4header.IPv4Header.MaxLength:
                marks["errs"] = 1
            marks["encrypted"] = int(entropy.is_encrypted_data(packet, start=offset + 4))

        elif icmph.type == icmpheader.TYPE_v4RouterAdvertisement:
            if icmph.code != 0:
                marks["errs"] = 1
            num_addr = struct.unpack_from('>B', packet, offset + 4)[0]
            if num_addr == 0:
                marks["errs"] = 1
            if marks.get("errs", 0) != 1:
                life_time = struct.unpack_from('>H', packet, offset + 6)[0]
                if life_time == 0:
                    marks["errs"] = 1
                size_data = len(packet) - offset - icmph.Length
                if size_data == 0:
                    marks["errs"] = 1
                else:
                    marks["encrypted"] = int(entropy.is_encrypted_data(packet, start=offset + icmph.Length))

        elif icmph.type in (icmpheader.TYPE_v4DestinationUnreachable,
                            icmpheader.TYPE_v4TimeExceeded, icmpheader.TYPE_v4SourceQuench,
                            icmpheader.TYPE_v4ParameterProblem):

            if icmph.type == icmpheader.TYPE_v4DestinationUnreachable:
                if icmph.code in tuple(range(0, 16)):
                    marks["errs"] = 1
            elif icmph.type == icmpheader.TYPE_v4TimeExceeded:
                if icmph.code in tuple(range(0, 2)):
                    marks["errs"] = 1
            elif icmph.type == icmpheader.TYPE_v4ParameterProblem:
                if icmph.code in tuple(range(0, 3)):
                    marks["errs"] = 1
            else:   # icmpheader.TYPE_v4SourceQuench
                if icmph.code != 0:
                    marks["errs"] = 1
            if len(packet) - offset - icmph.Length < MIN_DATA_SIZE_v4ICMPErrMsg:
                marks["errs"] = 1
            else:
                val = struct.unpack_from('>B', packet, offset + icmph.Length)[0]
                v = val >> 4
                if v != 4:
                    marks["errs"] = 1
                hl = (val & 0x0f) * 4
                if hl < ipv4header.IPv4Header.MinLength or hl > ipv4header.IPv4Header.MaxLength:
                    marks["errs"] = 1
                marks["encrypted"] = int(entropy.is_encrypted_data(packet, start=offset + icmph.Length))

        if icmph.type in self.deprecated_types or icmph.type in self.unassigned_types:
            marks['bad_type'] = 1

        mark = 0
        for key in marks:
            mark += marks[key]
        mark /= len(marks)

        return icmp_pid, mark