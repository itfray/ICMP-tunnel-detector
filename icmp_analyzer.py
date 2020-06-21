import icmpheader
import ipv4header
import entropy
import struct


MAX_DATA_SIZE_v4ICMP = 65507
MIN_DATA_SIZE_v4ICMP = 1


MIN_DATA_SIZE_v4ICMPErrMsg = 28
MAX_DATA_SIZE_v4ICMPErrMsg = 548


# values deprecated icmp types
DEFAULT_DEPRECATED_TYPES = tuple([icmpheader.TYPE_v4SourceQuench, 6,
                                 icmpheader.TYPE_v4InfoRequest, icmpheader.TYPE_v4InfoReply,
                                 icmpheader.TYPE_v4AddressMaskRequest, icmpheader.TYPE_v4AddressMaskReply]
                                 + list(range(30, 40)))

# values unassigned icmp types
DEFAULT_UNASSIGNED_TYPES = tuple([1, 2, 7, 40, 41] + list(range(19, 30)) +
                                 list(range(44, 255)))

# all variants ipv4 network masks
IPV4_POSSIBLE_MASKS = (0, 2147483648, 3221225472, 3758096384,
                        4026531840, 4160749568, 4227858432, 4261412864,
                        4278190080, 4286578688, 4290772992, 4292870144,
                        4293918720, 4294443008, 4294705152, 4294836224,
                        4294901760, 4294934528, 4294950912, 4294959104,
                        4294963200, 4294965248, 4294966272, 4294966784,
                        4294967040, 4294967168, 4294967232, 4294967264,
                        4294967280, 4294967288, 4294967292, 4294967294,
                        4294967295)


def right_direction_vals_bytes(data: bytes, **kwargs)-> bool:
    """ Function return cofficient right direction values bytes.
        Right direction bytes is data[i] - data[i + 1] == 1
        data[i] value less that data[i + 1] on 1
        Example:
            this_function(data = b'abcdefg') == True;
            this_function(data = b'gfedcba') == False
        Note: cff must be 0 < cff < 1
    """
    start = kwargs.get("start", 0)
    end = kwargs.get("end", len(data))
    cff = kwargs.get("cff", 0.75)
    if end > len(data) or start >= end:
        raise ValueError(f"right_direction_bytes: Uncorrect end or start value!!!")
    max_count = end - start - 1
    if max_count == 0:
        raise ValueError(f"right_direction_bytes: Uncorrect size data!!! Data must be more 1!!!")
    count = 0
    for i in range(start, end - 1):
        if data[i + 1] - data[i] == 1:
            count +=1
    return count / max_count > cff


def left_direction_vals_bytes(data: bytes, **kwargs)-> bool:
    """ Function return cofficient left direction values bytes
        Left direction bytes is data[i + 1] - data[i] == 1,
        data[i] value more that data[i + 1] on 1
        Example:
            this_function(data = b'abcdefg') == False;
            this_function(data = b'gfedcba') == True
        Note: cff must be 0 < cff < 1
    """
    start = kwargs.get("start", 0)
    end = kwargs.get("end", len(data))
    cff = kwargs.get("cff", 0.75)
    if end > len(data) or start >= end:
        raise ValueError(f"Uncorrect end or start value!!!")
    max_count = end - start - 1
    if max_count == 0:
        raise ValueError(f"right_direction_bytes: Uncorrect size data!!! Data must be more 1!!!")
    count = 0
    for i in range(start, end - 1):
        if data[i] - data[i + 1] == 1:
            count +=1
    return count / max_count > cff


class ICMPAnalyzer:
    def __init__(self, **kwargs):
        """
        :param kwargs:
            deprecated - list deprecated icmp types,
            unassigned - list unassigned icmp types,
            eps_encrypt - value epsilon for check encryption data;
            coeff_bytes_direct - reference value probability for check direct values bytes
        """
        self.deprecated_types = kwargs.get("deprecated", DEFAULT_DEPRECATED_TYPES)
        self.unassigned_types = kwargs.get("unassigned", DEFAULT_UNASSIGNED_TYPES)
        self.eps_encrypt = kwargs.get("eps_encrypt", 0.5)
        self.cff_bdirect = kwargs.get("coeff_bytes_direct", 0.75)

    def analyze(self, packet: bytes, offset = 0):
        assert len(packet) - offset <= MAX_DATA_SIZE_v4ICMP + icmpheader.ICMPHeader.Length, "Too big size packet!!!"
        assert len(packet) - offset >= icmpheader.ICMPHeader.Length, "Too little size packet!!!"
        icmph = icmpheader.ICMPHeader()
        icmph.read_bytes_from(packet, offset)

        icmp_pid = 0
        tunnelled = 0

        pos_data = offset + icmph.Length
        size_data = len(packet) - pos_data

        if icmph.type in  (icmpheader.TYPE_v4EchoRequest, icmpheader.TYPE_v4EchoReply):
            icmp_pid = icmpheader.icmpv4_id(icmph)
            if icmph.code != 0:
                tunnelled = 1
            else:
                if size_data > 1:
                    if not right_direction_vals_bytes(packet, start=pos_data, cff=self.cff_bdirect) and \
                       not left_direction_vals_bytes(packet, start=pos_data, cff=self.cff_bdirect):
                        tunnelled = int(entropy.is_encrypted_data(packet,
                                                 start=pos_data, eps=self.eps_encrypt)) # check data encrypted?

        elif icmph.type in (icmpheader.TYPE_v4TimestampRequest, icmpheader.TYPE_v4TimestampReply):
            icmp_pid = icmpheader.icmpv4_id(icmph)
            if size_data != 12 or icmph.code != 0:
                tunnelled = 1
            else:
                if icmph.type == icmpheader.TYPE_v4TimestampRequest:
                    t1, t2, t3 = struct.unpack_from(">3I", packet, pos_data)
                    if t1 != t2 or t2 != t3 or t1 != t3:
                        tunnelled = 1


        elif icmph.type in (icmpheader.TYPE_v4AddressMaskRequest, icmpheader.TYPE_v4AddressMaskReply):
            icmp_pid = icmpheader.icmpv4_id(icmph)
            if size_data != 4 or icmph.code != 0:
                tunnelled = 1
            else:
                mask_addr = struct.unpack_from('>I', packet, pos_data)
                if mask_addr not in IPV4_POSSIBLE_MASKS:
                    tunnelled = 1

        elif icmph.type == icmpheader.TYPE_v4ExtendedEchoReply:
            icmp_pid = icmpheader.icmpv4_id(icmph)
            if size_data != 0 or icmph.code not in range(0, 5):
                tunnelled = 1

        elif icmph.type == icmpheader.TYPE_v4ExtendedEchoRequest:
            icmp_pid = icmpheader.icmpv4_id(icmph)
            L = struct.unpack_from('>B', icmph.other_bs, 3)[0] & 0b00000001
            min_size = size_data
            if min_size < icmpheader.ICMPExtHeader.Length or icmph.code != 0:
                tunnelled = 1
            else:
                exth = icmpheader.ICMPExtHeader()
                exth.read_bytes_from(packet, pos_data)
                if exth.version != 2:
                    tunnelled = 1
                else:
                    min_size -= icmpheader.ICMPExtHeader.Length
                    if min_size < icmpheader.ICMPExtObjHeader.Length:
                        tunnelled = 1
                    else:
                        exthobj = icmpheader.ICMPExtObjHeader()
                        exthobj.read_bytes_from(packet, offset + icmph.Length + exth.Length)
                        min_size -= exthobj.Length
                        if exthobj.cls_num != 3:
                            tunnelled = 1
                        else:
                            if exthobj.c_type == 1:
                                if L == 0:
                                    tunnelled = 1
                                else:
                                    ifname_len = exthobj.len - exthobj.Length
                                    if ifname_len == 0:
                                        tunnelled = 1
                                    else:
                                        if min_size < ifname_len:
                                            tunnelled = 1
                                        else:
                                            tunnelled = int(entropy.is_encrypted_data(packet,
                                                                                      start= pos_data
                                                                                            + exth.Length
                                                                                            + exthobj.Length,
                                                                                      eps=self.eps_encrypt))
                            elif exthobj.c_type == 2:
                                if L == 0:
                                    tunnelled = 1
                                else:
                                    if exthobj.len != 4 + exthobj.Length:
                                        tunnelled = 1
                            elif exthobj.c_type == 3:
                                if min_size < icmpheader.ICMPIntIdObjAddrHeader.Length:
                                    tunnelled = 1
                                else:
                                    id_obj_addrh = icmpheader.ICMPIntIdObjAddrHeader()
                                    id_obj_addrh.read_bytes_from(packet,
                                    pos_data + exth.Length + exthobj.Length)
                                    if id_obj_addrh.addr_len == 0:
                                        tunnelled = 1
                                    else:
                                        min_size -= id_obj_addrh.Length
                                        loffset = pos_data + exth.Length + exthobj.Length + id_obj_addrh.Length
                                        if min_size < id_obj_addrh.addr_len:
                                            tunnelled = 1
                            else:
                                tunnelled = 1

        elif icmph.type in (icmpheader.TYPE_v4Redirect, icmpheader.TYPE_v4SourceQuench):
            if icmph.type == icmpheader.TYPE_v4SourceQuench:
                codes = range(0, 1)
            else:
                codes = range(0, 4)
                
            if size_data < MIN_DATA_SIZE_v4ICMPErrMsg or \
                    size_data > MAX_DATA_SIZE_v4ICMPErrMsg or icmph.code not in codes:
                tunnelled = 1
            else:
                val = struct.unpack_from('>B', packet, pos_data)[0]
                v = val >> 4
                hl = (val & 0x0f) * 4
                if v != 4 or (hl < ipv4header.IPv4Header.MinLength or hl > ipv4header.IPv4Header.MaxLength):
                    tunnelled = 1
                else:
                    tunnelled = int(entropy.is_encrypted_data(packet, start=pos_data, eps=self.eps_encrypt))

        elif icmph.type == icmpheader.TYPE_v4RouterAdvertisement:
            if icmph.code != 0:
                tunnelled = 1
            else:
                num_addr = struct.unpack_from('>B', packet, offset + 4)[0]
                life_time = struct.unpack_from('>H', packet, offset + 6)[0]
                addr_entry_size = struct.unpack_from('>B', packet, offset + 5)[0] * 4
                if num_addr == 0 or life_time == 0 or num_addr * addr_entry_size != size_data:
                    tunnelled = 1
                else:
                    tunnelled = int(entropy.is_encrypted_data(packet, start=pos_data, eps=self.eps_encrypt))

        elif icmph.type in (icmpheader.TYPE_v4DestinationUnreachable,
                            icmpheader.TYPE_v4TimeExceeded, icmpheader.TYPE_v4SourceQuench,
                            icmpheader.TYPE_v4ParameterProblem):

            if icmph.type == icmpheader.TYPE_v4DestinationUnreachable:
                codes = range(0, 16)
            elif icmph.type == icmpheader.TYPE_v4TimeExceeded:
                codes = range(0, 2)
            else:
                # icmph.type == icmpheader.TYPE_v4ParameterProblem
                codes = range(0, 3)
            if size_data < MIN_DATA_SIZE_v4ICMPErrMsg or icmph.code not in codes:
                tunnelled = 1
            else:
                val = struct.unpack_from('>B', packet, pos_data)[0]
                v = val >> 4
                hl = (val & 0x0f) * 4
                if v != 4 or (hl < ipv4header.IPv4Header.MinLength or hl > ipv4header.IPv4Header.MaxLength):
                    tunnelled = 1
                else:
                    length = struct.unpack_from('>B', packet, pos_data - 3)[0]
                    if length == 0:
                        tunnelled = int(entropy.is_encrypted_data(packet, start=pos_data, eps=self.eps_encrypt))
                    else:
                        length *= 4
                        length += 20
                        if length < 128 or size_data <= length + icmpheader.ICMPExtHeader.Length:
                            tunnelled = 1
                        else:
                            zcount = 0
                            i = pos_data + length - 1
                            while packet[i] == 0x00 and i >= pos_data + 20:
                                i -= 1
                                zcount += 1
                            e1 = entropy.is_encrypted_data(packet, start=pos_data, end=pos_data + length - zcount,
                                                                   eps=self.eps_encrypt)
                            exthdr = icmpheader.ICMPExtHeader()
                            exthdr.read_bytes_from(packet, pos_data + length)
                            if exthdr.version == 2:
                                e2 = entropy.is_encrypted_data(packet,
                                     start=pos_data + length + icmpheader.ICMPExtHeader.Length,
                                     end=pos_data + size_data, eps=self.eps_encrypt)
                            else:
                                e2 = 1
                            tunnelled = int(e1 or e2)

        if icmph.type in self.deprecated_types or icmph.type in self.unassigned_types:
            tunnelled = 1
        return icmp_pid, tunnelled