import base64
import struct
import socket
import ipv4header
import icmpheader
import net_header
import random
from rfc1071_checksum import checksum
import bytes_scrambler
import time


#     Principles of building ICMP packets in the tunnel
#
#     Example 1:
#
#     type = 8, code = 0 Echo Request
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |             ID              |           SeqNum            |
#     +-----------------------------+-----------------------------+   -----
#     |                        random_bytes                       |     ^
#     |                                                           |     |
#     |                       (scrcoeff[0] bytes)                 |  max 65507 bytes
#     +-----------------------------------------------------------+     |
#     |                     0 < Data  <= 65507 - scrcoeff[0]      |     v
#     +-----------------------------------------------------------+   -----
#
#
#     Example 2:
#
#     type = 3, code = 0 - 15 Destination Unreachable
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |                           Unused                          |
#     +-----------------------------------------------------------+    -----
#     |       0x45   |          ID (2 bytes)       |    SeqNum(1) |      ^
#     +--------------+-----------------------------+--------------+      |
#     |    SeqNum(1) |       random_bytes (scrcoeff[0] bytes)     |      |
#     +--------------+--------------------------------------------+    28 bytes
#     | len_bfill(1) |       0 < Data <= 22 - scrcoeff[0]         |      |
#     +--------------+--------------------------------------------+      |
#     |                      bytes filler                         |      v
#     +-----------------------------------------------------------+    -----
#
#     * the first byte must always be 0x45 for the packet to be valid;
#     * bytes_filler - byte placeholder to align packet data area up to 28 bytes,
#       is a random byte sequence;
#     * len_bfill - the size of the byte placeholder in the packet;
#
#     Example 3:
#
#     type = 5, code = 0-3 Redirect
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |   Gateway Addr(ID(2))       |  Gateway Addr(SeqNum(2))    |
#     +--------------+--------------+-----------------------------+   -----
#     |              |          random_bytes                      |     ^
#     |     0x45     |                                            |     |
#     |              |         (scrcoeff[0] bytes)                |  28 bytes
#     +--------------+--------------------------------------------+     |
#     | len_bfill(1) |         0 < Data  <= 26 - scrcoeff[0]      |     v
#     +--------------+--------------------------------------------+   -----
#
#     Example 4:
#
#     type = 13, code = 0 Timestamp Request
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |             ID              |           SeqNum            |
#     +-----------------------------------------------------------+    -----
#     |                        random_bytes                       |      ^
#     |                                                           |      |
#     |                       (scrcoeff[0] bytes)                 |      |
#     +--------------+--------------------------------------------+     12 bytes
#     | len_bfill(1) |         0 < Data <= 11 - scrcoeff[0]       |      |
#     +--------------+--------------------------------------------+      |
#     |                      bytes filler                         |      v
#     +-----------------------------------------------------------+    -----
#
#
#     Example 5:
#
#     type = 9, code = 0 Router Advertisement
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |   NumAddrs   | AddrEntrySize|           Life time         |
#     +-----------------------------+-----------------------------+
#     |             ID (2 bytes)    |           SeqNum (2 bytes)  |
#     +-----------------------------+-----------------------------+    -----
#     |                        random_bytes                       |      ^
#     |                                                           |      |
#     |                       (scrcoeff[0] bytes)                 |      |
#     +--------------+--------------------------------------------+   max 2040 bytes
#     | len_bfill(1) |         0 < Data <= 2035 - scrcoeff[0]     |      |
#     +--------------+--------------------------------------------+      |
#     |                      bytes filler                         |      v
#     +-----------------------------------------------------------+    -----
#
#     bytes_filler - in this case is needed for 8-byte alignment
#
#     Router Advertisement carries pairs of values in the data field (Router Address[i], Preference level[i]),
#     where Router Address[i] for IPv4 4 bytes, Preference level[i] - 4 bytes;
#     AddrEntrySize = 2 - machine words for tuple description (Router Address[i], Preference level[i]);
#
#
#     Example 6:
#
#     type = 12, code = 0-2 Parameter Problem
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |Pointer(ID(1))|             Unused                         |
#     +--------------+--------------+-----------------------------+    -----
#     |      0x45    |     ID (1)   |    SeqNum(2 bytes)          |      ^
#     +--------------+--------------+--------------+--------------+      |
#     |            random_bytes (scrcoeff[0] bytes)               |      |
#     +--------------+--------------------------------------------+    28 bytes
#     | len_bfill(1) |       0 < Data <= 23 - scrcoeff[0]         |      |
#     +--------------+--------------------------------------------+      |
#     |                      bytes filler                         |      v
#     +-----------------------------------------------------------+    -----
#
#     Pointer field encapsulates 1 byte from ID
#
#
#
#     Example 7:
#
#     type = 17, code = 0 Address Mask Request
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |             ID              |           SeqNum            |
#     +-----------------------------+-----------------------------+   -----
#     |                        random_bytes                       |     ^
#     |                                                           |     |
#     |                       (scrcoeff[0] bytes)                 |     |
#     +--------------+--------------------------------------------+   4 bytes
#     | len_bfill(1) |        0 < Data  <= 3 - scrcoeff[0]        |     |
#     +--------------+--------------------------------------------+     |
#     |                      bytes filler                         |     v
#     +-----------------------------------------------------------+   -----
#
#
#    Example 8:
#     type = 3, code = 0 - 15 Destination Unreachable
#
#     +--------------+--------------+-----------------------------+
#     |     Type     |     Code     |           Checksum          |
#     +--------------+--------------+-----------------------------+
#     |                           Unused                          |
#     +-----------------------------------------------------------+    -----
#     |       0x45   |          ID (2 bytes)       |    SeqNum(1) |      ^
#     +--------------+-----------------------------+--------------+      |
#     |    SeqNum(1) |       random_bytes (scrcoeff[0] bytes)     |      |
#     +--------------+--------------------------------------------+ ---  |
#     |                                                           |  ^   .---------------.
#     |                          Data                             | min 128 bytes        |
#     |                                                           |  v   .---------------.
#     +-----------------------------------------------------------+ ---  |
#     |                      ICMP Extension Header(4 bytes)       |      |
#     +-----------------------------------------------------------+      |
#     |           Interface Info Object Header(4 bytes)           |      |
#     +-----------------------------------------------------------+      |
#     |                Interface Index (4 bytes)                  |      |
#     +-----------------------------+-----------------------------+      |
#     |           AFI               |          Reserved           |    max 576 bytes
#     +-----------------------------+-----------------------------+      |
#     |                        IP Address                         |      |      # or 4 bytes IPv4 or 16 bytes IPv6
#     +-----------------------------------------------------------+      |
#     |  Length name | Interface Name (max 63 bytes)(Data max 45) |      |       # data encoding base 64 and max size 45 bytes
#     +--------------+--------------------------------------------+      |
#     |                        MTU (4 bytes)                      |      |
#     +-----------------------------------------------------------+      |
#     |              Interface Info Object Header(4 bytes)        |      |
#     +-----------------------------------------------------------+      |
#     |                                                           |      |
#     /                                                           /      /
#     .                                                           .      .
#     .                                                           .      .
#     .                                                           .      .
#     /                                                           /      /
#     |                                                           |      |
#     |                                                           |      v
#     +-----------------------------------------------------------+    -----
#
#     `lenbfill` field is included in the last `ifindex` or `ifaddr` or `ifname` or `mtu` that needs a placeholder.
#     No placeholder required for `Data`. No `lenbfill` required for `Data`, because `Length` attribute has been added to the ICMP header.
#     When tunneling, you must first fill the Extention Structure to the maximum (to up 4 Interface Info Objects),
#     and based on this, calculate the data size in the datagram area


MAX_DATA_SIZE_v4ICMP = 65507
MIN_DATA_SIZE_v4ICMP = 1

MAX_DATA_SIZE_v4ICMPAddrMask = 4
MAX_DATA_SIZE_v4ICMPTimestamp = 12

MIN_DATA_SIZE_v4ICMPErrMsg = 28
MAX_DATA_SIZE_v4ICMPErrMsg = 576

MAX_DATA_SIZE_v4ICMPRouterAdvertisement = 2040
MAX_DATA_SIZE_v4ICMPEcho = 65507


class TICMPConnector:
    def __init__(self, **kwargs):
        self.init_connection(**kwargs)

    def init_connection(self, **kwargs):
        """Method for initialization ticmp-connection.
           set all params connection in other values or default values"""
        self.set_id(kwargs.get("id", 8191))
        self.__seq_num = 0
        scr_coeffs = kwargs.get("scr_coeffs")
        self.__scrambler = bytes_scrambler.Scrambler(scr_coeffs if scr_coeffs else [1, 3, 5])
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.__socket.bind((kwargs.get("listen_addr",
                                       socket.gethostbyname_ex(socket.gethostname())[2][-1]), 0))

    def set_scrambler_coeffs(self, coeffs: list)-> None:
        self.__scrambler.set_coeffs(coeffs)

    def scrambler_coeffs(self)-> tuple:
        return self.__scrambler.coeffs()

    def set_id(self, val: int)-> None:
        if val < 0 or val > 65535:
            raise ValueError("Uncorrect value for id!!! id must be 0 <= id <= 65535")
        self.__id = val

    def __inc_seq_num(self):
        self.__seq_num += 1
        if self.__seq_num > 65535:
            self.__seq_num = 0

    def id(self)-> int:
        return self.__id

    def seq_num(self)-> int:
        return self.__seq_num

    def pack_data_in_packet(self, data: bytes):
        assert len(data) > 0 and len(data) <= MAX_DATA_SIZE_v4ICMP - self.scrambler_coeffs()[0],\
               "Bad data size for packing in icmpv4!!!"
        r = 0
        size_encrypted_data = len(data) + self.scrambler_coeffs()[0]
        if size_encrypted_data <= MAX_DATA_SIZE_v4ICMPAddrMask - 1:
            # include type = 17
            # 1 = len(lenbfill)
            r = random.randint(0, 11)
        elif size_encrypted_data <= 4:
            # include type = 42; afi = 16389
            # 6 - 1 - 1    # 4 = len(MAC) - len(lenbfill) - len(seq_num(1))
            r = random.randint(0, 10)
        elif size_encrypted_data <= MAX_DATA_SIZE_v4ICMPTimestamp - 1:
            # include type = 13
            # 1 = len(lenbfill)
            r = random.randint(0, 9)
        elif size_encrypted_data <= 14:
            # include type = 42; afi = 2
            # 16 - 1 - 1   # 14 = len(IPv6) - len(lenbfill) - len(seq_num(1))
            r = random.randint(0, 8)
        elif size_encrypted_data <= MIN_DATA_SIZE_v4ICMPErrMsg - 6:
            # include type = 4
            # 6 = len(0x45) + len(lenbfill) + len(id) + len(seq_num)
            r = random.randint(0, 7)
        elif size_encrypted_data <= MIN_DATA_SIZE_v4ICMPErrMsg - 2:
            # include type = 5 with max size datagram;
            # 2 = len(0x45) + len(lenbfill)
            r = random.randint(0, 6)
        elif size_encrypted_data <= 46:
            # include type = 42; ifname;
            # max size ifname = 63 in ifname sub-obj in rfc5837 with field length
            # max size ifname = 64 in ifname sub-obj without field length
            # 48 = 3*(64/4) for applying base64; 48 - 1 - 1   # 1 = len(lenbfill); 1 = len(seq_num(1))
            r = random.randint(0, 5)
        elif size_encrypted_data <= MAX_DATA_SIZE_v4ICMPErrMsg - 6:
            # include type = 3,11 with max size datagram;
            # 6 = len(0x45) + len(lenbfill) + len(id) + len(seq_num)
            r = random.randint(0, 4)
        elif size_encrypted_data <= MAX_DATA_SIZE_v4ICMPErrMsg - 5:
            # include type = 12 with max size datagram;
            # 5 = len(0x45) + len(lenbfill) + len(id(1)) + len(seq_num)
            r = random.randint(0, 2)
        elif size_encrypted_data <= MAX_DATA_SIZE_v4ICMPRouterAdvertisement - 5:
            # include type = 9;
            # 5 = len(lenbfill) + len(id) + len(seq_num)
            r = random.randint(0, 1)

        def fpack_17_13(this, icmph, max_size):
            # 1 = len(lenbfill)
            icmpheader.icmpv4_set_id(icmph, this.__id)
            icmpheader.icmpv4_set_seq_num(icmph, this.__seq_num)
            bfill_size = max_size - len(data) - 1 - this.scrambler_coeffs()[0]  # size bytes for fill
            buffer = bytearray(icmph.Length + max_size)                         # prepare buffer
            fmt = f">{max_size}s"                                           # create fromat writing data in buffer
            struct.pack_into(fmt, buffer, icmph.Length,                     # scramble(lenbfill + data + bytes_filler)
                             this.__scrambler.scramble(bytes([bfill_size]), data,
                                                       bytes([random.randint(0, 255) for i in range(bfill_size)])))
            return buffer

        def fpack_42_addr(this, icmph, addr_len, afi):
            # 2 = len(lenbfill) + len(seq_num(1))
            icmpheader.icmpv4_set_id(icmph, this.__id)
            icmpheader.icmpv4_set_seq_num(icmph, (this.__seq_num & 0xff00) | 0x0001)       # pack first byte seq_num
            ext_h = icmpheader.ICMPExtHeader(hversion=2)
            ext_obj_h = icmpheader.ICMPExtObjHeader(hlen=icmpheader.ICMPExtObjHeader.Length +
                                                         icmpheader.ICMPIntIdObjAddrHeader.Length + addr_len,
                                                         hcls_num=3, hc_type=3)
            ext_obj_addr_h = icmpheader.ICMPIntIdObjAddrHeader(hafi=afi, haddr_len=addr_len)

            bfill_size = addr_len - len(data) - 2 - this.scrambler_coeffs()[0]          # calculate size bytes_filler
            buffer = bytearray(icmph.Length + ext_h.Length + ext_obj_h.Length + ext_obj_addr_h.Length + addr_len)
            fmt = f">B{addr_len - 1}s"
            struct.pack_into(fmt, buffer, len(buffer) - addr_len, this.__seq_num & 0x00ff,   # pack second byte seq_num
                             this.__scrambler.scramble(bytes([bfill_size]), data,
                                                       bytes([random.randint(0, 255) for i in range(bfill_size)])))
            ext_obj_addr_h.write_bytes_into(buffer, icmph.Length + ext_h.Length + ext_obj_h.Length)
            ext_obj_h.write_bytes_into(buffer, icmph.Length + ext_h.Length)
            ext_h.write_bytes_into(buffer, icmph.Length)
            struct.pack_into('>H', buffer, icmph.Length + 2, checksum(buffer[icmph.Length:]))
            return buffer

        def fpack_3_11_4_min(this, icmph):
            # 6 = len(0x45) + len(id) + len(seq_num) + len(lenbfill)
            buffer = bytearray(icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg)
            buffer[icmph.Length] = 0x45
            struct.pack_into('>HH', buffer, icmph.Length + 1, this.__id, this.__seq_num)
            bfill_size = MIN_DATA_SIZE_v4ICMPErrMsg - len(data) - 6 - this.scrambler_coeffs()[0]
            fmt = f'>{MIN_DATA_SIZE_v4ICMPErrMsg - 5}s'
            struct.pack_into(fmt, buffer, icmph.Length + 5,
                             this.__scrambler.scramble(bytes([bfill_size]), data,
                                                       bytes([random.randint(0, 255) for i in range(bfill_size)])))
            return buffer

        def fpack_3_11(this, icmph, size_encrypted_data):
            if size_encrypted_data <= MIN_DATA_SIZE_v4ICMPErrMsg - 6:
                # 6 = len(0x45) + len(id) + len(seq_num) + len(lenbfill)
                buffer = fpack_3_11_4_min(this, icmph)
            else:
                r = random.randint(0, 1) if size_encrypted_data <= 457 else 0
                if r == 1:
                    # 7 = len(lenbfill) + len(seq_num) + len(id) + len(0x45) + len(lenzfill)
                    # max size ifname = 63 in ifname sub-obj with field length, ifindex size = 4, mtu size = 4 in rfc5837
                    # 45 = 3*(63//4) for applying base64; 45
                    # (63 * 4) + (4 * 4) + (4 * 4) + (4 * 4) = 300;  ifname*4 + ifindex*4 + ifaddr*4 + mtu*4
                    # (1 * 4) + (4 * 4) + (4 * 4) + 4 = 40;   len_ifname*4 + hdr_afi*4 + int_info_obj_hdr*4 + icmp_ext_header
                    # 300 - 4 * (63 - 45) = 228;
                    # 576 - 340 = 236; 236 - 6 + 228 - 1 = 457 # 7 = len(0x45) + len(id) + len(seq_num) + len(lenbfill) + len(lenzfill)
                    size_encrypted_data = len(data) + this.scrambler_coeffs()[0] + 1        # 1 = len(lenbfill)
                    dif = size_encrypted_data - 230                                         # 230 = 236 - 6
                    bfill_size = 228 - dif if dif > 0 else 228
                    size4data = (230 if size_encrypted_data > 230 else size_encrypted_data)     # size datagram field
                    if size_encrypted_data < 122:
                        zero_fill = 122 - size_encrypted_data                                   # 122 = 128 - 6
                    else:
                        ost = (6 + size4data) % 4
                        zero_fill = 4 - ost if ost > 0 else 0                                   # size zero bytes filler

                    ext_h = icmpheader.ICMPExtHeader(hversion=2)
                    size_icmph_with_datagram = icmpheader.ICMPHeader.Length + 6 + size4data + zero_fill
                    buffer = bytearray(size_icmph_with_datagram + 340)
                    buffer[icmph.Length] = 0x45
                    struct.pack_into('>HHB', buffer, icmph.Length + 1, this.__id, this.__seq_num, zero_fill)
                    scramble_data = this.__scrambler.scramble(bytes([bfill_size]),
                                                              data,
                                                              bytes([random.randint(0, 255) for i in range(bfill_size)]))
                    fmt = f'>{size4data}s'
                    struct.pack_into(fmt, buffer, icmph.Length + 6, scramble_data[:size4data])
                    ext_h = icmpheader.ICMPExtHeader(hversion=2)
                    role = 0b00001111
                    offset_buf = size_icmph_with_datagram + ext_h.Length
                    offset_data = size4data
                    for i in range(4):
                        ext_obj_h = icmpheader.ICMPExtObjHeader(hcls_num=2, hc_type=role)
                        ext_obj_h.len = ext_obj_h.Length + 80                                 # 80 = 4 + 8 + 64 + 4
                        ext_obj_h.write_bytes_into(buffer, offset_buf)
                        offset_buf += ext_obj_h.Length

                        struct.pack_into('>4s', buffer, offset_buf, scramble_data[offset_data:offset_data + 4])   # pack in ifindex
                        offset_buf += 4
                        offset_data += 4

                        ext_obj_addr_h = icmpheader.ICMPIntIPAddrSubObjHeader(hafi=net_header.AFI_IPv4) # pack in ifaddr
                        ext_obj_addr_h.write_bytes_into(buffer, offset_buf)
                        offset_buf += ext_obj_addr_h.Length
                        struct.pack_into('>4s', buffer, offset_buf, scramble_data[offset_data:offset_data + 4])
                        offset_buf += 4
                        offset_data += 4

                        struct.pack_into('>B60s3s', buffer, offset_buf, 61,                           # pack in ifname
                                         base64.urlsafe_b64encode(scramble_data[offset_data:offset_data + 45]),
                                         b'\x00\x00\x00')
                        offset_buf += 64
                        offset_data += 45

                        struct.pack_into('>4s', buffer, offset_buf, scramble_data[offset_data:offset_data + 4])   # pack in mtu
                        offset_buf += 4
                        offset_data += 4
                        role += 0b01000000
                    ext_h.write_bytes_into(buffer, size_icmph_with_datagram)
                    struct.pack_into('>H', buffer, size_icmph_with_datagram + 2,
                                     checksum(buffer[size_icmph_with_datagram:]))
                    struct.pack_into('>B', icmph.other_bs, 1, (size4data - 14 + zero_fill) // 4)
                else:
                    # 5 = len(0x45) + len(id) + len(seq_num)
                    buffer = bytearray(icmph.Length + 5 + len(data) + this.scrambler_coeffs()[0])
                    buffer[icmph.Length] = 0x45
                    struct.pack_into('>HH', buffer, icmph.Length + 1, this.__id, this.__seq_num)
                    fmt = f'>{len(data) + this.scrambler_coeffs()[0]}s'
                    struct.pack_into(fmt, buffer, icmph.Length + 5,
                                     this.__scrambler.scramble(data))
            return buffer

        icmph = None
        buffer = None
        if r == 1:
            # ====== v4RouterAdvertisement =========
            # 5 = len(lenbfill) + len(id) + len(seq_num)
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4RouterAdvertisement, hcode=0)
            num_addrs = (len(data) + self.scrambler_coeffs()[0] + 5) // 8
            mod = (len(data) + self.scrambler_coeffs()[0] + 5) % 8
            bfill_size = 0
            if mod > 0:
                num_addrs += 1
                bfill_size = 8 - mod
            buffer = bytearray(icmph.Length + num_addrs * 8)
            struct.pack_into('>2BH', icmph.other_bs, 0, num_addrs, 2, random.randint(1800, 65535))    # life time default 30 min
            struct.pack_into('>2H', buffer, icmph.Length, self.__id, self.__seq_num)
            fmt = f'>{len(data) + self.scrambler_coeffs()[0] + 1 + bfill_size}s'
            struct.pack_into(fmt, buffer, icmph.Length + 4,
                             self.__scrambler.scramble(bytes([bfill_size]), data,
                                                       bytes([random.randint(0, 255) for i in range(bfill_size)])))
        elif r == 2:
            # ====== v4ParameterProblem =========
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4ParameterProblem, hcode=random.randint(0, 2))
            if size_encrypted_data <= MIN_DATA_SIZE_v4ICMPErrMsg - 5:
                # 5 = len(0x45) + len(lenbfill) + len(id(1)) + len(seq_num)
                icmpheader.icmpv4_set_id(icmph, self.__id & 0xff00)  # pack high byte id
                buffer = bytearray(icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg)
                buffer[icmph.Length] = 0x45
                struct.pack_into('>BH', buffer, icmph.Length + 1, self.__id & 0x00ff, self.__seq_num)
                bfill_size = MIN_DATA_SIZE_v4ICMPErrMsg - len(data) - 5 - self.scrambler_coeffs()[0]
                fmt = f'>{MIN_DATA_SIZE_v4ICMPErrMsg - 4}s'
                struct.pack_into(fmt, buffer, icmph.Length + 4,
                                 self.__scrambler.scramble(bytes([bfill_size]), data,
                                                           bytes([random.randint(0, 255) for i in range(bfill_size)])))
            else:
                r = random.randint(0, 1) if size_encrypted_data <= 458 else 0
                if r == 1:
                    # 6 = len(lenbfill) + len(seq_num) + len(id(1)) + len(0x45) + len(lenzfill)
                    # (63 * 4) + (4 * 4) + (4 * 4) = 284;  ifname*4 + ifindex*4 + ifaddr*4
                    # (1 * 4) + (4 * 4) + (4 * 4) + 4 = 40;   len_ifname*4 + hdr_afi*4 + int_info_obj_hdr*4 + icmp_ext_header
                    # 284 - 4 * (63 - 45) = 212;
                    # 576 - 324 = 252; 252 - 6 + 212 = 458        # 6 = len(lenbfill) + len(seq_num) + len(id(1)) + len(0x45) + len(lenzfill)
                    icmpheader.icmpv4_set_id(icmph, self.__id & 0xff00)
                    size_encrypted_data = len(data) + self.scrambler_coeffs()[0] + 1        # 1 = len(lenbfill)
                    dif = size_encrypted_data - 247                                         # 247 = 252 - 5
                    bfill_size = 212 - dif if dif > 0 else 212
                    size4data = (247 if size_encrypted_data > 247 else size_encrypted_data)     # size datagram field
                    if size_encrypted_data < 123:
                        zero_fill = 123 - size_encrypted_data                                   # 123 = 128 - 5
                    else:
                        ost = (5 + size4data) % 4
                        zero_fill = 4 - ost if ost > 0 else 0                                   # size zero bytes filler

                    ext_h = icmpheader.ICMPExtHeader(hversion=2)
                    size_icmph_with_datagram = icmpheader.ICMPHeader.Length + 5 + size4data + zero_fill
                    buffer = bytearray(size_icmph_with_datagram + 324)
                    buffer[icmph.Length] = 0x45
                    struct.pack_into('>BHB', buffer, icmph.Length + 1, self.__id & 0x00ff, self.__seq_num, zero_fill)
                    scramble_data = self.__scrambler.scramble(bytes([bfill_size]),
                                                              data,
                                                              bytes([random.randint(0, 255) for i in range(bfill_size)]))
                    fmt = f'>{size4data}s'
                    struct.pack_into(fmt, buffer, icmph.Length + 5, scramble_data[:size4data])
                    ext_h = icmpheader.ICMPExtHeader(hversion=2)
                    role = 0b00001110
                    offset_buf = size_icmph_with_datagram + ext_h.Length
                    offset_data = size4data
                    for i in range(4):
                        ext_obj_h = icmpheader.ICMPExtObjHeader(hcls_num=2, hc_type=role)
                        ext_obj_h.len = ext_obj_h.Length + 76                                 # 76 = 4 + 8 + 64
                        ext_obj_h.write_bytes_into(buffer, offset_buf)
                        offset_buf += ext_obj_h.Length

                        struct.pack_into('>4s', buffer, offset_buf, scramble_data[offset_data:offset_data + 4])   # pack in ifindex
                        offset_buf += 4
                        offset_data += 4

                        ext_obj_addr_h = icmpheader.ICMPIntIPAddrSubObjHeader(hafi=net_header.AFI_IPv4) # pack in ifaddr
                        ext_obj_addr_h.write_bytes_into(buffer, offset_buf)
                        offset_buf += ext_obj_addr_h.Length
                        struct.pack_into('>4s', buffer, offset_buf, scramble_data[offset_data:offset_data + 4])
                        offset_buf += 4
                        offset_data += 4

                        struct.pack_into('>B60s3s', buffer, offset_buf, 61,                           # pack in ifname
                                         base64.urlsafe_b64encode(scramble_data[offset_data:offset_data + 45]),
                                         b'\x00\x00\x00')
                        offset_buf += 64
                        offset_data += 45
                        role += 0b01000000

                    ext_h.write_bytes_into(buffer, size_icmph_with_datagram)
                    struct.pack_into('>H', buffer, size_icmph_with_datagram + 2,
                                     checksum(buffer[size_icmph_with_datagram:]))
                    struct.pack_into('>B', icmph.other_bs, 1, (size4data - 15 + zero_fill) // 4)
                else:
                    # 4 = len(0x45) + len(id(1)) + len(seq_num)
                    buffer = bytearray(icmph.Length + 4 + len(data) + self.scrambler_coeffs()[0])
                    buffer[icmph.Length] = 0x45
                    icmpheader.icmpv4_set_id(icmph, self.__id & 0xff00)
                    struct.pack_into('>BH', buffer, icmph.Length + 1, self.__id & 0x00ff, self.__seq_num)
                    fmt = f'>{len(data) + self.scrambler_coeffs()[0]}s'
                    struct.pack_into(fmt, buffer, icmph.Length + 4,
                                     self.__scrambler.scramble(data))
        elif r == 3:
            # ====== v4TimeExceeded =========
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4TimeExceeded, hcode=random.randint(0, 1))
            buffer = fpack_3_11(self, icmph, size_encrypted_data)
        elif r == 4:
            # ====== v4DestinationUnreachable =========
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4DestinationUnreachable, hcode=random.randint(0, 15))
            buffer = fpack_3_11(self, icmph, size_encrypted_data)
        elif r == 5:
            # ====== v4ExtendedEchoRequest =========
            # max size ifname = 63 in ifname sub-obj in rfc5837 with field length
            # max size ifname = 64 in ifname sub-obj without field length
            # 48 = 3*(64/4) for applying base64; 48 - 1 - 1   # 1 = len(lenbfill); 1 = len(seq_num(1))
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4ExtendedEchoRequest, hcode=0)
            icmpheader.icmpv4_set_id(icmph, self.__id)
            icmpheader.icmpv4_set_seq_num(icmph, (self.__seq_num & 0xff00) | 0x0001)        # set bit L = 1

            ext_h = icmpheader.ICMPExtHeader(hversion=2)
            ext_obj_h = icmpheader.ICMPExtObjHeader(hlen=68, hcls_num=3, hc_type=1)
            buffer = bytearray(icmph.Length + ext_h.Length + ext_obj_h.Length + 64)
            bfill_size = 46 - len(data) - self.scrambler_coeffs()[0]
            struct.pack_into('64s', buffer, len(buffer) - 64,
                             base64.urlsafe_b64encode(bytes([self.__seq_num & 0x00ff]) +
                                                      self.__scrambler.scramble(bytes([bfill_size]), data,
                                                      bytes([random.randint(0, 255) for i in range(bfill_size)]))))
            ext_obj_h.write_bytes_into(buffer, icmph.Length + ext_h.Length)
            ext_h.write_bytes_into(buffer, icmph.Length)
            struct.pack_into('>H', buffer, icmph.Length + 2, checksum(buffer[icmph.Length:]))
        elif r == 6:
            # ====== v4Redirect =========
            # 2 = len(0x45) + len(lenbfill)
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4Redirect, hcode=random.randint(0, 3))
            icmpheader.icmpv4_set_id(icmph, self.__id)
            icmpheader.icmpv4_set_seq_num(icmph, self.__seq_num)
            buffer = bytearray(icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg)
            buffer[icmph.Length] = 0x45
            bfill_size = MIN_DATA_SIZE_v4ICMPErrMsg - len(data) - 2 - self.scrambler_coeffs()[0]
            fmt = f'{MIN_DATA_SIZE_v4ICMPErrMsg - 1}s'
            struct.pack_into(fmt, buffer, icmph.Length + 1, self.__scrambler.scramble(bytes([bfill_size]), data,
                                                       bytes([random.randint(0, 255) for i in range(bfill_size)])))
        elif r == 7:
            # ====== v4SourceQuench =========
            # 6 = len(0x45) + len(id) + len(seq_num) + len(lenbfill)
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4SourceQuench, hcode=0)
            buffer = fpack_3_11_4_min(self, icmph)
        elif r == 8:
            # ====== v4ExtendedEchoRequest =========
            # 16 - 1 - 1   # 14 = len(IPv6) - len(lenbfill) - len(seq_num(1))
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4ExtendedEchoRequest, hcode=0)
            buffer = fpack_42_addr(self, icmph, 16, net_header.AFI_IPv6)
        elif r == 9:
            # ====== v4TimestampRequest =========
            # 1 = len(lenbfill)
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4TimestampRequest, hcode=0)
            buffer = fpack_17_13(self, icmph, MAX_DATA_SIZE_v4ICMPTimestamp)
        elif r == 10:
            # ====== v4ExtendedEchoRequest =========
            # 6 - 1 - 1    # 4 = len(MAC-48) - len(lenbfill) - len(seq_num(1))
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4ExtendedEchoRequest, hcode=0)
            buffer = fpack_42_addr(self, icmph, 6, net_header.AFI_MAC48)
        elif r == 11:
            # ====== v4AddressMaskRequest =========
            # 1 = len(lenbfill)
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4AddressMaskRequest, hcode=0)
            buffer = fpack_17_13(self, icmph, MAX_DATA_SIZE_v4ICMPAddrMask)
        else:
            # ====== v4EchoRequest =========
            icmph = icmpheader.ICMPHeader(htype=icmpheader.TYPE_v4EchoRequest, hcode=0)
            icmpheader.icmpv4_set_id(icmph, self.__id)
            icmpheader.icmpv4_set_seq_num(icmph, self.__seq_num)
            buffer = bytearray(icmph.Length + len(data) + self.scrambler_coeffs()[0])
            fmt = f'>{len(data) + self.scrambler_coeffs()[0]}s'
            struct.pack_into(fmt, buffer, icmph.Length, self.__scrambler.scramble(data))

        icmph.write_bytes_into(buffer, 0)                        # pack icmpheader in buffer
        struct.pack_into('>H', buffer, 2, checksum(buffer))      # calculate header checksum and pack value in buffer
        return buffer

    def unpack_data_of_packet(self, data: bytes)-> bytearray:
        assert len(data) >= icmpheader.ICMPHeader.Length + self.scrambler_coeffs()[0] and len(data) <= 65515, \
               "Bad data size for unpacking of icmpv4!!!"
        def unpack_of_bfill(data: bytes)->bytes:
            # 1 = len(lenbfill)
            if len(data) < 1:
                return None
            return data[1:len(data) - data[0]] if len(data) > data[0] else None

        icmph = icmpheader.ICMPHeader(hbytes=data)
        if icmph.type == icmpheader.TYPE_v4EchoRequest:
            return self.__scrambler.descramble(data[icmph.Length:])

        elif icmph.type in (icmpheader.TYPE_v4AddressMaskRequest, icmpheader.TYPE_v4TimestampRequest):
            # 1 = len(lenbfill)
            return unpack_of_bfill(self.__scrambler.descramble(data[icmph.Length:]))

        elif icmph.type == icmpheader.TYPE_v4ExtendedEchoRequest:
            min_size = icmph.Length + icmpheader.ICMPExtHeader.Length + icmpheader.ICMPExtObjHeader.Length
            if len(data) < min_size:
                return None
            exth = icmpheader.ICMPExtHeader()
            exth.read_bytes_from(data, icmph.Length)
            if exth.version != 2:
                return None
            extobjh = icmpheader.ICMPExtObjHeader()
            extobjh.read_bytes_from(data, icmph.Length + icmpheader.ICMPExtHeader.Length)
            if extobjh.cls_num != 3 or extobjh.len <= extobjh.Length:
                return None
            if extobjh.c_type == 3:
                # 6 - 1 - 1    # 4 = len(MAC-48) - len(lenbfill) - len(seq_num(1))
                # 16 - 1 - 1   # 14 = len(IPv6) - len(lenbfill) - len(seq_num(1))
                if len(data) < min_size + icmpheader.ICMPIntIdObjAddrHeader.Length:
                    return None
                extaddrh = icmpheader.ICMPIntIdObjAddrHeader()
                extaddrh.read_bytes_from(data, min_size)
                min_size += icmpheader.ICMPIntIdObjAddrHeader.Length
                if extaddrh.afi == net_header.AFI_MAC48 and extaddrh.addr_len == 6:
                    len_addr = 6
                elif extaddrh.afi == net_header.AFI_IPv6 and extaddrh.addr_len == 16:
                    len_addr = 16
                else:
                    return None
                if len(data) < min_size + len_addr:
                    return None
                ans = data[min_size + 1:min_size + len_addr]
            elif extobjh.c_type == 1:
                # 48 = 3*(64/4) for applying base64; 48 - 1 - 1   # 1 = len(lenbfill); 1 = len(seq_num(1))
                if len(data) < min_size + 64:
                    return None
                ans = base64.urlsafe_b64decode(data[min_size: min_size + 64])[1:]
            else:
                return None
            return unpack_of_bfill(self.__scrambler.descramble(ans))

        elif icmph.type in (icmpheader.TYPE_v4SourceQuench, icmpheader.TYPE_v4DestinationUnreachable,
                            icmpheader.TYPE_v4TimeExceeded):
            if len(data) == icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg:
                # 6 = len(0x45) + len(id) + len(seq_num) + len(lenbfill)
                return unpack_of_bfill(self.__scrambler.descramble(data[icmph.Length + 5:]))
            elif len(data) > icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg:
                length = struct.unpack_from('>B', icmph.other_bs, 1)[0]
                if length > 0:
                    # 576 - 340 = 236; 236 - 6 + 228 - 1 = 457 # 7 = len(0x45) + len(id) + len(seq_num) + len(lenbfill) + len(lenzfill)
                    lenzfill = struct.unpack_from('>B', data, icmph.Length + 5)[0]
                    size_data = length*4 + 20
                    if len(data) < icmph.Length + size_data + 340 or lenzfill > size_data:
                        return None
                    buf = bytearray(data[icmph.Length + 6: icmph.Length + size_data - lenzfill])
                    if size_data == 128:
                        return self.__scrambler.descramble(buf)[1:]
                    exth = icmpheader.ICMPExtHeader()
                    exth.read_bytes_from(data, icmph.Length + size_data)
                    if exth.version != 2:
                        return None
                    role = 0b00001111
                    pos_packet = icmph.Length + size_data + exth.Length
                    pos_buf = len(buf)
                    buf += bytearray(228)
                    for i in range(4):
                        extobjh = icmpheader.ICMPExtObjHeader()
                        extobjh.read_bytes_from(data, pos_packet)
                        if extobjh.cls_num != 2 or extobjh.cls_num != role or extobjh.len != extobjh.Length + 80:
                            return None
                        pos_packet += extobjh.Length

                        struct.pack_into('>4s', buf, pos_buf, data[pos_packet: pos_packet + 4])
                        pos_packet += 4
                        pos_buf += 4

                        extaddrh = icmpheader.ICMPIntIPAddrSubObjHeader()
                        extaddrh.read_bytes_from(data, pos_packet)
                        if extaddrh.afi != net_header.AFI_IPv4:
                            return None
                        pos_packet += extaddrh.Length
                        struct.pack_into('>4s', buf, pos_buf, data[pos_packet:pos_packet + 4])
                        pos_packet += 4
                        pos_buf += 4

                        len_str = struct.unpack_from('>B', data, pos_packet)[0]
                        if len_str < 61:
                            return None
                        pos_packet += 1
                        struct.pack_into('>45s', buf, pos_buf,
                                         base64.urlsafe_b64decode(data[pos_packet: pos_packet + 60]))
                        pos_packet += 63
                        pos_buf += 45

                        struct.pack_into('>4s', buf, pos_buf, data[pos_packet:pos_packet + 4])
                        pos_packet += 4
                        pos_buf += 4
                        role += 0b01000000
                    return unpack_of_bfill(self.__scrambler.descramble(buf))
                else:
                    # 5 = len(0x45) + len(id) + len(seq_num)
                    return self.__scrambler.descramble(data[icmph.Length + 5:])

        elif icmph.type == icmpheader.TYPE_v4Redirect:
            # 2 = len(0x45) + len(lenbfill)
            if len(data) != icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg:
                return None
            return unpack_of_bfill(self.__scrambler.descramble(data[icmph.Length + 1:]))

        elif icmph.type == icmpheader.TYPE_v4RouterAdvertisement:
            # 5 = len(lenbfill) + len(id) + len(seq_num)
            num_addrs, addr_entry_size = struct.unpack_from('>2B', icmph.other_bs)
            if addr_entry_size != 2 or len(data) < icmph.Length + num_addrs * 8:
                return None
            return unpack_of_bfill(self.__scrambler.descramble(data[icmph.Length + 4:]))

        elif icmph.type == icmpheader.TYPE_v4ParameterProblem:
            if len(data) == icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg:
                # 5 = len(0x45) + len(id(1)) + len(seq_num) + len(lenbfill)
                return unpack_of_bfill(self.__scrambler.descramble(data[icmph.Length + 4:]))
            elif len(data) > icmph.Length + MIN_DATA_SIZE_v4ICMPErrMsg:
                length = struct.unpack_from('>B', icmph.other_bs, 1)[0]
                if length > 0:
                    # 576 - 324 = 252; 252 - 6 + 212 = 458        # 6 = len(lenbfill) + len(seq_num) + len(id(1)) + len(0x45) + len(lenzfill)
                    lenzfill = struct.unpack_from('>B', data, icmph.Length + 4)[0]
                    size_data = length*4 + 20
                    if len(data) < icmph.Length + size_data + 324 or lenzfill > size_data:
                        return None
                    buf = bytearray(data[icmph.Length + 5: icmph.Length + size_data - lenzfill])
                    if size_data == 128:
                        return self.__scrambler.descramble(buf)[1:]
                    exth = icmpheader.ICMPExtHeader()
                    exth.read_bytes_from(data, icmph.Length + size_data)
                    if exth.version != 2:
                        return None
                    role = 0b00001110
                    pos_packet = icmph.Length + size_data + exth.Length
                    pos_buf = len(buf)
                    buf += bytearray(212)
                    for i in range(4):
                        extobjh = icmpheader.ICMPExtObjHeader()
                        extobjh.read_bytes_from(data, pos_packet)
                        if extobjh.cls_num != 2 or extobjh.cls_num != role or extobjh.len != extobjh.Length + 76:
                            return None
                        pos_packet += extobjh.Length

                        struct.pack_into('>4s', buf, pos_buf, data[pos_packet: pos_packet + 4])
                        pos_packet += 4
                        pos_buf += 4

                        extaddrh = icmpheader.ICMPIntIPAddrSubObjHeader()
                        extaddrh.read_bytes_from(data, pos_packet)
                        if extaddrh.afi != net_header.AFI_IPv4:
                            return None
                        pos_packet += extaddrh.Length
                        struct.pack_into('>4s', buf, pos_buf, data[pos_packet:pos_packet + 4])
                        pos_packet += 4
                        pos_buf += 4

                        len_str = struct.unpack_from('>B', data, pos_packet)[0]
                        if len_str < 61:
                            return None
                        pos_packet += 1
                        struct.pack_into('>45s', buf, pos_buf,
                                         base64.urlsafe_b64decode(data[pos_packet: pos_packet + 60]))
                        pos_packet += 63
                        pos_buf += 45
                        role += 0b01000000
                    return unpack_of_bfill(self.__scrambler.descramble(buf))
                else:
                    # 4 = len(0x45) + len(id(1)) + len(seq_num)
                    return self.__scrambler.descramble(data[icmph.Length + 4:])
        return None


    def id_seq_num_packet(self, data: bytes)-> tuple:
        """Define packet's id and seq_num.
            If icmp type was unknown or error has occurred
            return (-1,-1)"""
        icmph = icmpheader.ICMPHeader(hbytes=data)
        if icmph.type in (icmpheader.TYPE_v4AddressMaskRequest,icmpheader.TYPE_v4AddressMaskReply,
                          icmpheader.TYPE_v4TimestampRequest,icmpheader.TYPE_v4TimestampReply,
                          icmpheader.TYPE_v4EchoRequest, icmpheader.TYPE_v4EchoReply,
                          icmpheader.TYPE_v4Redirect):
            return icmpheader.icmpv4_id(icmph), icmpheader.icmpv4_seq_num(icmph)      # get value of  standart position
        elif icmph.type in (icmpheader.TYPE_v4SourceQuench, icmpheader.TYPE_v4DestinationUnreachable,
                            icmpheader.TYPE_v4TimeExceeded):
            if len(data) < icmph.Length + 5:
                return -1, -1
            return struct.unpack_from('>2H', data, icmph.Length + 1)        #get value, of datagram field; 1 = len(0x45)
        elif icmph.type == icmpheader.TYPE_v4ParameterProblem:
            if len(data) < icmph.Length + 4:
                return -1, -1
            hid = (icmpheader.icmpv4_id(icmph) & 0xff00) +\
                  struct.unpack_from('>B', data, icmph.Length + 1)[0]         # get id of Pointer and of datagram field
            return hid, struct.unpack_from('>H', data, icmph.Length + 2)[0]
        elif icmph.type == icmpheader.TYPE_v4RouterAdvertisement:
            if len(data) < icmph.Length + 4:
                return -1, -1
            return struct.unpack_from('>2H', data, icmph.Length)
        elif icmph.type == icmpheader.TYPE_v4ExtendedEchoRequest:
            hid, hseq = icmpheader.icmpv4_id(icmph), icmpheader.icmpv4_seq_num(icmph) & 0xff00
            min_size = icmph.Length
            if len(data) < min_size + icmpheader.ICMPExtHeader.Length + icmpheader.ICMPExtObjHeader.Length:
                return -1, -1
            exth = icmpheader.ICMPExtHeader()
            exth.read_bytes_from(data, min_size)                            # read extention header
            if exth.version != 2:
                return -1, -1
            min_size += exth.Length
            extobjh = icmpheader.ICMPExtObjHeader()               # read interface identification object header
            extobjh.read_bytes_from(data, min_size)
            if extobjh.cls_num != 3:
                return -1, -1
            min_size += extobjh.Length
            if extobjh.c_type == 3:
                min_size += icmpheader.ICMPIntIdObjAddrHeader.Length
                if len(data) < min_size + 1:
                    return -1, -1
                return hid, hseq + data[min_size: min_size + 1][0]    # get low byte seq_num of first octet address
            elif extobjh.c_type == 1:
                if len(data) < min_size + 64:
                    return -1, -1
                return hid, hseq + base64.urlsafe_b64decode(data[min_size:min_size + 64])[0]  # get low byte seq_num of first octet ifname
        return -1, -1
        
    def sendto(self, data: bytes, addr: str)-> int:
        if len(data) < 1 or len(data) > MAX_DATA_SIZE_v4ICMP - self.scrambler_coeffs()[0]:
            raise ValueError(f"Bad data size for sending!!! min size: 1 byte, max size: {MAX_DATA_SIZE_v4ICMP - self.scrambler_coeffs()[0]}")
        sent =  self.__socket.sendto(self.pack_data_in_packet(data), (addr, 0))
        self.__seq_num += 1
        return sent

    def recvfrom(self)-> tuple:
        self.__socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        try:
            while True:
                data, addr = self.__socket.recvfrom(65535)
                iph = ipv4header.IPv4Header(hbytes=data)
                data = data[iph.header_length * 4:]
                hid, hseqn = self.id_seq_num_packet(data)
                if self.__id == hid and self.__seq_num == hseqn:
                    data = self.unpack_data_of_packet(data)
                    if data is not None:
                        self.__seq_num += 1
                        break
        finally:
            self.__socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        return data, addr