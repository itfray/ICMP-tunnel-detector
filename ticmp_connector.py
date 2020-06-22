import struct
import socket
import ipv4header
import icmpheader
import random
from rfc1071_checksum import checksum


# /* ================================================= Principles of building ICMP packets in the tunnel ===============================
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
#     +-----------------------------+-----------------------------+   -----
#     |                        random_bytes                       |     ^
#     |                                                           |     |
#     |                       (scrcoeff[0] bytes)                 |  28 bytes
#     +--------------+--------------------------------------------+     |
#     | len_bfill(1) |         0 < Data  <= 27 - scrcoeff[0]      |     v
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
#     |                       (scrcoeff[0] bytes)                 |  4 bytes
#     +--------------+--------------------------------------------+     |
#     | len_bfill(1) |        0 < Data  <= 3 - scrcoeff[0]        |     v
#     +--------------+--------------------------------------------+   -----
#    ========================================================================================================================== */


MAX_DATA_SIZE_v4ICMP = 65507
MIN_DATA_SIZE_v4ICMP = 1
MAX_DATA_SIZE_v4ICMPEcho = 65507
MAX_DATA_SIZE_v4ICMPDestUnreachable = 28
MAX_DATA_SIZE_v4ICMPParmeterProblem = 28
MAX_DATA_SIZE_v4ICMPTimeExceededMsg = 28
MAX_DATA_SIZE_v4ICMPTimestamp = 12
MAX_DATA_SIZE_v4ICMPSourceQuenchSize = 28
MAX_DATA_SIZE_v4ICMPRouterAdvertisement = 2040
MAX_DATA_SIZE_v4ICMPRedirect = 28
MAX_DATA_SIZE_v4ICMPAddrMask = 4


MAX_DATA_SIZE_v4TICMPEcho = MAX_DATA_SIZE_v4ICMPEcho

MAX_DATA_SIZE_v4TICMPDestUnreachable = MAX_DATA_SIZE_v4ICMPDestUnreachable - 6
# 6 == len(0x45) + len(id) + len(seq_n) + len(lenbfill)

MAX_DATA_SIZE_v4TICMPParmeterProblem = MAX_DATA_SIZE_v4ICMPParmeterProblem - 5
# 5 == len(0x45) + len(id) + len(seq_n) + len(lenbfill) - len(Pointer(id))

MAX_DATA_SIZE_v4TICMPTimeExceededMsg = MAX_DATA_SIZE_v4ICMPTimeExceededMsg - 6
# 6 == len(0x45) + len(id) + len(seq_n) + len(lenbfill)

MAX_DATA_SIZE_v4TICMPTimestamp = MAX_DATA_SIZE_v4ICMPTimestamp - 1
# 1 = len(lenbfill)

MAX_DATA_SIZE_v4TICMPSourceQuenchSize = MAX_DATA_SIZE_v4ICMPSourceQuenchSize - 6
# 6 == len(0x45) + len(id) + len(seq_n) + len(lenbfill)

MAX_DATA_SIZE_v4TICMPRouterAdvertisement = MAX_DATA_SIZE_v4ICMPRouterAdvertisement - 5
# 5 == len(id) + len(seq_n) + len(lenbfill)

MAX_DATA_SIZE_v4TICMPRedirect = MAX_DATA_SIZE_v4ICMPRedirect - 1
# 1 = len(lenbfill)

MAX_DATA_SIZE_v4TICMPAddrMask = MAX_DATA_SIZE_v4ICMPAddrMask - 1
# 1 = len(lenbfill)



class TICMPConnector:
    def __init__(self, **kwargs):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.__socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)                             # option for getting ip header
        listen_addr = kwargs.get("listen_addr", socket.gethostbyname_ex(socket.gethostname())[2][-1]) # get external host address
        self.__socket.bind((listen_addr, 0))                                                          # bind with address

        self.__scr_coeffs = kwargs.get("scr_coeffs")
        if self.__scr_coeffs:
            self.set_scrambler_coeffs(self.__scr_coeffs)
        else:
            self.__scr_coeffs = (1, 3, 5)

    def set_scrambler_coeffs(self, coeffs: tuple)-> None:
        if len(coeffs) == 0:
            raise ValueError("Bad size for scrambler coeffs!!!")
        self.__scr_coeffs = sorted(coeffs)

    def scrambler_coeffs(self)-> tuple:
        return self.__scr_coeffs

    def rand_icmp(self, size_data: int)-> tuple:
        icmph = icmpheader.ICMPHeader()
        r = 0
        if size_data < MAX_DATA_SIZE_v4TICMPAddrMask - self.__scr_coeffs[0]:
            r = random.randint(0, 8)
        elif size_data < MAX_DATA_SIZE_v4TICMPTimestamp - self.__scr_coeffs[0]:
            r = random.randint(0, 7)
        elif size_data < MAX_DATA_SIZE_v4TICMPDestUnreachable - self.__scr_coeffs[0]:
            r = random.randint(0, 6)
        elif size_data < MAX_DATA_SIZE_v4TICMPParmeterProblem - self.__scr_coeffs[0]:
            r = random.randint(0, 3)
        elif size_data < MAX_DATA_SIZE_v4TICMPRedirect - self.__scr_coeffs[0]:
            r = random.randint(0, 2)
        elif size_data < MAX_DATA_SIZE_v4TICMPRouterAdvertisement - self.__scr_coeffs[0]:
            r = random.randint(0, 1)

        if r == 1:
            pass
        elif r == 2:
            pass
        elif r == 3:
            pass
        elif r == 4:
            pass
        elif r == 5:
            pass
        elif r == 6:
            pass
        elif r == 7:
            pass
        elif r == 8:
            pass
        else:
            pass

    def sendto(self, data: bytes, addr)-> int:
        return 0