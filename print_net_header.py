def print_ipv4_header(**kwargs):
    iph = kwargs.get("ip_header")
    if iph:
        hversion = iph.version
        hlen = iph.header_length
        htos = iph.type_of_service
        htotal_len = iph.total_length
        hid = iph.id
        hdf = iph.dont_fragment
        hmfs = iph.more_fragments
        hoffset = iph.fragment_offset
        httl = iph.ttl
        hprotocol = iph.protocol
        hchecksum = iph.checksum
        hsrc_addr = iph.src_addr
        hdst_addr = iph.dst_addr
    else:
        hversion = kwargs.get("hversion", 0)
        hlen = kwargs.get("hlength", 0)
        htos = kwargs.get("htos", 0)
        htotal_len = kwargs.get("htotal_len", 0)
        hid = kwargs.get("hid", 0)
        hdf = kwargs.get("hdf", 0)
        hmfs = kwargs.get("hmfs", 0)
        hoffset = kwargs.get("hoffset", 0)
        httl = kwargs.get("httl", 0)
        hprotocol = kwargs.get("hprotocol", 0)
        hchecksum = kwargs.get("hchecksum", 0)
        hsrc_addr = kwargs.get("src_addr", "0.0.0.0")
        hdst_addr = kwargs.get("dst_addr", "0.0.0.0")
    print('+--------------------------------------------------------------+')
    print('|                           ipv4 header                        |')
    print('+-------+-------+---------------+------------------------------+')
    print(f'|{hversion:7}|' + f'{hlen:7}|' + f'{htos:15}|' + f'{htotal_len:30}|')
    print('+-------+-------+---------------+-+-+-+------------------------+')
    print(f'|{hex(hid):31}' + '|0' + f'|{hdf}' + f'|{hmfs}|'+ f'{hoffset:24}|')
    print('+---------------+---------------+-+-+-+------------------------+')
    print(f'|{httl:15}' + f'|{hprotocol:15}' + f'|{hex(hchecksum):30}|')
    print('+---------------+---------------+------------------------------+')
    print(f'|{hsrc_addr:62}|')
    print('+--------------------------------------------------------------+')
    print(f'|{hdst_addr:62}|')
    print('+--------------------------------------------------------------+')


def print_icmp_header(**kwargs):
    icmph = kwargs.get("icmp_header")
    if icmph:
        htype = icmph.type
        hcode = icmph.code
        hchecksum = icmph.checksum
        hother_bytes = icmph.other_bs
    else:
        htype = kwargs.get("htype", 0)
        hcode = kwargs.get("hcode", 0)
        hchecksum = kwargs.get('hchecksum', 0)
        hother_bytes = kwargs.get("hother_bytes", b'\x00\x00\x00\x00')
    print("+--------------------------------------------------------------+")
    print('|                          icmp header                         |')
    print('+---------------+---------------+------------------------------+')
    print(f'|{htype:15}' + f'|{hcode:15}' + f"|{hex(hchecksum):30}|")
    print('+---------------+----------------------------------------------+')
    print(f'|{hother_bytes.hex():62}|')
    print('+--------------------------------------------------------------+')