# Calculation checksum by algorithm of rfc1071

def checksum_data(bs: bytes) -> int:
    vsum = 0
    data = iter(bs)
    count = len(bs)
    while count > 0:
        vsum += next(data) << 8
        count -= 1
        if count > 0:
            vsum += next(data)
            count -= 1

    while vsum >> 16:
        vsum = (vsum >> 16) + (vsum & 0xffff)
    return (~vsum) & 0xffff


def checksum(*args) -> int:
    vsum = 0
    count = 0                                       # count bytes
    for arg in args:
        if len(arg) == 0:
            continue
        data = iter(arg)                            # create bytes iterator
        if count:                                   # if last sequence bytes was odd
            vsum += next(data)
            count = len(arg) - 1
        else:
            count = len(arg)
        while count > 1:
            vsum += next(data) << 8
            vsum += next(data)
            count -= 2
        if count > 0:                               # if there is one more byte
            vsum += next(data) << 8

    while vsum >> 16:
        vsum = (vsum >> 16) + (vsum & 0xffff)
    return (~vsum) & 0xffff