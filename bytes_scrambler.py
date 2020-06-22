import random

def min_index(arr: list)-> int:
    if len(arr) == 0:
        raise ValueError("Error calculating minimum empty list!!!")
    min_ind = 0
    min_val = arr[min_ind]
    for i in range(len(arr)):
        if min_val > arr[i]:
            min_val = arr[i]
            min_ind = i
    return min_ind


#       /* in functions scramblers:
#            * source - pointer on current byte sequence;
#            * destination - pointer on output encrypted byte sequence;
#            * coeffs - indices elements for scrambling,
#            * example:
#            *    coeffs = {3, 5, 7},
#            *    then equation for scrambling B[i] = A[i] xor B[i - 3] xor B[i - 5] xor B[i - 7],
#            *    where A - current byte sequence, B - encrypted byte sequence
#            * coeffs must be sorted ascending;
#            * destination length depends on the first element in coeffs,
#            * if source_size = 10 and coeffs[0] = 3 then destination_size must be 13
#
#        in functions descramblers:
#            * destination - pointer on decrypted byte sequence;
#            * source - pointer on input encrypted byte sequence;
#            * coeffs - indices elements for descrambling,
#            * example:
#            *    coeffs = {2, 6},
#            *    then equation for scrambling C[i] = B[i] xor B[i - 2] xor B[i - 6],
#            *    where C - decrypted byte sequence, B - encrypted byte sequence
#            * coeffs must be equal coeffs for function scrambling;
#            * destination length depends on the first element in coeffs,
#            * if source_size = 13 and coeffs[0] = 3 then destination_size must be 10
#        */


def scramble(bsrc: bytes, coeffs = (1, 3, 5))-> bytearray:
    if len(coeffs) == 0:
        raise ValueError("Uncorrect scramble coefficients!!!")
    bdst = bytearray(coeffs[0] + len(bsrc))                    # create buffer for answer
    for i in range(coeffs[0]):
        bdst[i] = random.randint(0, 255)                       # generate rand bytes
    di = coeffs[0]                                             # index var for bdst buffer
    for i in range(len(bsrc)):
        bdst[di] = bsrc[i]
        for coeff in coeffs:                                   # apply all cofficients
            if di >= coeff:
                bdst[di] ^= bdst[di - coeff]
        di += 1
    return bdst                                                # return scrambling buffer


def descramble(bsrc: bytes, coeffs = (1, 3, 5))-> bytearray:
    if len(coeffs) == 0:
        raise ValueError("Uncorrect descramble coefficients!!!")
    bdst = bytearray(len(bsrc) - coeffs[0])
    for i in range(len(bdst)):
        bdst[i] = bsrc[i + coeffs[0]]
        bdst[i] ^= bsrc[i]
        for j in range(1, len(coeffs)):
            sub = coeffs[j] - coeffs[0]
            if i >= sub:
                bdst[i] ^= bsrc[i - sub]
    return bdst


def scramble_many(coeffs: tuple, *args)-> bytearray:
    if len(coeffs) == 0:
        raise ValueError("Uncorrect scramble coefficients!!!")
    size = 0
    for arg in args:
        size += len(arg)
    bdst = bytearray(coeffs[0] + size)
    for i in range(coeffs[0]):
        bdst[i] = random.randint(0, 255)
    dst_ind = coeffs[0]
    for arg in args:
        if len(arg) == 0:
            continue
        for i in range(len(arg)):
            bdst[dst_ind] = arg[i]
            for coeff in coeffs:                            # apply all coeffs
                if dst_ind >= coeff:
                    bdst[dst_ind] ^= bdst[dst_ind - coeff]
            dst_ind += 1
    return bdst


class Scrambler:
    def __init__(self, scr_coeffs = [1, 3, 5]):
        self.set_coeffs(scr_coeffs)

    def scramble(self, *args)-> bytearray:
        return scramble_many(self.__scr_coeffs, *args)

    def descramble(self, bdata: bytes)-> bytearray:
        return descramble(bdata, self.__scr_coeffs)

    def set_coeffs(self, coeffs: list)-> None:
        if len(coeffs) == 0:
            raise ValueError("Bad size for scrambler coeffs!!!")
        if 0 in coeffs:
            raise ValueError("Value scrambler coefficient must be more than zero!!!")
        min_ind = min_index(coeffs)
        coeffs[min_ind], coeffs[0] = coeffs[0], coeffs[min_ind]
        self.__scr_coeffs = tuple(coeffs)

    def coeffs(self)-> tuple:
        return self.__scr_coeffs