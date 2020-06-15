import math
import decimal


def shenon_entropy(data: bytes, start=0, end=None) -> float:
    """ Calculate shenon's entropy for some data bytes"""
    if end is None:
        end = len(data)
    else:
        if end > len(data):
            raise ValueError(f"Uncorrect value end, end must be <= {len(data)}")
    entropy = 0
    length = end - start
    checked = []
    for i in range(start, end):
        if data[i] not in checked:
            p = 0
            for j in range(start, end):
                if data[i] == data[j]:
                    p += 1
            checked.append(data[i])
            p /= length
            entropy += p * math.log2(p)
    return -entropy

def factorial(n: int)-> int:
    p = 1
    for i in range(2, n + 1):
        p *= i
    return p

def dict_memoization(func):
    memory = {}
    def modify_func(n):
        val = memory.get(n)
        if val is None:
            val = func(n)
            memory[n] = val
        return val
    return modify_func

@dict_memoization
def eval4shenon_entropy_ecrypted_data(N: int)-> float:
    """
        calculate: evaluating the average sample entropy
        documenation: book "Detecting Subverted Cryptographic Protocols by Entropy Checking"
                      Jean Goubault-Larrecq and Julien Olivain Research, Report LSV-06-13 June 2006
    """
    assert N > 0, "Uncorrect size value!!!"
    decimal.getcontext().prec = 64
    c = decimal.Decimal(N / 256)                              # m = 256 for byte
    log10decimal2 = decimal.Decimal(2).log10()
    H = 8 + c.log10() / log10decimal2                         # log2(m) = 8
    s = 0
    for j in range(1, 415):
        log2j = decimal.Decimal(j).log10() / log10decimal2
        s += c**(j - 1) * log2j / decimal.Decimal(factorial(j - 1))
    H -= decimal.Decimal(-c).exp() * s
    return float(H)

def is_encrypted_data(data: bytes, **kwargs)-> bool:
    """ analysis entropy data and talk encrypted data or no!!!
        for correct result size data must be 32 <= size_data <= 65536!!!
        if size more or less false positives will occur
    """
    start = kwargs.get("start", 0)
    end = kwargs.get("end", len(data))
    eps = kwargs.get("eps", 0.5)
    if end > len(data) or start >= end:
        raise ValueError(f"Uncorrect end or start value!!!")

    entropy = shenon_entropy(data, start, end)                        # calculate shenon etropy
    eval_val = eval4shenon_entropy_ecrypted_data(end - start)         # calculate evaluating the average sample entropy
    dif = abs(entropy - eval_val)
    return dif < eps
