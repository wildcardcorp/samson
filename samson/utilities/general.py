from types import FunctionType
import dill
import random
import ssl
import socket


def rand_bytes(size: int=16) -> bytes:
    """
    Reads bytes from RUNTIME.random.

    Parameters:
        size (int): Number of bytes to read.
    
    Returns:
        bytes: Random bytes.
    """
    from samson.utilities.runtime import RUNTIME
    return RUNTIME.random(size)



def shuffle(in_list: list) -> list:
    """
    Shuffles a list in place using random numbers generated from RUNTIME.random.

    Parameters:
        in_list (list): List to be shuffled.
    
    Returns:
        list: in_list shuffled in place.
    """
    random.shuffle(in_list, lambda: int.from_bytes(rand_bytes(32), 'big') / (2 ** 256))



def de_bruijn(k: list, n: int) -> str:
    """
    Generates a de Bruijn sequence for alphabet `k` and subsequences of length `n`.

    Parameters:
        k (list): Alphabet.
        n  (int): Subsequence length.
    
    Returns:
        str: de Bruijn sequence.
    """
    try:
        # let's see if k can be cast to an integer;
        # if so, make our alphabet a list
        _ = int(k)
        alphabet = list(map(str, range(k)))

    except (ValueError, TypeError):
        alphabet = k
        k = len(k)

    a = [0] * k * n
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return "".join(alphabet[i] for i in sequence)


def binary_search(func: FunctionType, max_int: int):
    """
    Performs binary search using `func` between 0 and `max_int`.
    `func` should return True if the argument is less than the hidden number.

    Parameters:
        func   (func): Function to compare the current value against the hidden value.
        max_int (int): Maximum integer to try.
    
    Returns:
        int: Index of hidden value.
    """
    start_idx = 0
    end_idx   = max_int

    while end_idx - 1 != start_idx:
        current = (end_idx + start_idx) // 2

        if func(current):
            start_idx = current
        else:
            end_idx = current

    return end_idx


def binary_search_unbounded(func: FunctionType):
    """
    Finds the upper bound and then performs binary search.

    Parameters:
        func (func): Function to compare the current value against the hidden value.
    
    Returns:
        int: Index of hidden value.
    """
    current = 1

    while True:
        if func(current):
            current *= 2
        else:
            return binary_search(func, current)


def binary_search_list(in_list: list, value: object, key: FunctionType=lambda item: item, fuzzy: bool=False) -> int:
    """
    Performs binary search for `value` on a sorted `in_list` with key selector `key`.

    Parameters:
        in_list (list): Sorted list to search.
        value (object): Value to search for.
        key     (func): Function that takes in an item and returns the key to search over.
    
    Returns:
        int: Index of value.
    """
    start_range = 0
    end_range   = len(in_list)

    if not end_range or value > key(in_list[-1]):
        if fuzzy:
            return end_range
        else:
            raise IndexError("Item not in list")


    if value < key(in_list[0]):
        if fuzzy:
            return start_range
        else:
            raise IndexError("Item not in list")

    curr     = -1
    fuzz_mod = 0
    while end_range - 1 != start_range:
        curr = (end_range - start_range) // 2 + start_range
        item = key(in_list[curr])

        if item == value:
            return curr
        elif item < value:
            start_range = curr
            fuzz_mod    = 1
        else:
            end_range = curr
            fuzz_mod  = 0

    # Special case since at zero, end_range - 1 == start_range
    if key(in_list[0]) == value:
        return 0

    if fuzzy:
        return curr + fuzz_mod
    else:
        raise IndexError("Item not in list")



def add_or_increment(dictionary: dict, key: object, value: int=1):
    """
    Adds the `value` to the `key` if the `key` is in the `dictionary`. Otherwise, it creates the entry
    and initializes it with `value`. Useful for counting observed values.

    Parameters:
        dictionary (dict): Dictionary to update.
        key      (object): Key to update.
        value       (int): Value to increment.
    """
    if key in dictionary:
        dictionary[key] += value
    else:
        dictionary[key] = value


def crc24(data: bytes) -> int:
    """
    Calculates the CRC-24 checksum of `data`

    Parameters:
        data (bytes): Data to be checksummed.
    
    Returns:
        int: Checksum.
    """
    crc  = 0xB704CE
    poly = 0x1864CFB

    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= poly

    return crc & 0xFFFFFF


def get_tls_cert(host: str, port: int, parse_cert: bool=True, timeout: int=5) -> bytes:
    """
    Gets a TLS cert from the server at `host`:`port`.

    Parameters:
        host      (tuple): Host to get certificate from.
        port        (int): Port to connect to.
        parse_cert (bool): Whether or not to automatically parse the certificate.
        timeout     (int): Timeout for the TCP connection.

    Returns:
        bytes/dict: Certificate (possibly decoded).
    """
    context = ssl._create_unverified_context()
    context.check_hostname = False

    conn = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(conn, server_hostname=host)

    try:
        cert = sock.getpeercert(binary_form=True)
    finally:
        sock.close()


    if parse_cert:
        from samson.encoding.general import PKIAutoParser
        cert = PKIAutoParser.import_key(cert)
    else:
        cert = ssl.DER_cert_to_PEM_cert(cert).encode('utf-8')

    return cert



def load(filepath: str):
    with open(filepath, 'rb') as f:
        return dill.load(f)

loads = dill.loads
