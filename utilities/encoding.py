

# https://en.wikipedia.org/wiki/Non-adjacent_form
# Takes in bytes/bytearray or int
def to_NAF(input_arg):
    if type(input_arg) is int:
        E = input_arg
    else:
        E = int.from_bytes(input_arg, 'big')
    #bitstring = byte_to_bitstring(byte_arr)
    
    z = []
    
    i = 0
    while E > 0:
        if E % 2 == 1:
            z.append(int(2 - (E % 4)))
            E -= z[-1]
        else:
            z.append(0)
        
        E /= 2
        i += 1
    return z[::-1]


def from_NAF(naf):
    total = 0
    reversed_naf = naf[::-1]
    for i in range(len(naf)):
        total += 2 ** i * reversed_naf[i]
    
    return total




def int_to_bytes(n, byteorder='little'):
    """Converts the given int n to bytes and returns them."""
    return n.to_bytes(max((n.bit_length() + 7) // 8, 1), byteorder)



def byte_to_bitstring(input_bytes, fill=8):
    return ''.join(format(x, 'b').zfill(fill) for x in input_bytes)

