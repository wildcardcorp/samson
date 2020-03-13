from samson.utilities.runtime import RUNTIME
from samson.utilities.exceptions import OracleException
from samson.utilities.bytes import Bytes
from samson.utilities.analysis import count_items
from samson.math.general import kth_root, is_prime
from samson.protocols.diffie_hellman import DiffieHellman
from samson.core.metadata import IORelationType, FrequencyType, EphemeralType, SizeType, UsageType
from samson.core.primitives import BlockCipher, BlockCipherMode, StreamingBlockCipherMode
from itertools import groupby
import math

import logging
log = logging.getLogger(__name__)

WELL_KNOWN_GROUPS = {
    DiffieHellman.MODP_1536: 'MODP_1536',
    DiffieHellman.MODP_2048: 'MODP_2048',
    DiffieHellman.MODP_3072: 'MODP_3072',
    DiffieHellman.MODP_4096: 'MODP_4096',
    DiffieHellman.MODP_6144: 'MODP_6144',
    DiffieHellman.MODP_8192: 'MODP_8192'
}


class Fingerprint(object):
    def __init__(self, candidates, modes, max_input_analysis, io_relation, block_size):
        self.candidates = candidates
        self.modes  = modes
        self.max_input_analysis = max_input_analysis
        self.io_relation = io_relation
        self.block_size  = block_size


    def __repr__(self):
        return f"<Fingerprint: io_relation={self.io_relation}, block_size={self.block_size}, candidates={self.candidates}, modes={self.modes}, max_input_analysis={self.max_input_analysis}>"

    def __str__(self):
        return self.__repr__()


    def group_candidates(self) -> list:
        """
        Sorts and groups candidates by their score.

        Returns:
            list: List of candidate groups with the highest scoring first.
        """
        sorted_candidates = sorted(self.candidates.items(), key=lambda item: item[1], reverse=True)

        groups = []
        for _score, g in groupby(sorted_candidates, key=lambda item: item[1]):
            groups.append(list(g))

        return groups



class Fingerprinter(object):
    NOOP_FILTER  = lambda prim: True
    BASIC_FILTER = lambda prim: prim.USAGE_FREQUENCY != FrequencyType.NEGLIGIBLE and prim.USAGE_TYPE == UsageType.GENERAL

    def __init__(self, oracle: object):
        self.oracle = oracle


    @RUNTIME.report
    def execute(self, initial_filter=BASIC_FILTER, min_input_len: int=1) -> Fingerprint:
        sample   = self.oracle.request(b'a'*min_input_len)
        base_len = len(sample)
        filtered = RUNTIME.search_primitives(initial_filter)
        new_len  = base_len

        # TODO: How should I handle ECBCTS/CBCCTS?
        # 1) Has minimum input size (depending on implementation)
        # 2) Might be conditional stealing (^^)
        # 3) Has blocks, but increments like a stream cipher


        # Find block size and output size
        i       = min_input_len + 1
        io_diff = []
        log.debug(f'Starting block size/output size testing')
        while base_len == new_len and i < 64:
            sample  = self.oracle.request(b'a'*i)
            new_len = len(sample)
            io_diff.append(new_len - base_len)
            i += 1


        # Determine IO relation
        if any(io_diff):
            io_relation = IORelationType.EQUAL
        else:
            io_relation = IORelationType.FIXED


        block_size = (new_len - base_len) or base_len
        log.info(f'IORelation: {io_relation.name}')
        log.info(f'Block size: {block_size*8}')

        # See if there's a max size
        MAX_TEST_INPUT =  2**16384
        start_idx      =  0
        end_idx        = MAX_TEST_INPUT


        # Use MAX_TEST_INPUT as a canary. If the primitive will take MAX_TEST_INPUT, then
        # it's most likely going to take anything. Only run this test if we know the primitive
        # has a fixed output size (e.g. hashes and number-theoretical crypto).
        should_test_max = False

        if io_relation == IORelationType.FIXED:
            while True:
                try:
                    self.oracle.request(Bytes(MAX_TEST_INPUT))
                    log.debug(f'Oracle seems to take in arbitrary-sized inputs')
                    break

                except OracleException:
                    should_test_max = True
                    end_idx = MAX_TEST_INPUT
                    break

                except ValueError:
                    MAX_TEST_INPUT = kth_root(MAX_TEST_INPUT, 2)
                    log.warning(f'Oracle returned ValueError. Reducing MAX_TEST_INPUT to 2^{int(math.log(MAX_TEST_INPUT, 2))}')


        # Use binary search to find max input size. This is both the most efficient method of finding
        # the max size and the most precise. For example, if the primitive is RSA and rejects inputs
        # larger than its modulus, then "end_idx" will be the modulus.
        max_val   = {'value': -1, 'is_prime': None, 'uniform_distribution': None, 'byte_aligned': None, 'is_safe_prime': None, 'is_well_known': None}
        modifiers = {}

        if should_test_max:
            log.debug(f'Starting max input testing')

            while end_idx - 1 != start_idx:
                current = (end_idx + start_idx) // 2

                try:
                    self.oracle.request(Bytes(current))
                    start_idx = current

                except OracleException:
                    end_idx = current

            max_val['value'] = end_idx
            log.info(f'Max input size: {round(math.log(end_idx, 2), 1)} bits')


            # Check some basic properties of "max_val"
            # This might be a number theoretical primitive
            max_is_prime = is_prime(end_idx)
            byte_aligned = not end_idx % 8

            q, r = divmod(end_idx-1, 2)
            is_safe_prime = not r and is_prime(q) and max_is_prime
            is_well_known = end_idx in WELL_KNOWN_GROUPS


            # Determine bit distribution
            bits = bin(end_idx)[2:]
            bit_distribution = count_items(bits)
            percent_one = bit_distribution['1'] / len(bits)

            uniform_dist = abs(0.50 - percent_one) < 0.05

            max_val['uniform_distribution'] = uniform_dist
            max_val['byte_aligned'] = byte_aligned
            max_val['is_prime'] = max_is_prime
            max_val['is_safe_prime'] = is_safe_prime
            max_val['is_well_known'] = is_well_known

            if is_well_known:
                log.debug(f'Max input size is a well-known modulus: {WELL_KNOWN_GROUPS[end_idx]}')


            # Add modifiers for matching primitives
            if not max_is_prime and not byte_aligned and uniform_dist:
                from samson.public_key.rsa import RSA
                modifiers[RSA] = 1

                log.debug(f'Max input size looks like RSA modulus')

            elif max_is_prime and uniform_dist:
                from samson.protocols.dragonfly import Dragonfly
                from samson.public_key.elgamal import ElGamal

                # Process Diffie-Hellman-like primitives
                dh_modifier = 1 + is_safe_prime + is_well_known

                modifiers[DiffieHellman] = dh_modifier
                modifiers[Dragonfly]     = dh_modifier
                modifiers[ElGamal]       = dh_modifier

                log.debug(f'Max input size looks like Diffie-Hellman modulus')

        else:
            log.debug(f'Skipping max input testing')


        matching = [match for match in filtered if block_size*8 in match.BLOCK_SIZE and match.IO_RELATION_TYPE == io_relation]
        bc_modes = []


        # Punish IV/nonce/AEAD primitives if we can prove the output doesn't contain their ephemeral/tag
        # This is only really possible if the output is smaller than their ephemeral/tag

        def calculate_min_size(size):
            min_size     = 0
            typical_size = 0
    
            sizes = size.sizes
            if type(sizes) is int:
                min_size     += sizes
                typical_size += sizes

            else:
                if size.size_type not in [SizeType.ARBITRARY, SizeType.DEPENDENT]:
                    min_size += sizes[0]

                if size.typical:
                    typical_size += size.typical[0]

            return min_size, typical_size


        # If the primitive is a block cipher mode and its ephemeral/tag is DEPENDENT, we'll want to check
        # against known block ciphers.
        block_ciphers = [prim for prim in filtered if issubclass(prim, BlockCipher) and block_size*8 in prim.BLOCK_SIZE]
        minimum_bc    = min([calculate_min_size(block_cipher.BLOCK_SIZE)[0] for block_cipher in block_ciphers]) if block_ciphers else 0

        for match in matching:
            min_size     = 0
            typical_size = 0
            all_sizes    = []


            if hasattr(match, 'EPHEMERAL') and not match.EPHEMERAL.ephemeral_type == EphemeralType.KEY:
                all_sizes.append(match.EPHEMERAL.size)

            if hasattr(match, 'AUTH_TAG_SIZE'):
                all_sizes.append(match.AUTH_TAG_SIZE)


            for size in all_sizes:
                component_min, component_typical = calculate_min_size(size)
                min_size     += component_min
                typical_size += component_typical

                if issubclass(match, BlockCipherMode) and size.size_type == SizeType.DEPENDENT:
                    min_size += minimum_bc


            for size in [min_size, typical_size]:
                if base_len*8 < size:
                    if not match in modifiers:
                        modifiers[match] = 0

                    modifiers[match] -= 1


        # Find possible block cipher modes. We exclude StreamingBlockCipherModes because they're handled
        # by their block size above.
        if any([issubclass(match, BlockCipher) for match in matching]):
            from samson.block_ciphers.modes.ecb import ECB

            log.debug(f'Block ciphers in candidates. Attempting to find possible block cipher modes')
            bc_modes = [prim for prim in filtered if issubclass(prim, BlockCipherMode) and not issubclass(prim, StreamingBlockCipherMode)]
            blocks   = Bytes.wrap(self.oracle.request(b'a'*block_size*4)).chunk(block_size)

            # Check for ECB
            if len(set([bytes(block) for block in blocks])) < 4:
                log.info(f'Stateless blocks detected')
                bc_modes = [ECB]

            else:
                if ECB in bc_modes:
                    bc_modes.remove(ECB)



        # Score matches higher if they're more explicit
        scored_matches = {}

        for match in matching:
            bitsize   = block_size*8
            base_freq = match.USAGE_FREQUENCY.value + (modifiers[match] if match in modifiers else 0)
            scored_matches[match] = base_freq

            # If it matches a SINGLE value, that's significant
            if bitsize == match.BLOCK_SIZE.sizes:
                scored_matches[match] += FrequencyType.PROLIFIC.value

            # If it's in a RANGE, it's a bit less significant
            elif bitsize in match.BLOCK_SIZE.sizes:
                scored_matches[match] += FrequencyType.NORMAL.value


            # Add a modifier for being in 'typical'
            if bitsize in match.BLOCK_SIZE.typical:
                scored_matches[match] += 1

        return Fingerprint(candidates=scored_matches, modes=bc_modes, max_input_analysis=max_val, io_relation=io_relation, block_size=block_size)
