from samson.utilities.runtime import RUNTIME
from samson.protocols.diffie_hellman import DiffieHellman
from samson.core.metadata import FrequencyType, EphemeralType, SizeType, UsageType
from samson.core.primitives import BlockCipher, BlockCipherMode, StreamingBlockCipherMode
from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle
from samson.analysis.integer_analysis import IntegerAnalysis
from itertools import groupby
from types import FunctionType

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

    def __init__(self, oracle: ChosenPlaintextOracle):
        self.oracle = oracle


    @RUNTIME.report
    def execute(self, initial_filter: FunctionType=BASIC_FILTER, min_input_len: int=1) -> Fingerprint:
        sample   = self.oracle.request(b'a'*min_input_len)
        base_len = len(sample)
        filtered = RUNTIME.search_primitives(initial_filter)

        io_rel_analysis  = self.oracle.test_io_relation(min_input_len)
        io_relation      = io_rel_analysis['io_relation']
        block_size       = io_rel_analysis['block_size']

        max_val_analysis = IntegerAnalysis.analyze(self.oracle.test_max_input())

        modifiers = {}
        if max_val_analysis.n != -1:
            if max_val_analysis.prime_name:
                log.debug(f'Max input size is a well-known modulus: {max_val_analysis.prime_name}')


            # Add modifiers for matching primitives
            if not max_val_analysis.is_prime and not max_val_analysis.byte_aligned and max_val_analysis.is_uniform:
                from samson.public_key.rsa import RSA
                modifiers[RSA] = 1

                log.debug('Max input size looks like RSA modulus')

            elif max_val_analysis.is_prime and max_val_analysis.is_uniform:
                from samson.protocols.dragonfly import Dragonfly
                from samson.public_key.elgamal import ElGamal

                # Process Diffie-Hellman-like primitives
                dh_modifier = 1 + max_val_analysis.is_safe_prime + bool(max_val_analysis.prime_name)

                modifiers[DiffieHellman] = dh_modifier
                modifiers[Dragonfly]     = dh_modifier
                modifiers[ElGamal]       = dh_modifier

                log.debug('Max input size looks like Diffie-Hellman modulus')


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

            log.debug('Block ciphers in candidates. Attempting to find possible block cipher modes')
            bc_modes = [prim for prim in filtered if issubclass(prim, BlockCipherMode) and not issubclass(prim, StreamingBlockCipherMode)]

            # Check for ECB
            if self.oracle.test_stateless_blocks(block_size):
                log.info('Stateless blocks detected')
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

        return Fingerprint(candidates=scored_matches, modes=bc_modes, max_input_analysis=max_val_analysis, io_relation=io_relation, block_size=block_size)
