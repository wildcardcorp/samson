from samson.prngs.xorshift import Xorshift32, Xorshift64, Xorshift128Plus, Xorshift128, Xorshift116Plus, Xorshift1024Star
from samson.prngs.xoroshiro import Xoroshiro116Plus, Xoroshiro128Plus
from samson.prngs.xoshiro import Xoshiro128PlusPlus, Xoshiro256PlusPlus
from samson.prngs.mt19937 import MT19937
from samson.prngs.mwc1616 import MWC, MWC1616
from samson.prngs.lcg import LCG
from samson.prngs.lfg import LFG
from samson.core.metadata import CrackingDifficulty
from samson.utilities.exceptions import NoSolutionException
from samson.utilities.bytes import Bytes

from functools import partial

import logging
log = logging.getLogger(__name__)

def _generic_constructor(prng_type):
    return lambda state: prng_type(state)

_mt19937 = _generic_constructor(MT19937)
_xor128p = _generic_constructor(Xorshift128Plus)

_mtdict = {MT19937: _mt19937}

_generic = {prng_type: _generic_constructor(prng_type) for prng_type in [Xorshift32, Xorshift64, Xoroshiro128Plus, Xorshift1024Star]}

class PRNG(object):
    C           = {**_mtdict, LCG: lambda state: LCG(X=state, a=1103515245, c=12345, m=2**31)}
    C_MICROSOFT = {LCG: lambda state: LCG(X=state, a=214013, c=2531011, m=2**31, trunc=16)}
    CLOJURE     = {LCG: lambda state: LCG(X=state, a=0x5DEECE66D, c=0xB, m=2**48, trunc=16)}
    CPP         = C
    CPP_MICROSOFT = C_MICROSOFT
    CPP_MINSTD  = {LCG: lambda state: LCG(X=state, a=48271, c=0, m=2**31-1)}
    CPP_MINSTD0 = {LCG: lambda state: LCG(X=state, a=16807, c=0, m=2**31-1)}
    C_SHARP     = {LFG: lambda state: LFG(state=state, feed=0, tap=21, operation=LFG.SUB_OP, mask_op=LFG.C_SHARP_MASK_OP, length=55, increment=True)}
    D           = _mtdict
    DART        = {MWC: lambda state: MWC(seed=state, a=0xFFFFDA61), Xorshift128Plus: _xor128p}
    DELPHI      = {LCG: lambda state: LCG(X=state, a=134775813, c=1, m=2**32)}
    ERLANG      = {Xoroshiro116Plus: _generic_constructor(Xoroshiro116Plus), Xorshift116Plus: _generic_constructor(Xorshift116Plus)}
    ELIXIR      = ERLANG
    F_SHARP     = C_SHARP
    GO          = {LFG: lambda state: LFG(state, feed=334, tap=0, mask_op=LFG.GEN_MASK_OP(2**64-1), operation=LFG.ADD_OP, increment=False, length=607)}
    GROOVY      = CLOJURE
    JAVASCRIPT  = {Xorshift128Plus: _xor128p, MWC1616: _generic_constructor(MWC1616)}
    JAVA        = CLOJURE
    JULIA       = _mtdict
    KOTLIN      = CLOJURE
    LUA         = {Xorshift128Plus: _xor128p}
    MATLAB      = _mtdict
    NODEJS      = JAVASCRIPT
    OCTAVE      = _mtdict
    PASCAL      = _mtdict
    PERL        = {LCG: lambda state: LCG(X=state, a=0x5DEECE66D, c=0xB, m=2**48)}
    PHP         = _mtdict
    POSIX_48    = PERL
    POWERSHELL  = C_SHARP
    PYTHON      = _mtdict
    R           = _mtdict
    RUBY        = _mtdict
    RUST        = {Xorshift128: _generic_constructor(Xorshift128), Xoshiro128PlusPlus: _generic_constructor(Xoshiro128PlusPlus), Xoshiro256PlusPlus: _generic_constructor(Xoshiro256PlusPlus)}
    SCALA       = CLOJURE
    VB_NET      = C_SHARP
    VB6         = {LCG: lambda state: LCG(X=state, a=0x43FD43FD, c=0xC39EC3, m=2**24)}


    @staticmethod
    def __auto_crack_iter(outputs, max_diificulty):
        inv_map = {}
        lcgs = []
        for k,v in PRNG.__dict__.items():
            if type(v) is dict:
                for _prng_type, prng_constructor in v.items():
                    if prng_constructor not in inv_map:
                        inv_map[prng_constructor] = []
                        if LCG in v:
                            lcgs.append(v[LCG])

                    inv_map[prng_constructor].append(k)


        # Add in generic PRNGS just in case
        for k,v in _generic.items():
            if v not in inv_map:
                inv_map[v] = []

            inv_map[v].append('GENERIC')  


        def try_insta(prng):
            try:
                return prng(0)
            except TypeError:
                return prng([])


        def true_state_size(prng):
            instance = try_insta(prng)
            return not hasattr(instance, 'NATIVE_BITS') or int(instance.NATIVE_BITS)*int(instance.STATE_SIZE)


        max_bit_size = max(o.bit_length() for o in outputs)

        for prng in sorted(inv_map, key=lambda prng: true_state_size(prng)):
            instance = try_insta(prng)

            if instance.CRACKING_DIFFICULTY.value > max_diificulty.value:
                continue

            # Make sure the values are actually the right size
            # If the PRNG's output size is bigger than the `max_bit_size`,
            # we still want to allow some leeway. If there are three outputs
            # and none of them are within 15 bits of the expected size,
            # thats a 2^-45 chance it's valid (1 in 35 trillion).
            if instance.OUTPUT_SIZE < max_bit_size or abs(int(instance.OUTPUT_SIZE) - max_bit_size) > 15:
                continue

            # Use extra samples for greater accuracy
            if instance.REQUIRED_SAMPLES:
                if int(instance.REQUIRED_SAMPLES) > len(outputs):
                    log.warning(f'Not enough samples for {type(instance).__name__}; skipping')
                    continue

                num_test_samples = len(outputs)-int(instance.REQUIRED_SAMPLES)
            else:
                num_test_samples = 0


            # Actually run the crack
            log.info(f'{type(instance).__name__} {inv_map[prng]}')
            try:
                test_samples  = outputs[-num_test_samples:]
                input_samples = outputs[:(-num_test_samples) or len(outputs)]
                cracked       = instance.crack(input_samples)

                if all([cracked.generate() == test for _, test in zip(range(num_test_samples), test_samples)]):
                    yield cracked

            except Exception:
                pass



    @staticmethod
    def auto_crack(outputs, stop_on_first: bool=True, max_diificulty: CrackingDifficulty=CrackingDifficulty.NORMAL):
        results = PRNG.__auto_crack_iter(outputs, max_diificulty)
        if stop_on_first:
            try:
                results = results.__next__()
            except StopIteration:
                raise NoSolutionException('Outputs do not satisfy any registered PRNG')
        return results


    @staticmethod
    def auto_crack_bytes(outputs: bytes, stop_on_first: bool=True, max_diificulty: CrackingDifficulty=CrackingDifficulty.NORMAL):
        import itertools

        all_results = []
        func        = partial(PRNG.auto_crack, stop_on_first=stop_on_first, max_diificulty=max_diificulty)

        def eat_no_sol(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except NoSolutionException:
                return []


        for state_size in (4, 8, 3):
            if len(outputs) % state_size:
                continue

            log.info(f'Testing state size {state_size*8}')

            chunks  = Bytes.wrap(outputs).chunk(state_size)
            results = eat_no_sol(outputs=[c.int() for c in chunks])

            if stop_on_first:
                if not results:
                    results = eat_no_sol(outputs=[c[::-1].int() for c in chunks])
            else:
                results = list(itertools.chain(results, eat_no_sol(outputs=[c[::-1].int() for c in chunks])))

            if stop_on_first and results:
                return results
            
            all_results.extend(results)
        
        return all_results
