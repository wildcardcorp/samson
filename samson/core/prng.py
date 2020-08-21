from samson.prngs.xorshift import Xorshift128Plus, Xorshift128, Xorshift116Plus
from samson.prngs.xoroshiro import Xoroshiro116Plus
from samson.prngs.mt19937 import MT19937
from samson.prngs.lcg import LCG
from samson.core.iterative_prng import IterativePRNG

_mt19937 = lambda state: MT19937(state)
_xor128p = lambda state: Xorshift128Plus(state)

_mtdict = {MT19937: _mt19937}
_xor128pdict = {Xorshift128Plus: _xor128p}

class PRNG(object):
    C          = {**_mtdict, LCG: lambda state: LCG(X=state, a=1103515245, c=12345, m=2**31)}
    CLOJURE    = {LCG: lambda state: LCG(X=state, a=0x5DEECE66D, c=0xB, m=2**48, trunc=16)}
    CPP        = C
    D          = _mtdict
    ERLANG     = {Xoroshiro116Plus: lambda state: Xoroshiro116Plus(state), Xorshift116Plus: lambda state: Xorshift116Plus(state)}
    ELIXIR     = ERLANG
    JAVASCRIPT = _xor128pdict
    JAVA       = CLOJURE
    JULIA      = _mtdict
    LUA        = _xor128pdict
    MATLAB     = _mtdict
    NODEJS     = _xor128pdict
    OCTAVE     = _mtdict
    PASCAL     = _mtdict
    PERL       = {LCG: lambda state: LCG(X=state, a=0x5DEECE66D, c=0xB, m=2**48)}
    PHP        = _mtdict
    PYTHON     = _mtdict
    R          = _mtdict
    RUBY       = _mtdict
    RUST       = {Xorshift128: lambda state: Xorshift128(state)}
    SCALA      = CLOJURE



    @staticmethod
    def auto_crack(outputs):
        # Do all the IterativePRNGs with their specific invocations
        for prng in IterativePRNG.__subclasses__():
            instance = prng([1]*prng.STATE_SIZE)
            try:
                yield instance.crack(outputs)
            except RuntimeError:
                pass

        lcgs = set([dic[LCG] for dic in [v for k,v in PRNG.__dict__.items() if type(v) is dict] if LCG in dic])
        for prng in [MT19937, *lcgs]:
            instance = prng(0)
            try:
                yield instance.crack(outputs)
            except Exception:
                pass
