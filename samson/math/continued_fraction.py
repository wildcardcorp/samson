def _calc_continued_fraction(frac: 'FractionFieldElement') -> list:
    """
    Calculates the continued fraction form of `frac`.

    Parameters:
        frac (FractionFieldElement): Fraction.
    
    Returns:
        list: Continued fraction.
    """
    n, d = frac.numerator, frac.denominator
    cf   = []

    while True:
        q,r = divmod(n, d)
        cf.append(q)

        if not r:
            break

        n, d = d, r

    return cf


class ContinuedFraction(object):
    def __init__(self, element):
        self.element = element
        self.ring    = self.element.ring
        self.cf      = _calc_continued_fraction(self.element)


    def __repr__(self):
        return f'<ContinuedFraction: {self.cf}>'

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def from_list(cf):
        """
        Derives the fraction form for `cf`.

        Parameters:
            cf (list): Continued fraction.

        Returns:
            ContinuedFraction: Corresponding fraction.
        """
        w = self.ring(cf[0])

        if len(cf) > 1:
            w += ~eval_continued_fraction(cf[1:])
        return ContinuedFraction(w)



    def numerators(self) -> list:
        """
        Generates the numerators of the continued fraction.

        Returns:
            generator: Generator of the numerators.
        """
        last, two = self.ring.ring.one, self.ring.ring.zero

        for a in self.cf:
            h = a*last + two
            yield h
            last, two = h, last


    def denominators(self) -> list:
        """
        Generates the denominators of the continued fraction.

        Returns:
            generator: Generator of the denominators.
        """
        last, two = self.ring.ring.zero, self.ring.ring.one

        for a in self.cf:
            h = a*last + two
            yield h
            last, two = h, last


    def convergents(self):
        """
        Generates the convergents of the continued fraction.

        Returns:
            generator: Generator of the convergents.
        """
        return (self.ring((a,b)) for a,b in zip(self.numerators(), self.denominators()))
