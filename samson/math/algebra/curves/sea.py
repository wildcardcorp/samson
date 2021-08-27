from samson.auxiliary.atkin_modular_poly_db import AtkinDB
from samson.math.symbols import Symbol
from samson.math.general import frobenius_map, gcd
from samson.utilities.exceptions import NoSolutionException
from samson.math.dense_vector import DenseVector
from samson.math.algebra.rings.integer_ring import ZZ


db = AtkinDB()

def generate_elkies_modular_polynomials(E, l):
    x = Symbol('x')
    y = Symbol('y')

    R   = E.ring
    P   = R[x]
    Py  = R[y]
    j   = E.j_invariant()
    phi = db[l].change_ring(P)
    phi.symbol.repr = 'y'


    # Check if Atkin polynomial has roots
    phiJ = phi(y=j)
    rational_char = frobenius_map(x, phiJ)

    G = gcd(rational_char - x, phiJ)
    if not G.degree():
        raise NoSolutionException(f'{l} is not an Elkies prime for {E}')


    # Algorithm 1., page 27
    # 2: Let m = 18b/a, j′ = mj, and k = j′/(1827 − j).
    m   = 18 * E.b / E.a
    j_p = m * j
    k   = j_p/(1728-j)

    roots = G.roots()
    fE    = min(roots) 
    j_Phi = phi(x=fE)

    # Prepare all PHIs
    # 1: Compute Φx, Φxx, Φy, Φyy, Φxy.
    j_Phi_j = j_Phi.derivative()
    phi_j   = j_Phi_j(y=j)

    j_Phi_jj = j_Phi_j.derivative()
    Phi_jj   = j_Phi_jj(y=j)

    p_Phi    = phi.derivative(var=x)
    pj_Phi   = Py(list(p_Phi(x=fE)))

    pj_Phi_j = pj_Phi.derivative()
    Phi_fj   = pj_Phi_j(y=j)

    pf_Phi   = p_Phi(y=j)
    Phi_f    = pf_Phi(x=fE)
    Phi_ff   = pf_Phi.derivative()(x=fE)

    phi_jf = phi_j/Phi_f
    f_p    = -j_p*phi_jf

    Pyphi = Py(list(j_Phi))
    def lazy_roots(Pyphi):
        while True:
            facs  = Pyphi.factor(user_stop_func=lambda facs: any(f.degree() == 1 for f in facs))
            roots = Pyphi.ring.one
            for f in facs:
                if f.degree() == 1:
                    roots *= f
                    yield -f.monic()[0]

            if all(f.degree() > 1 for f in facs):
                break

            Pyphi //= roots

    for tj in lazy_roots(Pyphi):
        tPhi_j  = j_Phi_j(y=tj)
        tPhi_jj = j_Phi_jj(y=tj)

        tPhi_fj  = pj_Phi_j(y=tj)
        f_tPhi   = P(phi(y=tj))

        f_tPhi_f = f_tPhi.derivative()
        tPhi_f   = f_tPhi_f(x=fE)
        tPhi_ff  = f_tPhi_f.derivative()(x=fE)

        # Computation of polynomials is finished
        # 3: Let ȷ˜′ = −j′Φx/(ℓΦy), m˜ = ˜ȷ′/˜ȷ, and ˜k = ˜ȷ′/(1728 − ȷ˜)
        tj_p = j_p/l * phi_jf * tPhi_f / tPhi_j
        tm   = tj_p/tj
        tk   = tj_p/(1728-tj)

        # 4: Define a˜ = ℓ4m˜˜k/48 and b = ℓ6m˜2˜k/864
        ta = (R(l)**4)*tm*tk/48
        tb = (R(l)**6)*(tm**2)*tk/864

        # 5: Let r = −(j′2Φxx + 2ℓj′ȷ˜′Φxy + ℓ2ȷ˜′2Φyy)/(j′Φx)
        tr_f = -((f_p**2)*tPhi_ff+2*l*f_p*tj_p*tPhi_fj+(l**2)*(tj_p**2)*tPhi_jj)/(f_p*tPhi_f)
        r    = tr_f-(j_p*Phi_jj+2*f_p*Phi_fj+(f_p**2)*Phi_ff/j_p)/(phi_j)

        # 6: Define p1 = ℓ(r/2 + (k − ℓ˜k)/4 + (ℓm˜ − m)/3)
        p_1 = l*(r/2+(k-l*tk)/4+(l*tm-m)/3)

        # 7: Let d = (ℓ − 1)/2
        d = int((R(l)-1)/2)

        # 8: Let t0 = d, t1 = p1/2, t2 = ((1 − 10d)a − a˜)/30, and t3 = ((1 − 28d)b −42t1a − ˜b)/70
        t = DenseVector([d, p_1/2, ((1-10*d)*E.a-ta)/30, ((1-28*d)*E.b-42*p_1/2*E.a-tb)/70])

        # 9: Let c0 = 0, c1 = 6t2 + 2at0, c2 = 10t3 + 6at1 + 4bt0
        c = DenseVector([R(0), 6*t[2]+2*E.a*t[0], 10*t[3]+6*E.a*t[1]+4*E.b*t[0]])

        # Step 10-13
        for i in range(2, d):
            s      = c[:i+1][::-1].dot(c[:i+1])
            c[i+1] = (3*s-(2*i-1)*(i-1)*E.a*c[i-1]-(2*i-2)*(i-2)*E.b*c[i-2])/((i-1)*(2*i+5))

        # Step 14-16
        for i in range(3, d):
            t[i+1] = (c[i]-(4*i-2)*E.a*t[i-1]-(4*i-4)*E.b*t[i-2])/(4*i+2)


        # Step 17-21
        s    = [None]*(d+1)
        s[0] = R(1)

        for n in range(1, d+1):
            s[n] = R(0)
            c    = R(-1)

            for i in range(1 ,n+1):
                s[n] += c*t[i]*s[n-i]
                c = -c

            s[n] = s[n]*R(-1)/n


        c = 1
        for n in range(d+1):
            if c == 0:
                s[n] = -s[n]

            c = (c+1) % 2

        yield P(s[::-1])


def elkies_trace_mod_l(E: 'EllipticCurve', l: 'int') -> 'RingElement':
    """
    References:
        http://stankovicaleksa.net/Crypto_paper_Aleksa_Stankovic.pdf
        https://github.com/StankovicAleksa/SEA-SAGE/blob/master/sea/main.sage
    """
    x = Symbol('x')
    R = E.ring
    P = R[x]

    for g in generate_elkies_modular_polynomials(E, l):
        # Calculate division polynomials
        PQR   = P/g
        x_pqr = PQR(x)
        f     = PQR(E.defining_polynomial())
        div, div2, div02 = E._division_polynomials_mod(l, g)

        if div[l] == 0:
            # Frobenius
            x_p = x_pqr**E.p
            y_p = f**((E.p-1) // 2)
            lam = 0

            if x_p - x_pqr == 0:
                if y_p == 1:
                    lam = 1
                else:
                    lam = l-1
            else:
                f4 = f*4
                f8 = f4*2

                # Look for the point
                for i in range(2, (l-1) // 2 + 1):
                    xp_div  = x_p*div2[i]
                    xqr_div = x_pqr*div2[i]
                    xp_sub  = xp_div-xqr_div

                    if i % 2 == 0:
                        pol_xi = f4*xp_sub + div02[i-1]
                    else:
                        pol_xi = xp_sub + div02[i-1] * f4

                    # Found x, now we just need to know sign
                    if pol_xi == 0:
                        yp_div2 = y_p*div2[i]*div[i]
                        div12   = div[i+2]*div2[i-1]-div[i-2]*div2[i+1]

                        if i % 2 == 0:
                            pol_yi = f4*f8*yp_div2 - 2*div12
                        else:
                            pol_yi = f4 * (yp_div2 - div12)

                        if pol_yi == 0:
                            lam = i
                        else:
                            lam = l-i
                        break

            Z = ZZ/ZZ(l)
            return lam + Z(E.p)/lam
