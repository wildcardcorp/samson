"""
This script finds smooth curves given parameters `a` and `p`.
It then generates a 'plan' for an invalid curve attack to minimize
the number of interactions.
"""

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable

import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def trial_factor(n, bound=2^16):
    curr = n
    facs = []
    while True:
        fac = trial_division(curr, bound)
        curr //= fac
        if is_prime(fac):
            facs.append(fac)

        if curr == 1:
            break
        
    
    return facs


def count_items(items: list) -> dict:
    """
    Counts the items in an enumerable object.

    Parameters:
        items (list): Enumerable of items.
    
    Returns:
        dict: Dictionary of {item, count}.
    """
    item_ctr = {curr_item: 0 for curr_item in items}

    for curr_item in items:
        item_ctr[curr_item] += 1

    return item_ctr


def generate_plan(a, p, search_range, banned_curves=None, banned_factors=None):
    R              = ZZ.quo(p)
    inv_curves     = []
    Ra             = R(a)
    banned_curves  = banned_curves or []
    banned_factors = banned_factors or []

    # Generate a bunch of curves
    @parallel
    def process_curve(b):
        try:
            b_inv = R(b)
            e_inv = EllipticCurve([Ra, b_inv])
            return b, count_items(trial_factor(e_inv.order())), int(e_inv.order())
        except (TypeError, ArithmeticError):
            return

    inv_curves = [result[1] for result in tqdm(process_curve(search_range), total=len(search_range)) if result[1] is not None]

    plan = [[(b_inv, fac, e) for fac, e in facs.items()] for b_inv, facs, _order in inv_curves if b_inv not in banned_curves]
    plan = [item for sublist in plan for item in sublist]
    plan = sorted(plan, key=lambda item: item[1])

    # Find curves with best exponents for every factor
    plan_b = {}
    for b,f,e in plan:
        if f in banned_factors:
            continue

        if f not in plan_b:
            plan_b[f] = (b, e)
            continue
        
        if plan_b[f][1] < e:
            plan_b[f] = (b, e)


    # Select the smallest factors
    total  = 1
    plan_c = []
    for f, (b, e) in plan_b.items():
        total *= f^e
        plan_c.append((b, f, e))
        if total > p^2:
            break

    if total < p:
        print('CRITICAL: "total" does not exceed "p"')
    elif total < p^2:
        print('WARNING: "total" does not meet the p^2 threshold!')
    

    bs = [b for b,f,e in plan_c]
    return plan_c, {b:order for b, _, order in inv_curves if b in bs}, sum([((f+1)//2)*e for b,f,e in plan_c])


if __name__ == '__main__':
    a, p, start, end = [int(arg) for arg in sys.argv[1:]]
    plan, orders, efficiency = generate_plan(ZZ(a), ZZ(p), list(range(start, end)), banned_curves=[6886], banned_factors=[2])
    print(f'Plan:\n{plan}\n')
    print(f'Curve orders:\n{orders}\n')
    print(f'Avg number of requests: {efficiency}')
