"""PolyHE test"""

from argparse import ArgumentParser, Namespace

import numpy as np

import polyhe


__all__ = ()


def main(config: Namespace) -> None:
    ctx = polyhe.new(config.backend)
    rel_tol = 1e-8
    abs_tol = 1e-8

    # Numbers
    p1 = 1
    p2 = -1
    c1 = ctx.encrypt(p1)
    c2 = ctx.encrypt(p2)
    c3 = c1 * c2 + p1
    p3 = ctx.decrypt(c3)
    ref = 0
    assert np.isclose(p3, ref, rel_tol, abs_tol).all(), f"numbers error; got {p3}, expect {ref}"

    # Lists
    p1 = [0.3, 0.4]
    p2 = [0.4, 0.3]
    c1 = ctx.encrypt(p1)
    c2 = ctx.encrypt(p2)
    c3 = -c1 + c2
    p3 = ctx.decrypt(c3)
    ref = [0.1, -0.1]
    assert np.isclose(p3, ref, rel_tol, abs_tol).all(), f"lists error; got {p3}, expect {ref}"

    # NumPy
    p1 = np.full((2, 3, 4), 0.4, np.float64)
    p2 = np.full((2, 3, 4), 0.3, np.float64)
    c1 = ctx.encrypt(p1)
    c2 = ctx.encrypt(p2)
    c3 = c1 - c2
    p3 = ctx.decrypt(c3)
    ref = np.full((2, 3, 4), 0.1, np.float64)
    assert np.isclose(p3, ref, rel_tol, abs_tol).all(), f"numpy error; got {p3}, expect {ref}"


if __name__ == "__main__":
    parser = ArgumentParser(prog="polyhe-test", description="PolyHE test")
    parser.add_argument("backend", choices=list(polyhe.Backend), help="Operational backend")
    main(parser.parse_args())
