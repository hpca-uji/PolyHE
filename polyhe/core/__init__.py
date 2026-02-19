"""Structures package"""

from dataclasses import dataclass

import numpy as np


__all__ = (
    "Options",
)


# COEFF_MODULUS[security_level][poly_degree]
# source: sealapi.CoeffModulus.BFVDefault
COEFF_MODULUS = {
    128: {
        10: [27],
        11: [54],
        12: [36, 36, 37],
        13: [43, 43, 44, 44, 44],
        14: [48, 48, 48, 49, 49, 49, 49, 49, 49],
        15: [55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 56]
    },
    192: {
        10: [19],
        11: [37],
        12: [25, 25, 25],
        13: [38, 38, 38, 38],
        14: [50, 50, 50, 50, 50, 50],
        15: [54, 54, 54, 54, 54, 55, 55, 55, 55, 55, 55]
    },
    256: {
        10: [14],
        11: [29],
        12: [58],
        13: [39, 39, 40],
        14: [47, 47, 47, 48, 48],
        15: [52, 53, 53, 53, 53, 53, 53, 53, 53]
    }
}


@dataclass(slots=True, frozen=True)
class Descriptor:
    """Data descriptor"""
    type: type
    shape: tuple[int, ...]

    @property
    def numpy(self) -> bool:
        """Is numpy-like"""
        return issubclass(self.type, np.number)


@dataclass(slots=True, frozen=True)
class Options:
    """Encryption options"""
    slots: int = 13
    scale: int = 40
    security: int = 128


def numpy2python(scalar: np.number) -> type:
    """Transform numpy scalar to python scalar"""
    return type(scalar().tolist())  # type: ignore


def materialize(obj):
    """Generate description and array"""
    is_np = isinstance(obj, np.ndarray)
    obj = np.asarray(obj)
    type = obj.dtype.type
    if not is_np:
        type = numpy2python(type)  # type: ignore
    shape = obj.shape
    return Descriptor(type, shape), obj
