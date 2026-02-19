"""Context package"""

import copy
import math
import typing
import itertools
from abc import ABC, abstractmethod
from collections.abc import Iterable
from functools import cached_property

import numpy as np

from polyhe.core.ciphertext import Ciphertext
from polyhe.core import COEFF_MODULUS, Options, materialize


__all__ = (
    "Context",
)


class Context(ABC):
    """Abstract context"""
    _cls: type[Ciphertext]

    def __init__(self, options: Options = Options()) -> None:
        """Initialize context"""
        self.options = options

    @property
    def _slots_exp(self) -> int:
        """Slot exponent"""
        return self.options.slots

    @property
    def _slots(self) -> int:
        """Slot count"""
        return 2 ** self._slots_exp

    @property
    def _scale_exp(self) -> int:
        """Scale exponent"""
        return self.options.scale

    @property
    def _security_level(self) -> int:
        """Security level"""
        return self.options.security

    @property
    def _poly_exp(self) -> int:
        """Polynomial exponent"""
        return self._slots_exp + 1

    @property
    def _poly(self) -> int:
        """Polynomial size"""
        return 2 ** self._poly_exp

    @property
    def _coeff_modulus(self) -> list[int]:
        """Coefficient modulus"""
        return COEFF_MODULUS[self._security_level][self._poly_exp]

    def __getstate__(self) -> dict:
        """Get serializable state"""
        state: dict = dict(super().__getstate__())  # type: ignore
        state.pop("_public", None)
        return state

    @cached_property
    def public(self) -> typing.Self:
        """Get public context"""
        return copy.deepcopy(self)

    def _new(self, /, *args, **kwds) -> Ciphertext:
        """Create new operable ciphertext"""
        return self._cls(_context=self.public, *args, **kwds)

    def _partition(self, array: np.ndarray) -> Iterable[np.ndarray]:
        """Transform array into flat batches"""
        parts = (array.size + self._slots - 1) // self._slots
        space = np.zeros(parts * self._slots, dtype=np.float64)
        space[:array.size] = array.ravel()
        return np.split(space, parts)

    def _encode(self, chunk):
        """Encode data to plaintext"""
        return chunk

    @abstractmethod
    def _encrypt(self, chunk):
        """Encrypt plaintext to ciphertext"""

    @abstractmethod
    def _decrypt(self, chunk):
        """Decrypt cypertext to plaintext"""

    def _decode(self, chunk):
        """Decode plaintext to data"""
        return chunk

    def _plaintext[T](self, data: T) -> Ciphertext[T]:
        """Encode data to plaintext"""
        descriptor, obj = materialize(data)
        chunks = tuple(map(self._encode, self._partition(obj)))
        return Ciphertext(_context=self.public, _descriptor=descriptor, _chunks=chunks)

    def encrypt[T](self, data: T) -> Ciphertext[T]:
        """Encrypt data to ciphertext"""
        descriptor, obj = materialize(data)
        chunks = tuple(map(self._encrypt, map(self._encode, self._partition(obj))))
        return self._new(_descriptor=descriptor, _chunks=chunks)

    def decrypt[T](self, data: Ciphertext[T]) -> T:
        """Decrypt cypertext to data"""
        data._link(self)
        descriptor = data._descriptor
        result = itertools.chain.from_iterable(map(self._decode, map(self._decrypt, data._chunks)))
        result = np.fromiter(iter=result, dtype=descriptor.type, count=math.prod(descriptor.shape)).reshape(descriptor.shape)
        return result if descriptor.numpy else result.tolist()  # type: ignore

    def __repr__(self) -> str:
        """Context representation"""
        return f"{self.__class__.__name__}(options={self.options!r})"
