"""Ciphertext package"""
from __future__ import annotations

import typing
import operator
import itertools
from dataclasses import dataclass

import numpy as np

from polyhe.core import Descriptor

if typing.TYPE_CHECKING:
    from polyhe.core.context import Context


__all__ = (
    "Ciphertext",
)


@dataclass(eq=False, order=False, slots=True, frozen=True)
class Ciphertext[T]:
    """Abstract ciphertext"""
    _context: Context
    _descriptor: Descriptor
    _chunks: tuple

    def _new(self, /, *args, **kwds):
        """Create new operable ciphertext"""
        return self.__class__(
            _context=self._context,
            _descriptor=self._descriptor,
            *args, **kwds
        )

    def _operable(self, other):
        """Ensure ciphertext is operable"""
        if not isinstance(other, Ciphertext):

            # Try scalar to array
            try:
                is_np = isinstance(other, np.ndarray)
                other = np.full(self._descriptor.shape, other, self._descriptor.type)
                if not is_np:
                    other = other.tolist()
            except Exception:
                pass

            # Try data to plaintext
            try:
                other = self._context._plaintext(other)
            except Exception:
                raise NotImplementedError(f"Different ciphertext types ({other.__class__} != {self.__class__})")  # from None

        if other._descriptor != self._descriptor:
            raise ValueError(f"Different underlying descriptions ({other._descriptor} != {self._descriptor})")

        return other

    def _link(self, context):
        """Link ciphertext to context"""

    def _neg(self, a):
        """Negate two ciphertext"""
        return operator.neg(a)

    def _add(self, a, b):
        """Add two ciphertexts"""
        return operator.add(a, b)

    def _sub(self, a, b):
        """Substract two ciphertexts"""
        return operator.sub(a, b)

    def _mul(self, a, b):
        """Multiply two ciphertexts"""
        return operator.mul(a, b)

    def _op_unary(self, op):
        """Execute a unary operation"""
        self._link(self._context)
        chunks = tuple(map(op, self._chunks))
        return self._new(_chunks=chunks)

    def _op_binary(self, op, other):
        """Execute a binary operation"""
        other = self._operable(other)
        self._link(self._context)
        other._link(self._context)
        chunks = tuple(itertools.starmap(op, zip(self._chunks, other._chunks)))
        return self._new(_chunks=chunks)

    def __neg__(self):
        """Negate a ciphertext"""
        return self._op_unary(self._neg)

    def __add__(self, other):
        """Add two ciphertexts"""
        return self._op_binary(self._add, other)

    def __sub__(self, other):
        """Substract two ciphertexts"""
        return self._op_binary(self._sub, other)

    def __mul__(self, other):
        """Multiply two ciphertexts"""
        return self._op_binary(self._mul, other)

    def __repr__(self) -> str:
        """Ciphertext representation"""
        return f"<{self.__class__.__name__} format={self._descriptor.type.__name__} shape={self._descriptor.shape}>"
