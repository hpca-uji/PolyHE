"""uArchFHE encryption"""

import sys
import typing
import copyreg
from dataclasses import dataclass
from functools import cached_property

from polyhe import core
from polyhe.core import context
from polyhe.core import ciphertext

# Make sure global package is not confused with current package
_pkg = sys.path.pop(0)
try:
    import fhe_py_binding as uarchfhe
finally:
    sys.path.insert(0, _pkg)


__all__ = (
    "Context",
)


@dataclass(repr=False, eq=False, order=False, slots=True, frozen=True)
class Ciphertext(ciphertext.Ciphertext):
    """uArchFHE ciphertext"""
    _context: "Context"

    def _link(self, context: "Context") -> None:
        """Link ciphertext to context"""
        for chunk in self._chunks:
            chunk.attach_context(context._context)

    def _neg(self, a: uarchfhe.PyCiphertext) -> uarchfhe.PyCiphertext:
        """Negate a ciphertext"""
        return uarchfhe.PyCiphertext.negate(a)

    def _add(self, a: uarchfhe.PyCiphertext, b: uarchfhe.PyCiphertext) -> uarchfhe.PyCiphertext:
        """Add two ciphertexts"""
        if not isinstance(b, uarchfhe.PyCiphertext):
            return uarchfhe.PyCiphertext.add_plaintext(a, b, self._context._scale_exp)
        return uarchfhe.PyCiphertext.add(a, b)

    def _sub(self, a: uarchfhe.PyCiphertext, b: uarchfhe.PyCiphertext) -> uarchfhe.PyCiphertext:
        """Substract two ciphertexts"""
        if not isinstance(b, uarchfhe.PyCiphertext):
            return uarchfhe.PyCiphertext.sub_plaintext(a, b, self._context._scale_exp)
        return uarchfhe.PyCiphertext.sub(a, b)

    def _mul(self, a: uarchfhe.PyCiphertext, b: uarchfhe.PyCiphertext) -> uarchfhe.PyCiphertext:
        """Multiply two ciphertexts"""
        if not isinstance(b, uarchfhe.PyCiphertext):
            return uarchfhe.PyCiphertext.mult_plaintext(a, b, self._context._slots, self._context._scale_exp)
        return uarchfhe.PyCiphertext.mult(a, b)


class Context(context.Context):
    """uArchFHE context"""
    _cls = Ciphertext

    def __init__(self, options: core.Options = core.Options()) -> None:
        """Initialize context"""
        super().__init__(options)
        self._plaintext = self.encrypt

        # Context
        h = 3  # Secret key Hamming weight (security parameter)
        sigma = 3  # Standard deviation for error distribution (security parameter)
        self._context = uarchfhe.PyContext(self._poly_exp, max(self._coeff_modulus), self._scale_exp, sigma, h)

        # Keys
        keygen = uarchfhe.PyKeyGen(self._context)
        self._keys = keygen.gen_keys()

    @cached_property
    def public(self) -> typing.Self:
        """Get public context"""
        context = super().public
        public_key = context._keys.save_public_keys_to_memory()
        context._keys = context._keys.load_full_from_memory(public_key)
        return context

    @cached_property
    def _ckks(self) -> uarchfhe.PyCKKS:
        """uArchFHE CKKS context"""
        return uarchfhe.PyCKKS(self._context, self._keys)

    def __getstate__(self) -> dict:
        """Get serializable state"""
        state = super().__getstate__()
        state.pop("_ckks", None)
        return state

    def _encrypt(self, chunk) -> uarchfhe.PyCiphertext:
        """Encrypt list to ciphertext"""
        return self._ckks.encrypt(chunk, len(chunk), self._scale_exp, max(self._coeff_modulus))

    def _decrypt(self, chunk: uarchfhe.PyCiphertext):
        """Decrypt cypertext to list"""
        return self._ckks.decrypt(chunk)


# Pickle support
def context_reducer(context: uarchfhe.PyContext) -> tuple:
    """uArchFHE context pickle reducer"""
    cls = context.load_from_memory
    args = (context.save_to_memory(),)
    return (cls, args)


def keychain_reducer(keychain: uarchfhe.PyKeychain) -> tuple:
    """uArchFHE key chain pickle reducer"""
    cls = keychain.load_full_from_memory
    public = keychain.save_public_keys_to_memory()
    secret = keychain.save_secret_key_to_memory() if keychain.has_secret_key else None
    args = (public, secret)
    return (cls, args)


def ciphertext_reducer(ciphertext: uarchfhe.PyCiphertext) -> tuple:
    """uArchFHE ciphertext reducer"""
    cls = ciphertext.load_from_memory
    args = (ciphertext.save_to_memory(),)
    return (cls, args)


copyreg.pickle(uarchfhe.PyContext, context_reducer)
copyreg.pickle(uarchfhe.PyKeychain, keychain_reducer)
copyreg.pickle(uarchfhe.PyCiphertext, ciphertext_reducer)
