"""TenSEAL encryption"""

# FIXME: TenSEAL context deserialization is very slow

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
    import tenseal
    from tenseal import sealapi
    from tenseal.tensors import CKKSVector
    from tenseal.enc_context import Context as SealContext
finally:
    sys.path.insert(0, _pkg)


__all__ = (
    "Context",
)


SECURITY_LEVEL = {
    # 0: sealapi.SEC_LEVEL_TYPE.NONE,
    128: sealapi.SEC_LEVEL_TYPE.TC128,
    192: sealapi.SEC_LEVEL_TYPE.TC192,
    256: sealapi.SEC_LEVEL_TYPE.TC256
}


@dataclass(repr=False, eq=False, order=False, slots=True, frozen=True)
class Ciphertext(ciphertext.Ciphertext):
    """TenSEAL ciphertext"""
    _context: "Context"

    def _link(self, context: "Context") -> None:
        """Link ciphertext to context"""
        for chunk in self._chunks:
            chunk.link_context(context._context)


class Context(context.Context):
    """TenSEAL context"""
    _cls = Ciphertext

    def __init__(self, options: core.Options = core.Options()) -> None:
        """Initialize context"""
        super().__init__(options)

        degree = 2 ** self._poly_exp
        level = SECURITY_LEVEL[self._security_level]

        # Context
        modulus = [
            m.bit_count()
            for m in sealapi.CoeffModulus.BFVDefault(degree, level)
        ]
        self._context = tenseal.context(
            scheme=tenseal.SCHEME_TYPE.CKKS,
            poly_modulus_degree=degree,
            coeff_mod_bit_sizes=modulus
        )

        # Keys
        self._context.global_scale = 2 ** self._scale_exp
        self._context.generate_galois_keys()
        self._context.generate_relin_keys()

    @cached_property
    def public(self) -> typing.Self:
        """Get public context"""
        context = super().public
        context._context.make_context_public()
        return context

    def _encode(self, chunk) -> tenseal.PlainTensor:
        """Encrypt plaintext to ciphertext"""
        return tenseal.plain_tensor(chunk)

    def _encrypt(self, chunk: tenseal.PlainTensor) -> CKKSVector:
        """Encrypt plaintext to ciphertext"""
        return tenseal.ckks_vector(self.public._context, chunk)

    def _decrypt(self, chunk: CKKSVector):
        """Decrypt cypertext to list"""
        return chunk.decrypt()


# Pickle support
def context_reducer(context: SealContext):
    """TenSEAL context pickle reducer"""
    cls = context.load
    args = (context.serialize(save_secret_key=True),)
    return (cls, args)


def ckks_vector_reducer(vector: CKKSVector):
    """TenSEAL CKKS vector pickle reducer"""
    cls = vector.lazy_load
    args = (vector.serialize(),)
    return (cls, args)


copyreg.pickle(SealContext, context_reducer)
copyreg.pickle(CKKSVector, ckks_vector_reducer)  # type: ignore (wrong inferred typing)
