"""OpenFHE encryption"""

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
    import openfhe
finally:
    sys.path.insert(0, _pkg)


__all__ = (
    "Context",
)


SECURITY_LEVEL = {
    # 0: openfhe.SecurityLevel.HEStd_NotSet,
    128: openfhe.SecurityLevel.HEStd_128_classic,
    192: openfhe.SecurityLevel.HEStd_192_classic,
    256: openfhe.SecurityLevel.HEStd_256_classic
}


@dataclass(repr=False, eq=False, order=False, slots=True, frozen=True)
class Ciphertext(ciphertext.Ciphertext):
    """OpenFHE ciphertext"""
    _context: "Context"

    def _neg(self, a: openfhe.Ciphertext) -> openfhe.Ciphertext:
        """Negate a ciphertext"""
        return self._context._context.EvalNegate(a)

    def _add(self, a: openfhe.Ciphertext, b: openfhe.Ciphertext) -> openfhe.Ciphertext:
        """Add two ciphertexts"""
        return self._context._context.EvalAdd(a, b)

    def _sub(self, a: openfhe.Ciphertext, b: openfhe.Ciphertext) -> openfhe.Ciphertext:
        """Substract two ciphertexts"""
        return self._context._context.EvalSub(a, b)

    def _mul(self, a: openfhe.Ciphertext, b: openfhe.Ciphertext) -> openfhe.Ciphertext:
        """Multiply two ciphertexts"""
        return self._context._context.EvalMult(a, b)


class Context(context.Context):
    """OpenFHE context"""
    _cls = Ciphertext

    def __init__(self, options: core.Options = core.Options()) -> None:
        """Initialize context"""
        super().__init__(options)

        ring_dim = 2 ** self._poly_exp
        print(ring_dim, self._poly_exp, self._slots_exp)
        level = SECURITY_LEVEL[self._security_level]

        # Context
        parameters = openfhe.CCParamsCKKSRNS()
        parameters.SetRingDim(ring_dim)
        parameters.SetSecurityLevel(level)
        parameters.SetScalingModSize(self._scale_exp)
        self._context = openfhe.GenCryptoContext(parameters)
        self._context.Enable(openfhe.PKESchemeFeature.PKE)
        # self._context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
        self._context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)

        # Keys
        keys = self._context.KeyGen()
        self._public_key = keys.publicKey
        self._private_key = keys.secretKey
        self._context.EvalMultKeyGen(self._private_key)

    @cached_property
    def public(self) -> typing.Self:
        """Get public context"""
        context = super().public
        try:
            del context._private_key
        except AttributeError:
            pass
        return context

    def _encode(self, chunk):
        """Ecnode data to plaintext"""
        return self._context.MakeCKKSPackedPlaintext(chunk)

    def _encrypt(self, chunk: openfhe.Plaintext) -> openfhe.Ciphertext:
        """Encrypt plaintext to ciphertext"""
        return self._context.Encrypt(self._public_key, chunk)

    def _decrypt(self, chunk: openfhe.Ciphertext) -> openfhe.Plaintext:
        """Decrypt cypertext to plaintext"""
        return self._context.Decrypt(chunk, self._private_key)

    def _decode(self, chunk: openfhe.Plaintext):
        """Decode plaintext to data"""
        return chunk.GetRealPackedValue()


# Serialization
def deserialize_context(str: bytes) -> openfhe.CryptoContext:
    """OpenFHE context deserializer"""
    return openfhe.DeserializeCryptoContextString(str, openfhe.BINARY)


def deserialize_ciphertext(str: bytes) -> openfhe.Ciphertext:
    """OpenFHE cipher text deserializer"""
    return openfhe.DeserializeCiphertextString(str, openfhe.BINARY)


def deserialize_publickey(str: bytes) -> openfhe.PublicKey:
    """OpenFHE public key deserializer"""
    return openfhe.DeserializePublicKeyString(str, openfhe.BINARY)


def deserialize_privatekey(str: bytes) -> openfhe.PrivateKey:
    """OpenFHE private key deserializer"""
    return openfhe.DeserializePrivateKeyString(str, openfhe.BINARY)


# Pickle support
def context_reducer(context: openfhe.CryptoContext):
    """OpenFHE context pickle reducer"""
    cls = deserialize_context
    args = (openfhe.Serialize(context, openfhe.BINARY),)
    return (cls, args)


def ciphertext_reducer(ciphertext: openfhe.Ciphertext):
    """OpenFHE cipher text pickle reducer"""
    cls = deserialize_ciphertext
    args = (openfhe.Serialize(ciphertext, openfhe.BINARY),)
    return (cls, args)


def public_key_reducer(public_key: openfhe.PublicKey):
    """OpenFHE public key pickle reducer"""
    cls = deserialize_publickey
    args = (openfhe.Serialize(public_key, openfhe.BINARY),)
    return (cls, args)


def private_key_reducer(private_key: openfhe.PrivateKey):
    """OpenFHE private key pickle reducer"""
    cls = deserialize_privatekey
    args = (openfhe.Serialize(private_key, openfhe.BINARY),)
    return (cls, args)


copyreg.pickle(openfhe.CryptoContext, context_reducer)
copyreg.pickle(openfhe.Ciphertext, ciphertext_reducer)
copyreg.pickle(openfhe.PublicKey, public_key_reducer)
copyreg.pickle(openfhe.PrivateKey, private_key_reducer)
