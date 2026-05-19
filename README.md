# PolyHE
Simple and Pythonic Homomorphic Encryption

Designed to make homomorphic encryption approachable, predictable and easy to integrate into Python applications.

- Native Python operators (`+`, `-`, `*`)
- Transparent operations with Python and NumPy objects
- Built-in pickle support for encrypted objects
- Predictable type, dtype and shape preservation
- Arbitrary typed, shaped and sized arrays
- No plaintext encoders or packing APIs required
- Automatic multi-ciphertext management beyond backend slot limits
- Portable ciphertexts with embedded public context
- Unified high-level interface across multiple FHE backends
- Transparent serialization and remote computation workflows
- Familiar Python semantics with minimal cryptographic boilerplate
- Designed for experimentation, prototyping and educational use

## Example
```python
import polyhe
ctx = polyhe.new()

# Numbers
p1 = 1
p2 = -1
c1 = ctx.encrypt(p1)
c2 = ctx.encrypt(p2)
c3 = c1 * c2 + p1
p3 = ctx.decrypt(c3)
# 0

# Lists
p1 = [0.3, 0.4]
p2 = [0.4, 0.3]
c1 = ctx.encrypt(p1)
c2 = ctx.encrypt(p2)
c3 = -c1 + c2
p3 = ctx.decrypt(c3)
# [0.1, -0.1]

# NumPy
import numpy as np
p1 = np.full((2, 3, 4), 0.4, np.float64)
p2 = np.full((2, 3, 4), 0.3, np.float64)
c1 = ctx.encrypt(p1)
c2 = ctx.encrypt(p2)
c3 = c1 - c2
p3 = ctx.decrypt(c3)
# np.full((2, 3, 4), 0.1, np.float64)
```

## Install
### Production
```bash
pip install polyhe
```

### Development
```bash
git clone https://github.com/hpca-uji/polyhe.git
cd polyhe
pip install -e .
```

## Documentation
### Constants
- `Backend`:

  Encryption backend

  - `OPENFHE` ([source](https://github.com/openfheorg/openfhe-python))
  - `TENSEAL` ([source](https://github.com/OpenMined/TenSEAL))
  - `UARCHFHE`

### Structures
- `Options(...)`

  Encryption options

  - `slots: int = 13`

    `2 ** slots` elements per backend ciphertext

  - `scale: int = 40`

    `2 ** scale` typical operational scale

  - `security: int = 128`

    Security level

    Typical values: `128`, `192` and `256`.

### Functions
- `new(backend, options)`

  Create a communicator.

  - `backend: Backend = Backend.OPENFHE`
  - `options: Options = Options()`

### Classes
- `core.Context(options)`

  Encryption context implementation

  - `options: Options = Options()`

  ---

  - `encrypt(data) -> Ciphertext`

    Encrypt data to ciphertext

  - `decrypt(obj: Ciphertext)`

    Decrypt cypertext to data

- `core.Ciphertext(...)`

  Ciphertext has `-`, `+` and `*` operator support, with either another ciphertext or plain data.

  *Note: Support for operation may vary between backends*

- `{backend}.Context(options)`

  Concrete encryption context implementation for the given backend

## Notes
`PolyHE` prioritizes simplicity and ease of use over advanced features. It is designed for prototyping and experimentation purposes rather than production-grade deployments. If you require fine-grained control over encryption parameters, performance tuning, or advanced schemes, we recommend using the underlying backend libraries directly. Alternatively, `Pyfhel` ([source](https://github.com/ibarrond/Pyfhel)) is a mature Python library that provides more comprehensive access to homomorphic encryption features.

## Acknowledgments
The library has been partially supported by:
- Project PID2023-146569NB-C22 "Inteligencia sostenible en el Borde-UJI" funded by the Spanish Ministry of Science, Innovation and Universities.
- Project C121/23 Convenio "CIBERseguridad post-Cuántica para el Aprendizaje FEderado en procesadores de bajo consumo y aceleradores (CIBER-CAFE)" funded by the Spanish National Cybersecurity Institute (INCIBE).

![](footer.jpg)