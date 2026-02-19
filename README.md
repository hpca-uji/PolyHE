# PolyHE
Easy Homomorphic Encryption

- Supports Python's operators & pickle serialization
- Supports arbitrary typed, shaped & sized arrays

## Example
```python
import polyhe

ctx = polyhe.new()

# Numbers
p1 = 1
p2 = 2
c1 = ctx.encrypt(p1)
c2 = ctx.encrypt(p2)
c3 = c1 * c2
p3 = ctx.decrypt(c3)
# 2

# Lists
p1 = [0.3, 0.4]
p2 = [0.4, 0.3]
c1 = ctx.encrypt(p1)
c2 = ctx.encrypt(p2)
c3 = c1 + c2
p3 = ctx.decrypt(c3)
# [0.7, 0.7]

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

  - `OPENFHE`
  - `TENSEAL`
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

  Context implementation

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

  Concrete context encryption implementation for the given backend

## Acknowledgments
The library has been partially supported by:
- Project PID2023-146569NB-C22 "Inteligencia sostenible en el Borde-UJI" funded by the Spanish Ministry of Science, Innovation and Universities.
- Project C121/23 Convenio "CIBERseguridad post-Cuántica para el Aprendizaje FEderado en procesadores de bajo consumo y aceleradores (CIBER-CAFE)" funded by the Spanish National Cybersecurity Institute (INCIBE).

![](footer.jpg)