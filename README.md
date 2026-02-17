# uHE
Homomorphic Encryption made easy

- Builtin pickle support
- Maintains array type and shape
- Supports arbitrary sized arrays

## Example
```python
import uhe
import numpy

ctx = uhe.new()

p1 = np.full((2, 3, 4), 0.3)
p2 = np.full((2, 3, 4), 0.4)

c1 = ctx.encrypt(p1)
c2 = ctx.encrypt(p2)
c3 = c1 + c2

p3 = ctx.decrypt(c3)
# np.full((2, 3, 4), 0.7)
```

## Install
### Production
```bash
pip install uhe
```

### Development
```bash
git clone https://github.com/hpca-uji/uhe.git
cd uhe
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

    Tipical values: `128`, `192` and `256`.

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

  - `encrypt(obj: numpy.ndarray) -> Ciphertext`

    Encode numpy array to ciphertext

  - `decrypt(obj: Ciphertext) -> numpy.ndarray`

    Decode cypertext to numpy array

- `core.Ciphertext(...)`

  Ciphertext has `+` and `*` operator support.

- `{backend}.Context(options)`

  Concrete context encryption implementation for the given backend

- `{backend}.Ciphertext(options)`

  Concrete ciphertext encryption implementation for the given backend

## Acknowledgments
The library has been partially supported by:
- Project PID2023-146569NB-C22 "Inteligencia sostenible en el Borde-UJI" funded by the Spanish Ministry of Science, Innovation and Universities.
- Project C121/23 Convenio "CIBERseguridad post-Cuántica para el Aprendizaje FEderado en procesadores de bajo consumo y aceleradores (CIBER-CAFE)" funded by the Spanish National Cybersecurity Institute (INCIBE).

![](footer.jpg)