# Vendored Windows launcher stubs

These console-mode launcher stubs are copied unmodified from distlib 0.4.3
(`distlib/t32.exe`, `distlib/t64.exe`, `distlib/t64-arm.exe`). They are
byte-identical to the stubs vendored by pip 26.2.1 (distlib 0.4.2).

- Upstream: https://github.com/pypa/distlib (launcher source: simple_launcher)
- License: PSF-2.0, see `LICENSE.txt` in this directory.

| File | SHA-256 |
| --- | --- |
| `t32.exe` | `6b4195e640a85ac32eb6f9628822a622057df1e459df7c17a12f97aeabc9415b` |
| `t64.exe` | `81a618f21cb87db9076134e70388b6e9cb7c2106739011b6a51772d22cae06b7` |
| `t64-arm.exe` | `ebc4c06b7d95e74e315419ee7e88e1d0f71e9e9477538c00a93a9ff8c66a6cfc` |

`python_env_repair/generator.py` pins these hashes and refuses to use a stub
that does not match. Updating a stub is a deliberate change: replace the file,
update both hash tables, and re-run the byte-equivalence tests against the
matching distlib release.
