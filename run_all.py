"""roda todos os ataques e a demo do gcm em sequencia, so para conferencia
"""

import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent

SCRIPTS = [
    "01_ecb_byte_at_a_time/attack.py",
    "02_cbc_padding_oracle/attack.py",
    "03_cbc_bitflipping/attack.py",
    "04_ctr_nonce_reuse/attack.py",
    "05_gcm_comparison/demo.py",
]

for script in SCRIPTS:
    caminho = RAIZ / script
    print("=" * 70)
    print(f"RODANDO: {script}")
    print("=" * 70)
    resultado = subprocess.run(
        [sys.executable, "-I", str(caminho.name)],
        cwd=str(caminho.parent),
    )
    if resultado.returncode != 0:
        print(f"[!] {script} terminou com erro (codigo {resultado.returncode})")
        sys.exit(resultado.returncode)
    print()

print("tudo rodou sem erros.")
