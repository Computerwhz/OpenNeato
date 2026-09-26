"""Run real AuthManager code against host adapters (Windows, Visual Studio C++)."""
from pathlib import Path
import subprocess
import os

root = Path(__file__).resolve().parents[2]
out = root / '.pio' / 'auth-host-test'
out.mkdir(parents=True, exist_ok=True)
parts = [(root / 'tests/auth/host_stubs.h').read_text()]
for name in ['auth_manager.h', 'auth_manager.cpp']:
    parts.append('\n'.join(line for line in (root / 'firmware/src' / name).read_text().splitlines() if not line.startswith('#include')))
parts.append((root / 'tests/auth/host_tests.cpp').read_text())
source = out / 'test.cpp'
source.write_text('\n'.join(parts))
installations = sorted(Path(os.environ.get('ProgramFiles', 'C:/Program Files')).glob('Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat'))
if not installations:
    raise SystemExit('Visual Studio C++ build tools are required')
command = f'"{installations[-1]}" >nul && cl /nologo /std:c++17 /EHsc /W3 /D NOMINMAX "{source}" /Fe:"{out / "auth-test.exe"}" /Fo:"{out / "auth-test.obj"}" && "{out / "auth-test.exe"}"'
subprocess.run(f'cmd.exe /d /s /c "{command}"', cwd=out, check=True)

