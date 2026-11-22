"""Prepare a curated read-only 9p export for the isolated login VM harness.

Run in a private mount namespace. No host root or credential directories are exported.
Bind mounts preserve the single-link fixed-artifact invariant without copying the CLI.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--binary-directory', required=True, type=Path)
    parser.add_argument('--libtest', required=True, type=Path)
    parser.add_argument('--command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root inside a private mount namespace')
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    mounts = []
    copied = set()

    def bind(source, relative):
        source = Path(source).resolve(strict=True)
        target = root / relative
        if target in copied:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            target.mkdir()
        else:
            target.touch()
        subprocess.run(['mount', '--bind', str(source), str(target)], check=True)
        mounts.append(target)
        copied.add(target)

    def executable(source, relative=None, include_file=True):
        source = Path(source).resolve(strict=True)
        if include_file:
            bind(source, relative or source.relative_to('/'))
        result = subprocess.run(['ldd', str(source)], capture_output=True, text=True)
        if result.returncode == 0:
            for token in result.stdout.split():
                if token.startswith('/'):
                    bind(token, token.lstrip('/'))

    try:
        for tool in ('python3', 'openssl', 'ip', 'nft', 'strace', 'mount', 'umount',
                     'unshare', 'flock', 'nsenter', 'setpriv', 'busybox'):
            source = shutil.which(tool)
            if source is None:
                raise RuntimeError(f'missing runtime tool: {tool}')
            executable(source)
            # Preserve both merged-/usr spellings used by the fixed fixture.
            if tool in ('busybox', 'mount', 'umount'):
                bind(source, 'bin/' + tool)
        bind('/usr/bin/python3.12', 'usr/bin/python3')
        bind('/usr/lib/python3.12', 'usr/lib/python3.12')
        bind('/usr/lib/x86_64-linux-gnu/ossl-modules', 'usr/lib/x86_64-linux-gnu/ossl-modules')
        for extension in Path('/usr/lib/python3.12/lib-dynload').glob('*.so'):
            executable(extension, include_file=False)
        for name in ('protocols', 'services', 'ethertypes'):
            bind('/etc/' + name, 'etc/' + name)
        bind('/var/lib/tempest-claude-offline/claude', 'var/lib/tempest-claude-offline/claude')
        for name in ('ld-linux-x86-64.so.2', 'libc.so.6', 'libdl.so.2', 'libm.so.6',
                     'libpthread.so.0', 'librt.so.1'):
            bind('/usr/lib/x86_64-linux-gnu/' + name, 'var/lib/tempest-claude-offline/lib/' + name)
        for name in ('tempest-combined-login-diagnostic', 'tempest-host-login-responder',
                     'tempest-host-login-publisher', 'tempest-claude-offline-local-auth-pty'):
            executable(args.binary_directory / name, 'opt/bin/' + name)
        executable(args.libtest, 'opt/bin/libtest')
        repository = Path(__file__).resolve().parents[1]
        for directory in ('integration', 'tools/host_ledger'):
            bind(repository / directory, 'opt/tempest/' + directory)
        for module in ('cryptography', '_cffi_backend.cpython-312-x86_64-linux-gnu.so'):
            source = Path('/usr/lib/python3/dist-packages') / module
            if source.exists():
                bind(source, 'usr/lib/python3/dist-packages/' + module)
        print(f'LOGIN_VM_RUNTIME_READY mounts={len(mounts)} export={root}', flush=True)
        # Keep the private namespace and its curated export alive for QEMU.
        if args.command:
            subprocess.run(args.command, check=True)
        else:
            try:
                input('Press Enter only after the VM has exited to unmount the runtime.\n')
            except EOFError:
                pass
    finally:
        for target in reversed(mounts):
            subprocess.run(['umount', str(target)], check=True)
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
