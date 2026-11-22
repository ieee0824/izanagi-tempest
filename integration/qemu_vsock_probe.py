"""Boot a minimal diskless VM and verify the actual vsock peer CID."""

import argparse
import gzip
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--kernel-release', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='tempest-vsock-') as temporary:
        root = Path(temporary)
        guest = root / 'guest'
        for name in ('bin', 'dev', 'proc', 'sys', 'modules'):
            (guest / name).mkdir(parents=True)
        shutil.copyfile('/usr/bin/busybox', guest / 'bin/busybox')
        (guest / 'bin/busybox').chmod(0o755)
        subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).parent / 'fixtures/vsock_probe.c'),
                        '-o', str(guest / 'bin/probe')], check=True)
        dependencies = subprocess.check_output([
            'modprobe', '-S', args.kernel_release, '--show-depends',
            'vmw_vsock_virtio_transport'], text=True)
        modules = []
        for line in dependencies.splitlines():
            if not line.startswith('insmod '):
                continue
            source = Path(line.split()[1])
            name = source.name.removesuffix('.zst')
            modules.append(name)
            data = (subprocess.check_output(['zstd', '-dc', str(source)])
                    if source.suffix == '.zst' else source.read_bytes())
            (guest / 'modules' / name).write_bytes(data)
        init = ('#!/bin/busybox sh\nset -eu\n'
                '/bin/busybox mount -t proc proc /proc\n'
                '/bin/busybox mount -t sysfs sysfs /sys\n'
                '/bin/busybox mount -t devtmpfs devtmpfs /dev\n')
        init += ''.join('/bin/busybox insmod /modules/' + name + '\n' for name in modules)
        init += '/bin/probe\n/bin/busybox poweroff -f\n'
        (guest / 'init').write_text(init)
        (guest / 'init').chmod(0o755)
        names = ['.'] + [str(path.relative_to(guest)) for path in guest.rglob('*')]
        archive = subprocess.check_output(['cpio', '-o', '-H', 'newc', '--quiet'],
                                          cwd=guest, input=('\n'.join(names) + '\n').encode())
        image = root / 'initrd.gz'
        image.write_bytes(gzip.compress(archive))
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
            listener.settimeout(40)
            listener.bind((socket.VMADDR_CID_HOST, 23101))
            listener.listen(1)
            with (root / 'serial.log').open('wb') as log:
                vm = subprocess.Popen([
                    'qemu-system-x86_64', '-machine', 'q35,accel=kvm:tcg', '-m', '256',
                    '-nodefaults', '-display', 'none', '-serial', 'stdio', '-no-reboot',
                    '-net', 'none', '-kernel', str(args.kernel), '-initrd', str(image),
                    '-append', 'console=ttyS0 panic=-1 quiet',
                    '-device', 'vhost-vsock-pci,id=ledger,guest-cid=232'],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    connection, peer = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        with connection.makefile('rb') as stream:
                            data = stream.readline(64)
                        if peer[0] != 232 or data != b'tempest-channel-probe\n':
                            raise RuntimeError('vsock peer or probe mismatch')
                        connection.sendall(b'ok\n')
                    if vm.wait(timeout=20) != 0:
                        raise RuntimeError('probe VM failed')
                finally:
                    if vm.poll() is None:
                        vm.kill()
                        vm.wait()
            output = (root / 'serial.log').read_text(errors='replace')
            if 'VSOCK_PROBE_OK' not in output:
                raise RuntimeError(output)
        print('Actual guest CID 232 verified; guest exchange and shutdown succeeded')


if __name__ == '__main__':
    main()
