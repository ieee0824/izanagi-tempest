"""Boot the curated login-test userspace with read-only 9p and vsock, without a NIC."""
import argparse
import gzip
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--kernel-release', required=True)
    parser.add_argument('--runtime', required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='tempest-login-boot-', dir='/var/lib') as temporary:
        root = Path(temporary)
        guest = root / 'guest'
        for name in ('bin', 'dev', 'proc', 'sys', 'modules', 'runtime', 'usr', 'lib', 'lib64',
                     'opt', 'etc', 'tmp', 'run', 'var/lib/tempest-claude-offline'):
            (guest / name).mkdir(parents=True, exist_ok=True)
        shutil.copyfile('/usr/bin/busybox', guest / 'bin/busybox')
        (guest / 'bin/busybox').chmod(0o755)
        modules = []
        for module in ('9p', '9pnet_virtio', 'vmw_vsock_virtio_transport', 'nf_tables',
                       'nft_reject_inet', 'nft_chain_nat'):
            dependencies = subprocess.check_output([
                'modprobe', '-S', args.kernel_release, '--show-depends', module], text=True)
            for line in dependencies.splitlines():
                if not line.startswith('insmod '):
                    continue
                source = Path(line.split()[1])
                name = source.name.removesuffix('.zst')
                if name in modules:
                    continue
                modules.append(name)
                data = (subprocess.check_output(['zstd', '-dc', str(source)])
                        if source.suffix == '.zst' else source.read_bytes())
                (guest / 'modules' / name).write_bytes(data)
        init = '''#!/bin/busybox sh
set -eu
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts devpts /dev/pts
/bin/busybox chmod 1777 /tmp
'''
        init += ''.join('/bin/busybox insmod /modules/' + name + '\n' for name in modules)
        init += '''/bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L,ro runtime /runtime
'''
        for name in ('usr', 'lib', 'lib64', 'opt', 'var/lib/tempest-claude-offline'):
            init += f'/bin/busybox mount --bind /runtime/{name} /{name}\n'
        init += '''/bin/busybox cp /runtime/etc/* /etc/
export PATH=/usr/sbin:/usr/bin:/bin
export PYTHONDONTWRITEBYTECODE=1
/usr/bin/python3 -c 'import ssl,sqlite3,pty,os; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; Ed25519PrivateKey.generate(); assert os.stat("/var/lib/tempest-claude-offline/claude").st_nlink == 1; print("LOGIN_VM_RUNTIME_CRYPTO_OK")'
/usr/bin/python3 - <<'READONLY'
import errno
for path in ("/runtime/readonly-probe", "/runtime/new-file-probe"):
    try:
        open(path, "wb").close()
    except OSError as error:
        assert error.errno == errno.EROFS, error
    else:
        raise AssertionError("read-only export accepted a write")
print("LOGIN_VM_READONLY_OK")
READONLY
/opt/bin/libtest --ignored --exact claude_offline::tests::pin_login_vm_runtime_artifacts --nocapture
/usr/bin/openssl version
ip link set lo up
nft add table inet runtime_smoke
nft delete table inet runtime_smoke
echo LOGIN_VM_RUNTIME_OK
/bin/busybox poweroff -f
'''
        (guest / 'init').write_text(init)
        (guest / 'init').chmod(0o755)
        names = ['.'] + [str(path.relative_to(guest)) for path in guest.rglob('*')]
        archive = subprocess.check_output(['cpio', '-o', '-H', 'newc', '--quiet'], cwd=guest,
                                         input=('\n'.join(names) + '\n').encode())
        image = root / 'initrd.gz'
        image.write_bytes(gzip.compress(archive))
        log_path = root / 'serial.log'
        with log_path.open('wb') as log:
            vm = subprocess.Popen([
                'qemu-system-x86_64', '-machine', 'q35,accel=kvm:tcg', '-m', '768',
                '-nodefaults', '-display', 'none', '-serial', 'stdio', '-no-reboot', '-net', 'none',
                '-kernel', str(args.kernel), '-initrd', str(image),
                '-append', 'console=ttyS0 panic=-1 quiet',
                '-device', 'vhost-vsock-pci,id=ledger,guest-cid=234',
                '-virtfs', f'local,path={args.runtime.resolve()},mount_tag=runtime,security_model=none,readonly=on'],
                stdout=log, stderr=subprocess.STDOUT)
            try:
                code = vm.wait(timeout=60)
            finally:
                if vm.poll() is None:
                    vm.kill()
                    vm.wait()
        output = log_path.read_text(errors='replace')
        print(output[-6000:])
        if code != 0 or 'LOGIN_VM_RUNTIME_OK' not in output:
            raise RuntimeError('login userspace VM boot or runtime verification failed')


if __name__ == '__main__':
    main()
