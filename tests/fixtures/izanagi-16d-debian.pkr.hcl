packer {
  required_plugins {
    qemu = {
      version = "~> 1"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "debian_version" {
  type    = string
  default = "13.7.0"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:6e93fa1759bd9d4b0fc11e938987de6967ee7de5297dac1be27c3a75cc17024b"
}

locals {
  iso_url = "https://cdimage.debian.org/debian-cd/current/arm64/iso-cd/debian-${var.debian_version}-arm64-netinst.iso"
}

variable "agent_binary" {
  type        = string
  description = "Path to izanagi-agent binary (aarch64-unknown-linux-gnu)"
}

variable "ebpf_binary" {
  type        = string
  description = "Path to izanagi-ebpf ELF object (bpfel-unknown-none)"
  validation {
    condition     = length(var.ebpf_binary) > 0
    error_message = "Variable ebpf_binary is required. Run 'make build-ebpf' first."
  }
}

variable "disk_size" {
  type    = string
  default = "4G"
}

variable "http_binary" {
  type        = string
  description = "Path to guest HTTP sidecar (aarch64-unknown-linux-gnu)"
  validation {
    condition     = length(var.http_binary) > 0
    error_message = "Variable http_binary is required. Run 'make build-http-gnu' first."
  }
}

variable "memory" {
  type    = number
  default = 2048
}

variable "cpus" {
  type    = number
  default = 2
}

source "qemu" "debian" {
  iso_url      = local.iso_url
  iso_checksum = var.iso_checksum

  output_directory = "output-debian"
  vm_name          = "debian-aarch64.qcow2"

  disk_size = var.disk_size
  format    = "qcow2"

  qemu_binary  = "qemu-system-aarch64"
  machine_type = "virt"
  accelerator  = "hvf"
  cpu_model    = "host"
  memory       = var.memory
  cpus         = var.cpus

  qemuargs = [
    ["-bios", "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"],
    ["-device", "virtio-net-pci,netdev=user.0"],
    ["-device", "virtio-gpu-pci"],
    ["-device", "usb-ehci"],
    ["-device", "usb-kbd"],
    ["-device", "usb-tablet"],
    ["-boot", "menu=off"],
  ]

  net_device        = "virtio-net-pci"
  disk_interface    = "virtio"
  boot_wait         = "60s"
  boot_key_interval = "100ms"
  shutdown_command  = "sh /tmp/izanagi-lock-down.sh && shutdown -h now"

  # aarch64 では -boot once=d が使えないため無効化
  cd_files     = []
  communicator = "ssh"
  ssh_username = "root"
  ssh_timeout  = "30m"
  ssh_port     = 22
  headless     = true

  http_directory = "http"

  boot_command = [
    # GRUB コマンドラインに入り、preseed 付きでカーネルを起動
    "c<wait3>",
    "linux /install.a64/vmlinuz auto=true priority=critical preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg --- quiet<enter>",
    "initrd /install.a64/initrd.gz<enter>",
    "boot<enter>",
  ]
}

build {
  sources = ["source.qemu.debian"]

  # izanagi-agent をコピー
  provisioner "file" {
    source      = var.agent_binary
    destination = "/usr/local/bin/izanagi-agent"
  }

  # 最終イメージからビルド用 root 認証と SSH 起動を除去する。
  provisioner "file" {
    source      = "${path.root}/lock-down.sh"
    destination = "/tmp/izanagi-lock-down.sh"
  }

  provisioner "file" {
    source      = "${path.root}/verify-image.sh"
    destination = "/tmp/verify-image.sh"
  }

  # eBPF オブジェクトをコピー (ビルド済みの場合)
  provisioner "file" {
    source      = var.ebpf_binary
    destination = "/tmp/izanagi-ebpf.o"
  }

  # agent のセットアップ
  provisioner "file" {
    source      = var.http_binary
    destination = "/usr/local/bin/izanagi-http-capture"
  }

  provisioner "shell" {
    inline = [
      # systemd-resolved の起動を待つ (resolv.conf が有効になるまで)
      "systemctl start systemd-resolved || true",
      "for i in $(seq 1 15); do getent hosts deb.debian.org >/dev/null 2>&1 && break; echo \"Waiting for DNS... ($i/15)\"; sleep 2; done",
      # fallback: resolved が動かない場合は SLIRP DNS を一時的に直接設定
      "getent hosts deb.debian.org >/dev/null 2>&1 || (rm -f /etc/resolv.conf && echo 'nameserver 10.0.2.3' > /etc/resolv.conf && echo 'DNS fallback to 10.0.2.3')",

      # 基本パッケージ + Homebrew の依存
      "apt-get update",
      "apt-get install -y curl git build-essential procps file",

      # DNS fallback を適用した場合は resolv.conf の symlink を復元して systemd-resolved を有効化
      "if [ ! -L /etc/resolv.conf ]; then ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf && systemctl restart systemd-resolved || true; fi",

      # 非特権ユーザーを作成（コマンド実行はこのユーザーで行う）
      "useradd -m -d /home/izanagi -s /bin/bash izanagi",
      "mkdir -p /workspace && chown izanagi:izanagi /workspace",

      # Homebrew (Linuxbrew) を izanagi ユーザーでインストール
      # NOTE: Homebrew は固定バージョン URL を提供していないため HEAD を使用。
      # イメージの再現性が必要な場合は git clone で特定コミットを使うこと。
      "mkdir -p /home/linuxbrew/.linuxbrew && chown -R izanagi:izanagi /home/linuxbrew",
      "NONINTERACTIVE=1 su - izanagi -c 'bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"'",
      # izanagi ユーザーの .bashrc に brew の PATH を追加
      "echo 'eval \"$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\"' >> /home/izanagi/.bashrc",
      "echo 'eval \"$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\"' >> /home/izanagi/.profile",

      # anyenv をインストール (タグ固定で再現性を確保)
      "su - izanagi -c 'git clone --branch v1.1.5 --depth 1 https://github.com/anyenv/anyenv ~/.anyenv'",
      "echo 'export PATH=\"$HOME/.anyenv/bin:$PATH\"' >> /home/izanagi/.bashrc",
      "echo 'eval \"$(anyenv init -)\"' >> /home/izanagi/.bashrc",
      "echo 'export PATH=\"$HOME/.anyenv/bin:$PATH\"' >> /home/izanagi/.profile",
      "echo 'eval \"$(anyenv init -)\"' >> /home/izanagi/.profile",
      "su - izanagi -c 'export PATH=\"$HOME/.anyenv/bin:$PATH\" && yes | anyenv install --init'",
      "su - izanagi -c 'export PATH=\"$HOME/.anyenv/bin:$PATH\" && eval \"$(anyenv init -)\" && anyenv install nodenv'",
      "su - izanagi -c 'export PATH=\"$HOME/.anyenv/bin:$PATH\" && eval \"$(anyenv init -)\" && nodenv install 24.14.1 && nodenv global 24.14.1'",
      # agent の固定 PATH (/usr/local/bin) から node/npm を使えるように symlink を作成
      "ln -sf /home/izanagi/.anyenv/envs/nodenv/shims/node /usr/local/bin/node",
      "ln -sf /home/izanagi/.anyenv/envs/nodenv/shims/npm /usr/local/bin/npm",

      "chmod +x /usr/local/bin/izanagi-agent",
      "chown root:root /usr/local/bin/izanagi-http-capture && chmod 0755 /usr/local/bin/izanagi-http-capture",

      # eBPF オブジェクトを配置
      "mkdir -p /opt/izanagi",
      "if [ -f /tmp/izanagi-ebpf.o ] && [ -s /tmp/izanagi-ebpf.o ]; then mv /tmp/izanagi-ebpf.o /opt/izanagi/izanagi-ebpf.o; fi",

      # タイムゾーンを Asia/Tokyo に設定
      "ln -sf /usr/share/zoneinfo/Asia/Tokyo /etc/localtime",
      "echo 'Asia/Tokyo' > /etc/timezone",

      # ファイアウォール無効化 (QEMU SLIRP ポートフォワーディング用)
      "systemctl disable nftables.service 2>/dev/null || true",
      "systemctl stop nftables.service 2>/dev/null || true",
      "nft flush ruleset 2>/dev/null || true",

      # systemd サービス
      "cat > /etc/systemd/system/izanagi-agent.service << 'SERVICEEOF'\n[Unit]\nDescription=Izanagi Agent\nAfter=network.target\n\n[Service]\nType=simple\nEnvironment=IZANAGI_ALLOW_ALL_COMMANDS=1\nExecStart=/usr/local/bin/izanagi-agent\nRestart=always\nRestartSec=3\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\nSERVICEEOF",
      "systemctl daemon-reload",
      "systemctl enable izanagi-agent",

      # SSH root ログインを無効化 (Packer プロビジョニング完了後は不要)
      "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",

      # クリーンアップ
      "apt-get clean",
      "rm -rf /var/lib/apt/lists/*",
    ]
  }
}
