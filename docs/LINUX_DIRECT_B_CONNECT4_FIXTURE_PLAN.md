# 固定loopback隔離テスト案

room #16934 のレビュー用。既存の特権管理経路から専用の子cgroupを一つ作り、固定テストbinaryを引数なし、空の環境で一回起動する。親がloopback上に専用listenerを二つ確保し、片方のportをこの試行の許可先とする。両listenerを保持したまま実行し、port競合やattach状態の不一致では子を解放せず終了する。

既存GCCとLinux UAPIヘッダで、固定命令列と `bpf` syscall ABIをビルドする案を採る。固定アドレスと親が確保したportの比較のみとし、入力ファイルから任意命令や宛先を受け取る経路は設けない。親だけがプログラムとlink FDを保持し、対象cgroupの同一性と有効なattachを照合する。

子は接続前の待機点で専用cgroupへ収容する。不要なFDを閉じ、専用UIDへ移行してcapabilityを消去し、no_new_privsとseccompを適用する。親はPID、cgroup、FD、capability、seccompの事後状態を確認してから実行を許す。子にcgroupの書き込み経路やBPF管理FDを渡さない。

- 正例は許可listenerへのIPv4 TCP接続一回とし、親が受理を独立に数える。
- 負例はもう一つのloopback listenerへのTCP接続と、IPv6、UDP、raw、Unix socketの生成を拒否する。同じ試験で許可外listenerの受理数がゼロであることを親が集計する。拒否とlistener不在を区別するため、親側から両listenerの到達を先に確認する。
- 親は絶対期限を持ち、子を回収して専用cgroupが空になったことを確認してからlinkを閉じ、cgroupとlistenerを削除する。回収が確認できない場合は隔離を解除せず、失敗を記録する。

この試験の受入範囲は固定ホスト上のdummy listenerへの接続制御である。実IzanagiのVM同一性と設定ファイル閉包は後続試験で確認する。ここでは読取調査のみ実施し、load、attach、unit追加、VM起動はレビュー待ち。

## 既存ファイルのSHA-256

| ファイル | SHA-256 |
| --- | --- |
| /usr/bin/cc、/usr/bin/gcc | 1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26 |
| /usr/include/linux/bpf.h | 69f6566ab51435fc497fe38832d6429abbf9c4b3ee1b15ac34307e496dc7ee4d |
| /usr/include/linux/filter.h | aeb1560f02eff26dfea4ad4596d77c05d2bad3eab87cf3dd5aaf6b64ad2f5053 |
| /usr/lib/x86_64-linux-gnu/libbpf.so.1 | 0e9998e17e38d78e5ce953f89a5e6a7c8b457d3e1bfe71e3ec5a1cfb05bbd1c3 |

libbpfのruntime共有ライブラリはあるが、標準include位置に開発ヘッダがなく、PATH上にclang/llcはない。bpftoolの実体は既存metadataに記録済み。
