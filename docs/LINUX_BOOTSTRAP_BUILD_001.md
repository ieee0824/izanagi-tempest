# bootstrap build 001: partition仮定による失敗

2026-11-18、room #16369の監査指示後に固定commandを1回実行しました。
完成imageは得られていません。再実行・fallback・probe起動は行っていません。

## 開始と観測

開始前に全13入力hash/mode、未使用unit・固定3port空き・output未存在を再確認しました。
observer session47351を先に開始し、build session98472を開始しました。
unitは`tempest-izanagi-bootstrap-build-001.service`、InvocationIDは
`f693ebfa3a97469f9fdf42b5242a9c5f`、cgroupは
`/system.slice/tempest-izanagi-bootstrap-build-001.service`です。

QEMU起動後、実HTTP/SSH/VNCは127.0.0.1:18081/22221/5901でした。
実network引数は`-vnc 127.0.0.1:1`と
`-netdev user,id=user.0,hostfwd=tcp:127.0.0.1:22221-:22`です。
観測322sample（10:11:53.809151〜10:17:23.139670 UTC）で非loopback listenは検出しませんでした。
1秒samplingなので短時間socketの全網羅を主張しません。

## 失敗の直接証拠

PackerがSSH待ちの間にVNC framebufferを読取専用で取得しました。
keyboard/mouse操作は行っていません。画面はAlpine installがsystemを`/dev/vda2`、
`/boot`を`/dev/vda1`へ配置して完了した後、
`mount: mounting /dev/vda3 on /mnt failed: No such file or directory`を表示していました。
固定上流`packer/http/setup.sh`は`set -e`で`mount /dev/vda3 /mnt`を行います。
このpartition仮定の不一致で停止し、以降のSSH設定とrebootに到達しない状態でした。
guest-bootstrap helper、agent配置、最終lock-down/verifyには未到達です。

## 停止と回収

固定unitへ`systemctl stop --no-block`を発行しました。
build clientはexit1、observerはexit0（観測正常終了）です。
最終sampleは同InvocationID、ActiveState/SubState=failed、Result=exit-code、
ExecMainCode=1、ExecMainStatus=1、cgroup PID空でした。
Packerはcancelled、service runtimeは5min15.681sです。
観測終了後にもcgroup不在、UID999残留なし、3port閉鎖、全13入力hash不変を独立確認しました。
observer exit0をimage成功と解釈しません。

## 保持証拠

raw証拠はprivateのまま保持し、公開repositoryには要約とhashのみ記録します。

| 証拠 | SHA256 |
| --- | --- |
| /tmp/tempest-bootstrap-build-001.log | 1d738e0909f33b18ab2b6165e7a2ddeb2a789eaaf364c323f4cda1fa27e1f36c |
| /tmp/tempest-bootstrap-build-observation-001.jsonl | 2d2a845a456d5f30065d61afa89eff06c7c77e168cbb950821bfa81ba7147e38 |
| /tmp/tempest-bootstrap-console-001.png | f52de90991cca926e6059a9c312c775e9efc60f22ecf8aa17b31b5c5fa7abbf5 |
| work/output-x86_64/alpine-x86_64.qcow2（途中image） | 70b4e42be525bae8a6730e6071173d89efa607487800c9e82ecbdbef529549ee |

途中imageは98,631,680 bytesで、成功入力として使用しません。
unit reset、途中image/log削除は行っていません。

次は固定ISOのpartition構成と上流setupの仮定を照合し、上流source不変更の派生差分を監査します。
修正後も新しい入力hash・出力・unit名・具体commandで再監査し、無断で再buildしません。

## 停止後のread-only照合と修正準備

固定answersは`DISKOPTS="-m sys -s 0 /dev/vda"`でswapなしです。
停止済みqcow2から専用userの`qemu-img dd`で先頭1MiBを別fileへ読み出しました。
MBR署名55aa、partition1はtype83/start2048/614400 sectors、partition2は
type83/start616448/3577856 sectors、partition3/4はtype0/start0/size0でした。
先頭1MiB SHA256は`ef1c26e292db2204f44d9569e717c81b4575fc0f46c17af03bd21eed69918e93`です。
これも画面のboot=vda1/root=vda2と整合します。host mountや再起動は行っていません。

生成器で派生setupのみを変更し、vda2 block存在・vda3不在を要求してからvda2をmount、
mount後にalpine-releaseとetc/sshの存在を確認する差分を準備しました。
元source/旧snapshot/途中imageは変更せず、manifestには元setup hashと派生setup hashを別記します。
派生setup SHA256は`bc345d9f3d21db0385d60df0ae4ac73ec669a4f0d5242eba97934aa49e382de9`です。
定義003の生成、`sh -n`、固定pluginでのfull Packer validateが成功しました。
修正のguest内実行は未確認であり、再buildはしていません。
