# Linux x86配送競合M3 smoke001の準備案

## 状態と目的

[build001とoffline照合](LINUX_X86_DELIVERY_RACE_BUILD_001.md)の結果監査後に進める草案。
新runtime root・snapshot・VMは未作成。Packer build時のinstaller用network契約は使わない。
今回のscopeは実fixtureのforced readerを含むM3 smokeだけで、host Tempest CLIによるcompleted試験・大容量controlは別段階。

rootは`/var/lib/tempest-izanagi-delivery-race-smoke-001`、unitは`tempest-izanagi-delivery-race-smoke-001.service`。
完成image SHAは`4c2a101c929547c422ce5f7709e4d52db69dbc2032bb7408fc4a4ce16aefe236`。
新fixture manifestと[同一imageのagent/HTTP/eBPF証拠](LINUX_X86_DELIVERY_RACE_NATIVE_ARTIFACTS_001.json)を入力へコピーする。
親非fixture imageのoffline reportは流用しない。新reportは実`artifact_evidence.validate_offline`を通過済み。

## 準備と権限

[固定source SHA](LINUX_X86_DELIVERY_RACE_SMOKE_SOURCE_001.json)へ全runtime import closure、observer、準備/caller、Python lock/wheels、native reportと旧証拠検証helperを束縛する。
[prepare_snapshot.py](evidence/delivery-race-smoke-001/prepare_snapshot.py)は実行前に旧証拠と完成image・source hash・UID999空・unit未使用・出力不在・KVM・pinned repoを検査する。
準備実行はrootの`/usr/bin/python3 -I -B`。入力はroot:988/dir0750/files0440（実行file0550）、workは999:988/0700。
Python venvは固定hash wheelを`--no-index --require-hashes`で新inputs内に構築する。global環境は変更しない。
実snapshot作成後に[UID999検査](evidence/delivery-race-smoke-001/check_preparation.py)をstdinから`runuser -u tempest-kvm -- /usr/bin/python3 -I -B -`へ渡す。
hash・owner・read可/write不可・外部runtime・固定Python版・AESGCM roundtrip・import/help・native report binding・xattr・出力不在だけを検査し、この段階ではVMを起動しない。

容量はcopy前12GiB以上、copy後10GiB以上を準備条件とする。image約2.05GBとPython/sourceをコピーし、runtimeのsnapshot overlayは最大4GiB相当＋logs/evidence約1GiBの仮枠を見込む。測定済みpeakの保証値ではない。
現在のoffline派生raw/partitionは保持したままでも条件を満たす見込みで、削除は行わない。容量条件を満たさない場合はpartial保持で停止する。

## 実行予定argvとobserver

具体systemd-run argvは[run_once.py](evidence/delivery-race-smoke-001/run_once.py)のCOMMANDを正とする。
Type=exec、UID/GID tempest-kvm、補助kvm、KillMode=control-group、RuntimeMaxSec=1800、TimeoutStopSec=10、SendSIGKILL=yes、Restart=no、UMask0077、NoNewPrivileges=yes、Delegate=noとする。
同unitのExecStopPostでexit statusを保存し、専用work cwd・env-iのPATH/TZ/LANG/LC_ALL/HOME/TMPDIRだけを使う。

```sh
NEW_ROOT=/var/lib/tempest-izanagi-delivery-race-smoke-001
# snapshot/UID検査と開始条件の監査後にだけ、root observerを先行する。
sudo -n /usr/bin/python3 -I -B "$NEW_ROOT/inputs/repo/integration/image_smoke_observe.py" \
  --attempt delivery-race-smoke-001 \
  --output /tmp/tempest-delivery-race-smoke-observation-001.jsonl
# 別handleで一度だけ実行する（上記をshellで直列実行しない）。
python3 -I -B docs/evidence/delivery-race-smoke-001/run_once.py
```

callerはsnapshot内Pythonで`integration/image_smoke.py --exec-evidence --delivery-race-fixture`と固定izanagi/image/build-inputs/offline-artifacts/outputを渡す。
実モデル・OAuth・実AWSは使わず、local LWS/dummyのみ。通常runtimeのrestrict/snapshot/readonly/share条件と単一QEMU PID/starttime/cwdを既存validatorで検査する。
observerへ新attemptの固定unit/root対応だけを追加し、既存24テストは成功した。runtime policy自体は変更していない。

## 期待値・保存範囲

同export IDの認証済み結果を回収し、operation submission 1回、forced readerのexecution_errorとforced_reader_pidがquiesce.moved_pidsへ入ったことを要求する。
complete export、service freeze/descendants_empty、必須M3権限・隔離・実trace・artifact bindingとprivate execの保存中scanを検査する。
caller/observerの同handleを終端まで追い、同Invocation trusted終了、UID/cgroup/ports回収、全入力と既存証拠不変を保存する。
GC終端欠測はunknownのまま独立証拠と分離し、失敗時partialを保存して自動retryしない。結果監査後の鍵cleanupは別記する。
