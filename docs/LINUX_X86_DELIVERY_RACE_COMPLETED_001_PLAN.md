# Linux x86固定host CLI配送競合completed001案

## 後続の実行結果

room16827監査後、固定callerは終了コード0、独立collectorも終了コード0。[実測結果と限界](LINUX_X86_DELIVERY_RACE_COMPLETED_001.md)を参照する。
以下は準備段階の記録であり、各「未実施」「未作成」はその時点を表す。大容量controlは引き続き未実施。

## 後続の準備結果

room16824のsource/argv/容量監査後、prepare9846とUID check48780は各同handleで終了コード0。
[実snapshot](LINUX_X86_DELIVERY_RACE_COMPLETED_SNAPSHOT_001.json)は1310項目、canonical tree `142c805897a670b3b4a2fa262becbb964aa9e46c011070f0816e831464b084f9`。
[準備検査結果](LINUX_X86_DELIVERY_RACE_COMPLETED_PREPARATION_001.json)へhash/owner-mode/nonwrite、固定Python/AES/import-help、固定host CLI help/scenario validate、artifact binding/xattrと出力不在を保存した。
181 directoryはroot:988/0750、work/home/tmp/evidenceは999:988/0700。copy後free10461425664 bytesで8GiB条件を満たし、UID検査後も専用UIDプロセスとruns/exit recordは不在。
19固定source/data・外部runtime・旧入力/結果は不変で、raw/partitionも保持した。新root/snapshotだけを作成し、run_once・VMは未実行。
以下は草案時点の記録であり、各「未作成」はその時点を表す。

## 状態と対象

room16819/16821に従う具体案。新root・snapshot・VMは未作成で、この試験は未実施。
[M3 smoke001](LINUX_X86_DELIVERY_RACE_SMOKE_001.md)の結果はroom16821で受理され、専用鍵cleanupも別記した。
次は固定host Tempest CLIを実管理MCP経路で使い、競合回復後のcompletedとfresh retest・cleanupを確認する。大容量controlは含めない。

- root/unit: `/var/lib/tempest-izanagi-delivery-race-completed-001` / `tempest-izanagi-delivery-race-completed-001.service`
- 完成fixture image SHA: `4c2a101c929547c422ce5f7709e4d52db69dbc2032bb7408fc4a4ce16aefe236`
- 固定host Tempest CLI SHA: `4354c40b7fba68ec03e4cbb8cd1407ce3ba7566816801b69dec09d85a984dc6f`
- 固定Izanagi CLI SHA: `088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8`

host CLIは[既存buildの結果とsource provenance](LINUX_X86_HOST_CLI_001_RESULT.json)を検証し、binaryとその記録を入力へコピーする。現HEADから再buildしたとは扱わず、現Rust source全体の一致を偽って要求しない。
fixture image・guest compile metadata・native reportも新inputsへ固定する。既存1314smoke入力・原本・raw/partitionは変更しない。

## Snapshotと専用UID検査

[prepare_snapshot.py](evidence/delivery-race-completed-001/prepare_snapshot.py)は[固定source/data SHA](LINUX_X86_DELIVERY_RACE_COMPLETED_SOURCE_001.json)、旧証拠、smokeのsnapshot/result/key不在、image、CLI、KVM、UID999空、unit未使用と出力不在を確認してから新rootを作る。
runtime import closureはruntime_delivery_race、host_bridge/transport、scenario、observer/bootstrap observer/exit recorderで、UIDのartifact binding用helperも含める。
新inputsはroot:988/dir0750/file0440（実行file0550）、work/home/tmp/evidenceは999:988/0700。固定hash wheelをoffline/no-indexで新venvへ導入する。

監査後の準備argvはrootの`/usr/bin/python3 -I -B docs/evidence/delivery-race-completed-001/prepare_snapshot.py`。
次に[check_preparation.py](evidence/delivery-race-completed-001/check_preparation.py)をstdinで`runuser -u tempest-kvm -- /usr/bin/python3 -I -B -`へ渡し、全入力read可/write不可/hash/owner-mode、外部runtime、固定Python版/AESGCM、runtime help、固定Tempest help/scenario validate、xattr、artifact binding、出力不在を確認する。この段階でVMは起動しない。

容量はcopy前10GiB以上・copy後8GiB以上とする。smoke後free12571164672 bytes、image2048524288 bytes＋host CLI約10.7MB＋Python/sourceをコピーした後も約10GBを見込む。
primary/retestは逐次起動とし、一時snapshot overlayの最大4GiB相当＋logs/evidence約1GiBの仮枠を用意する。これは測定済みpeakではなく準備上の余裕である。前段smokeの12/10GiB閾値を流用せず、この二段階trialの入力量・同時VM数とともに監査する。
raw/partitionを保持したまま条件を満たさない場合は停止し、自動削除・再試行はしない。

## 固定callerとobserver

具体systemd-run argvは[run_once.py](evidence/delivery-race-completed-001/run_once.py)のCOMMANDを正とする。
UID/GID tempest-kvm、補助kvm、Type=exec、RuntimeMaxSec1800/TimeoutStopSec10、KillMode=control-group、SendSIGKILL=yes、Restart=no、UMask0077、NoNewPrivileges=yes、Delegate=no、専用cwd/env-iとExecStopPostを使う。
内側は固定Pythonで`integration/runtime_delivery_race.py --expect completed`を実行し、固定tempest/izanagi/image/image-inputs/python/runsを渡す。`--large-evidence`は渡さない。
script内host runのtimeout720秒と、unit全体1800秒を区別する。失敗時も新run/root/ログを保持し、自動再実行しない。

```sh
NEW_ROOT=/var/lib/tempest-izanagi-delivery-race-completed-001
# snapshot/UID検査結果の監査後にだけ、固定observerを先行する。
sudo -n /usr/bin/python3 -I -B "$NEW_ROOT/inputs/repo/integration/runtime_normal_observe.py" \
  --trial delivery-race-completed \
  --output /tmp/tempest-delivery-race-completed-observation-001.jsonl
# 別handleで一度だけ実行する。
python3 -I -B docs/evidence/delivery-race-completed-001/run_once.py
```

observerへ追加したprofileは、`work/runs/forced-delivery-race/sandbox`→`work/runs/forced-delivery-race/retest/sandbox`の2段階だけを許可する。
既存のrestrict/snapshot/readonly-share条件、単一VM、各PID/starttime/cwd、boot nonce/session fingerprintとstage順序・入替拒否を維持する。既存observerテスト14件は成功した。
GC終端欠測でも別collectorが2 stageとbindingの完備性を確認する。GC後の既定Resultを終了成功の代用にしない。

## 期待値と保存

primary export startedは1件、実管理MCPで同要求のexecution_errorを観測してから認証済み回復し、forced_reader_pidがmoved_pidsへ入り、freeze時間が正でcomplete exportを得ることを要求する。
run.status=completed、固定scenarioのretest.configured=true/checks_passed、fresh VMの別identity/binding、primary/retest双方の正常cleanup、artifact inventory complete、transport key不在、formal_metrics_eligible=falseを確認する。
mockのcallsは空配列・最終findingsも空であり、発見能力の成功を期待値に含めない。実AWS・実モデル・OAuthは使わない。
caller/observerの同handle終端、入力・旧証拠不変、same-Invocationの独立trusted終了、UID/cgroup/全観測port回収とrun/control/export receiptsを安全な投影へ保存する。
結果監査後に別rootの大容量controlを計画する。fixtureの成功をInternet全般・本番B/MCP・全配送障害・正式比較へ一般化しない。
