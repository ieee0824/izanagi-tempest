# 新capture large control 001 草案（未実行）

room16885に従い、旧large001の29回×1MiB、2CPU/4GiB、sandbox_execのmock call1回、expect completed、retestなし、正式比較対象外を維持する。旧large001の失敗を再認定しない。新root `/var/lib/tempest-izanagi-capture-large-001`、unit `tempest-izanagi-capture-large-001.service` を予定する。

## Source / binary / image binding

hostは[build002](LINUX_X86_HOST_CLI_002_RESULT.json)のfixed source fa3f1d9/new binary SHA `4f66f0bd2fca5e98490440c9069da26630c331d9dd56a26dd808c24f1603549d`を使う。runtime driverは既存 `integration/runtime_delivery_race.py --expect completed --large-evidence` の生成負荷を維持する。

imageは現在build中の `/var/lib/tempest-izanagi-capture-build-001/work/output-debian/debian-x86_64.qcow2` を候補とする。実image SHAは未確定であり、旧SHAを代入しない。完成collectorとoffline installed bytes/source/metadata/native artifact結果の監査後にのみ固定する。guestはsource0656333、release SHA3bc9fd0a…、要求buffer16MiB/immediate/-U/全loopback/drop検査のまま。

新snapshot source集合はruntime driver、専用observer、bootstrap observe/record_exit、transport/host_bridge/artifact_evidence、呼出しsource、host build provenance、新image build/offline provenance、旧large001失敗RESULTとhardlink物理例外追補を含む。新observerは既存runtime validatorへ固定root/unit/1stageだけ追加するか、固定root置換版をsnapshotする案をレビューする。既存profileを変更しない。新image SHA未確定の間はsnapshot作成入口を公開・実行しない。

## 具体caller argv

[run_once.py草案](evidence/capture-large-001/run_once.py)のCOMMANDを正とする。新root以外の旧large001条件を維持する。Typeexec/UID-GIDtempest-kvm+kvm、RuntimeMax1800/Stop10、KillModecontrol-group/SendSIGKILLyes/Restartno/UMask0077/NNP/Delegateno、ExecStopPost固定、env-i、専用HOME/TMPDIR、固定venvPython-I-B。

```text
ROOT/inputs/python/bin/python -I -B ROOT/inputs/repo/integration/runtime_delivery_race.py
  --tempest ROOT/inputs/tempest --izanagi ROOT/inputs/izanagi
  --image ROOT/inputs/image.qcow2 --image-inputs ROOT/inputs/build-inputs.json
  --python ROOT/inputs/python/bin/python --runs ROOT/work/runs
  --expect completed --large-evidence
```

ROOTは新rootの絶対path。driver内host timeout720秒とunit1800秒を維持。hostのfile予算はmin(600秒,30秒+ceil(bytes/32768)×250ms)、collection全体600秒の絶対期限。進捗で延長しない。32KiB wire/fixed reply/file上限を維持する。これはRPC待ち/次fetch開始の期限で、同期write/fsync/renameのhard cap保証ではない。

snapshot容量は旧large001と同じcopy前10GiB/後8GiBを仮条件とし、image完成後に実サイズで再審査する。root988/dir750/file440-550、work9999880700、UID空/unusedunit/出力不在/KVM検査を行う。

## Collectorの旧large001からの差分

- caller/observer/Invocation/boot/1stage PID-starttime-bindingは新実測で固定。実handlesを終端まで追跡し、GCunknownを独立trusted終了と区別する。
- 元large001はaborted/partial/expect completed未達のまま。新runはcompleted/evaluation performedを要求し、生成scenarioの29×1MiB、1 agent call、無retest/formaleligiblefalseを再照合する。
- manifestはnative finalized/complete、drop0/read_failedfalse、API29/incomplete0、recorder counter各error0を要求。buffer requested16384は実割当保証と区別する。forced reader/moved包含/freeze>0/descendants emptyと単回export同hostID回復も照合する。
- manifest→API→PCAPの収集順を固定host source/provenanceで束縛し、3fileが実際に保持され各実長/SHAとcollection receiptが一致することを確認する。mtime順は補助証拠として保存し、auditにfile識別子がない場合は実fetch順を直接観測したと誤認しない。
- PCAP56〜64MiB/API29の負荷gate、collection.complete、manifest.completeとrunのexport.complete、runtime control integrity/embedded intentを個別に確認する。native completeを配送成功だけで推定しない。
- fetch auditのstarted/completed/read countersとtimestamp幅、sizeから算定した絶対予算を保存。fetch terminal欠測/期限超過/receipt false/partial cleanupは失敗証拠として保持し、後付けの期待値変更・同run retryはしない。
- management_stoppedを含むcleanup receiptと実UID/cgroup/port回収を別記する。falseを実資源回収からtrueへ読み替えない。inventory complete/key不在、旧証拠のcontent/owner-mode、hardlink追補で許可された物理identity例外を確認する。

この草案時点では新image SHA未確定、new snapshot/observer/runtime VM/collector実行はすべて未開始。image build後のoffline照合結果と本案sourceをレビューしてから進む。

## image監査後の具体source（まだ未実行）

room16895で新imageとoffline結果の監査を受け、実image SHAを `b46a44433488b067db24940e4a7231604628f35403517856a3c84f01939c65df` に固定した。前段の「未確定」は草案時点の履歴である。

[prepare](evidence/capture-large-001/prepare_snapshot.py)は新host002-v2、新capture image/build/offline/native、新guestbuild、旧失敗RESULT、hardlink追補を入力へcopyする。旧RAW削除例外は旧delivery-race-build001の正確pathのまま保持する。旧証拠・seed-loss全treeは従来verifier prefixで検査し、hardlink8pathの許可済みinode/nlink8も確認。image10GiB/8GiB条件はfresh測定する。

[専用observer](../integration/capture_large_observe.py)は元runtime validatorの専用コピーで、新 `capture-large` profileだけが新root/unit/1stageを指す。既存runtime observerは変更していない。元14テストを新moduleへ適用して全成功し、新profileのstage pathも確認した。

```sh
sudo -n /usr/bin/python3 -I -B docs/evidence/capture-large-001/prepare_snapshot.py
sudo -n /usr/sbin/runuser -u tempest-kvm -- /usr/bin/python3 -I -B - < docs/evidence/capture-large-001/check_preparation.py
# snapshot/UID結果と直前検査の監査後だけ、以下を実行する。
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-capture-large-001/inputs/repo/integration/capture_large_observe.py --trial capture-large --output /tmp/tempest-capture-large-observation-001.jsonl
python3 -I -B docs/evidence/capture-large-001/run_once.py
```

[UID検査](evidence/capture-large-001/check_preparation.py)は全hash/owner-mode/read可write不可/Python crypto AES/runtime help/xattr/offline native binding/newhost SHAを確認する。[collector](evidence/capture-large-001/collect_result.py)は保存証拠だけを読み、実測Invocation・caller/observer handleと終了コードを引数で受ける。completed未達時には成功投影を保存せず、元runを失敗証拠として保持する。observer0の同Invocation終端とobserver1のGC欠測を区別する。3receipt/実PCAP読取、2CPU4G/29curl/1MiB/1call/無retest、manifest drop0と16384KiB要求、intent/transitionとexport回復、cleanup receiptと実資源回収、trusted journalを照合する。

source集合と実SHAは [source catalog](LINUX_X86_CAPTURE_LARGE_SOURCE_001.json) に固定した。各sourceはPython構文確認済みだが、snapshot/UID検査/collectorの本番実行は未実施。review後にsnapshot準備のみへ進む。
