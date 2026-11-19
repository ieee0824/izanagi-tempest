# 新capture fixture image build 001 のsnapshot草案

room16879に従い、既存delivery-race-build001と同じinstaller/build-only契約で、新root `/var/lib/tempest-izanagi-capture-build-001` とunit `tempest-izanagi-capture-build-001.service` を使う。以下はレビュー用で、snapshot/UID検査/build/新VMはいずれも未実行。

## 固定入力とprovenance

[標準定義](LINUX_X86_CAPTURE_DEFINITION_001.json)の全16fileとowner/mode/SHA、source `06563333e895924fb0b3892dfd1213a5285eb33f`、新guest SHA `3bc9fd0a…`、[9 compile値](LINUX_X86_CAPTURE_COMPILE_BINDING_001.json)を新snapshotへ束縛する。旧ISO/agent/eBPF/HTTP/LWS/Packer/pluginはfull003の実SHAを再検証しcopyする。guestだけ新artifactをcopyする。新guestのsourceを旧fixtureと同じだったとは扱わない。

[prepare_snapshot.py](evidence/capture-build-001/prepare_snapshot.py)はcopy前20GiB以上・後18GiB以上、UID999空・unit未使用・KVM、旧入力/結果/seed-loss全treeを確認する。[hardlink追補](LINUX_X86_IMAGE_HARDLINK_001_RESULT.json)をSHAでprovenanceへ含め、8pathの許可済みinode/nlink8も再検証する。原本RESULT/snapshotは書き換えない。

入力はroot:988/0440（Packer/plugin実行file0550）、dir0750。work/home/tmp/cache/evidenceは999:988/0700。定義inputs.jsonへ標準prepare元manifest SHAを残す。

Path置換はtemplate内full003 inputs prefixの2箇所（ISO/LWS）と新artifact guest pathの1箇所、pkrvarsのagent/eBPF/HTTP3値、manifestの5asset pathとtemplate SHAだけ。image.jsonのcompile metadataはbytes不変。実instrument後dispatcher/quiesceとderivation SHAは標準定義へ一致させる。

## レビュー後の準備argv

```sh
sudo -n /usr/bin/python3 -I -B docs/evidence/capture-build-001/prepare_snapshot.py
# rootが固定sourceをstdin経由で専用UIDへ渡す。例示であり未実行。
sudo -n /usr/sbin/runuser -u tempest-kvm -- /usr/bin/python3 -I -B - < docs/evidence/capture-build-001/check_preparation.py
```

[UID検査](evidence/capture-build-001/check_preparation.py)は全inputのSHA/owner-mode/singlelink/read可write不可、external runtime、work所有者、未使用outputを確認し、新snapshot内Packerでfull validateのみ行う。snapshot sourceと実UID結果のレビュー後に単発buildへ進む。

## Caller / observer

[run_once.py](evidence/capture-build-001/run_once.py)のCOMMANDを正確argvとする。Typeexec、UID/GID tempest-kvm＋kvm、RuntimeMax3600/Stop10、KillModecontrol-group、SendSIGKILLyes、Restartno、UMask0077、NoNewPrivilegesyes、Delegateno、ExecStopPost固定記録、env-iと専用HOME/TMP/cache/plugin/logを維持する。caller logはexclusive0600。

[build-only observer](../integration/capture_build_observe.py)は固定snapshotへcopyして先行起動する。QEMUは一つだけ・PID/starttime/cwd固定、ディスクとISO固定、installer HTTP127.0.0.1:18082/SSH22222/VNC5902だけを許可する。runtime restrict契約とは別。既存build observerの3検査（正常identity持続、逐次入替/欠測拒否、異cwd/ISO/disk/network/listener-owner/external拒否）を新observerへ適用して全成功。

```sh
sudo -n /usr/bin/python3 -I -B /var/lib/tempest-izanagi-capture-build-001/inputs/repo/integration/capture_build_observe.py --output /tmp/tempest-capture-build-observation-001.jsonl
python3 -I -B docs/evidence/capture-build-001/run_once.py
```

上記build argvはまだ未実行。caller/observerの同handleを終端まで追い、GC terminal unknownは独立trusted終了と区別する。失敗原本を保持し自動再試行しない。完成qcow2の実SHA/ELF-installed metadata/新guest sourceとbinary/fixture scriptsのoffline照合は別gate。
