# Linux x86配送競合fixture image build001

## 結果と範囲

room16800の監査後、専用root/unitで一度だけビルドした。caller34339は終了コード0、collector41386も終了コード0。
fixture runtimeは未実施であり、ビルド成功を競合再現・回復成功とは扱わない。

- [開始時検査とhandle](LINUX_X86_DELIVERY_RACE_BUILD_START_001.json)
- [ビルド終了・入力・生成物の検証](LINUX_X86_DELIVERY_RACE_BUILD_001_RESULT.json)
- [実ディスク内fixtureの読取専用照合](LINUX_X86_DELIVERY_RACE_BUILD_OFFLINE_001.json)
- [固定入力29ファイル](LINUX_X86_DELIVERY_RACE_BUILD_SNAPSHOT_001.json)

Invocationは`f5ff6db2e2714f8fa265e8e95d3399b7`、current bootは`30389abc903c40ae89a5c6268ec1c432`。
observer87131は334sampleを保存し、同一QEMU PID310225/starttime37156503と固定cwd、build専用network/storage/listener条件を検査した。
検査エラー0・外部listener観測なし。ただしunit GC後の同Invocation終端属性を取得できず終了コード1になったため、observer終端はunknownとして保持する。
独立したExecStopPostのexited0/success、PID1/root/current boot/同unit/同Invocationに束縛したStarting・Started・Deactivatedのjournalで正常終了を確認した。
専用UID999のプロセス・cgroupは不在、HTTP18082/SSH22222/VNC5902は閉じている。GC後の既定Result値を終了証拠には用いない。

生成qcow2のSHA256は`4c2a101c929547c422ce5f7709e4d52db69dbc2032bb7408fc4a4ce16aefe236`。
virtual size 4GiB、backingなし、dirty/corruptフラグなし。Packer成功とinstall security markerを保存ログで確認した。
固定29入力と外部runtime SHA、過去の入力・結果証拠・seed-loss全treeは不変。

## インストール済みfixtureの確認

offline caller59042は終了コード0。専用UID999で新生成物をsparse rawへ変換し、partition tableの境界・data非重複・logical containmentを確認して唯一のext4候補を抽出した。
debugfsを読取専用で使用し、mount・新VM起動・抽出ファイル実行は行っていない。生成元qcow2は照合前後で同SHA。

実`/etc/tempest/image.json`はfixture=trueで標準prepareの全fieldと一致し、追加installed_sha256も実抽出ファイルへ一致する。
dispatcher/mailboxは`faf0c5ae…`、quiesceは`72fabf3c…`で固定instrument後bytesと一致する。
guest native/LWSも固定binary SHAへ一致。各script/binaryはguest root:root/0755、manifestはroot:root/0644。
offline後もsnapshot directoryのroot:988/0750、UID999プロセス不在・cgroup不在を再確認した。派生raw/partitionを保持した状態の空き容量は14718812160 bytes。
後続room16834の容量確保許可で、[限定RAW cleanup追補](LINUX_X86_DELIVERY_RACE_RAW_CLEANUP_001.json)の通りdisk.rawだけを削除した。partition・qcow2・全抽出artifact・元の結果JSONは保持し、上記offline計測は削除前の歴史的記録として残す。
後続のUID999 native artifact抽出77480も終了コード0。[agent/HTTP/eBPFの別証拠](LINUX_X86_DELIVERY_RACE_NATIVE_ARTIFACTS_001.json)は同一qcow2の前後SHAと既存partition SHAを拘束し、実mode 0551/0755/0440・root:root・ELF machine 62/62/247と固定binary SHAの一致を確認する。
通常runtimeの`artifact_evidence.validate_offline`にもこの新reportを渡して成功した。親imageのreportを新SHAへ書き換えて再利用していない。
compile commit/tree/dirty等は親の固定binary provenanceを保持し、現HEADで再ビルドしたとは記録しない。
build collector時点の`installed_fixture_bytes`未検証という履歴は変更せず、後続offline JSONを追加証拠として参照する。

## 再現入口と次段階

[collector](evidence/delivery-race-build-001/collect_result.py)と[offline照合](evidence/delivery-race-build-001/offline_fixture.py)を保存した。
両者は新証拠を排他的に作成するため、既存rootで再実行しない。ビルドの再試行も行っていない。
次は[別runtime計画](LINUX_X86_DELIVERY_RACE_RUNTIME_PLAN.md)のsnapshot/source/argvを監査してから、forced-reader M3 smokeへ進む。
全期間・全argv・未知FD・Internet全般・本番モデル/MCP・正式比較の証明へ一般化しない。
