# Linux x86 delivery-race fixture build001 recipe案

## 後続結果

単発buildと読取専用offline照合は完了した。[実測結果](LINUX_X86_DELIVERY_RACE_BUILD_001.md)を参照。
以下は計画・準備時点の記録であり、各「未開始」はその時点を表す。fixture runtimeは引き続き未実施。

## 状態と範囲

現在は標準prepareと定義full validateまで完了し、room16796で固定source64f0429から新root snapshot作成・UID999事前検査だけを依頼済み。実snapshot結果は未受領であり、Packer build・VM開始は未実施。以下の草案時点の未実施記述は、その段階の記録として残す。

room16784の提案をLinux側で再計算確認したため、採用案は固定旧source＋標準prepare明示flagとする。custom pure recipeは比較検討・検査記録として保持し、実導出には使わない。

room16780の指示に基づくbuild-only草案。新root /var/lib/tempest-izanagi-delivery-race-build-001と専用unitを提案する。
まだrecipe/source監査前で、新root・定義directory・Packer build・VM起動は未実施。
既存full003 image/全入力/旧証拠は不変更。完成してもfixture runtimeやforced race実測の成功とは区別する。

## 親子provenance

親はfull003の固定definition/inputs.json・packer全定義、ISO・agent/ebpf/http/lws/guest各binary・Packer/pluginを使用する。
親image SHA5885abea1d5820d2626dbd0ba5121bb8f0c106b91a8dc879c0ad99a6f040fe7eは参照証拠であり、既存qcow2を直接書換えない。
別imageを同ISO/assetsから再buildする案。親definitionのfile集合/hash/owner/modeと元manifest SHAを束縛し、全path置換を許可差分として記録する。

親guest binaryのsource metadataはcommit7ab5d4ee98b009086d83a98320dc752c3372bf4f、tree680b42138d4a8d2b1ae2cd7db8f83721366d58ddc754ee590f3471ac0f4452c8、dirty=false。
現在のprepare.helper_sourceはtree0ba049bd57412fc0a13e319b432b9f718242150950397bdfff6bd137c349d2b1で異なる。
現在のprepareを再実行して旧guest binaryへ現在treeを付けるとsource/binary整合の意味が変わるため、そのまま実行しない。
親binaryのinput_sha/source metadataを維持し、別fixture recipe revision/instrumenter hash/親manifest hash/変更前後file hashを追加provenanceにする案を監査する。
image/prepare.py --delivery-race-fixtureと同じinstrument()を親の固定dispatcher/quiesceへ実適用し、flagだけを後付けしない。
custom recipeであることを明記し、実際にprepare CLIを実行したとは記録しない。標準prepareを使う場合は同binaryと一致するソースsnapshotを先に確保し、metadataの解決後にだけ進む。

## instrumentationのメモリ内確認

新fileを作らず、親固定sourceへ現instrumenterを適用しPython構文を確認した。source差分の実受入やbuild成功ではない。

|対象|親SHA256|fixture SHA256|
|---|---|---|
|dispatcher.py|2c785fa2d24841ed00e5807604343e31e9409c5b7ae9855d0e0adf5449622b09|faf0c5aef7e5ae7600e77c88df61d84edad6b3cdd39e5b765e65d7a96972e1b9|
|quiesce.py|34cbc78cfec3caedac52bcaa747df62342383612ee5f3f9aab9ab02bac5cb8b0|72fabf3ce527257ab2bb5fb8cb3b8a8ef7e706ff2715b29e5b7c0857bf5390a8|

instrumenter SHA562a44539935b975f3c9b1eba8e141579d12c5791d62206163578f4ddf170dc6。
実root deliver PIDをservice cgroup内で保持し、quiesceが同requestのreaderを待ってfreeze/kill証拠へ記録するfixtureである。通常imageへこの待機を入れない。
派生image.json/inputs.jsonはdelivery_race_fixture=trueと実dispatcher/quiesce/instrumenter derivation SHAを持ち、親非fixture metadataも別に保持する。

## build-only準備条件

親fileの不変照合→新definition導出と許可差分/manifest照合→既存Packer1.15.0/plugin1.1.8 full validate→新root snapshot/専用UID検査→正確argv/容量/未使用unit監査の順。
root/inputs0750・入力0440/実行0550、UID999:GID988/kvm993のwork0700/env-i、有限runtime/同unit回収を維持する。
installerのbuild時network/loopback HTTP・SSH・VNC条件は親full003と同じbuild-only契約として別監査し、runtimeのrestrict=on受入と混同しない。
旧bootstrap/full001002003と後続全runtime証拠・鍵不在を保持する。2026-11-18の調査時free23387729920 bytesであり、snapshotコピー/ISO/一時disk/完成image/失敗ログを含む必要容量を具体的に見積もってから開始条件を固定する。
新unit/port/serial/debug/output未使用、owner/nonwrite/hash、ELF/loader/GLIBC親同一、実QEMUcwd/単一VM/build listenerを観測する。
失敗時は当該unitだけ回収しpartialを保持、暗黙retryや既存root再利用をしない。
生成物hash/format/backingなし/明示fixture manifest/provenanceと同Invocation trusted終了・cgroup/UID/port回収を保存し、結果監査後に別runtime計画へ進む。

## 純粋recipeと容量の具体化

[derive.py](evidence/delivery-race-build-001/derive.py)は受け取った親file bytesを変更せずchild bytesを返す草案で、filesystem公開/CLI build入口をまだ持たない。
固定親script/instrumenter/変換後SHAをassertし、変更対象6file以外を拒否、元compile metadata/input SHAを保持する。
追加fixture-provenance.jsonとguestへ渡すimage.json/host inputs.jsonへ同じ親manifest/file SHA・recipe revisionを束縛する。
実親定義16fileでメモリ内導出を確認し、child17file/変更6file、compile metadata/ISO/全binary SHA維持を確認した。recipe revisionはこの非保存検査では明示placeholderを使い、実行済みsource revisionと偽っていない。
正負2testsで実instrumenter適用・無関係file不変と、改変親/既fixture/偽compile情報/誤binary path/instrumenter差分/不正revisionの拒否を確認した。

親全26input合計915586311 bytes（定義53000 bytes）、親生成image2145124352 bytes、virtual diskは4294967296 bytes。
調査時free23387049984 bytes。新input約0.916GB＋4GiB diskを3個分（installer/変換/完成の保守的仮枠）＋log/partial/margin各1GiBを見込むと約16GiB以内だが、実Packer temp使用量の保証値ではない。
開始案はcopy前free20GiB以上/copy後18GiB以上を要求し、実templateのdisk_size・temp/output配置と正確argvを次監査で固定する。
旧証拠削除や旧image再利用で容量を空けず、不足時は開始しない。新root/build/VMは未開始。

## 採用案: clean旧sourceから標準prepareを実行

Linux git object7ab5d4ee98b009086d83a98320dc752c3372bf4fの93fileを同算法で再計算しtree680b42138d4a8d2b1ae2cd7db8f83721366d58ddc754ee590f3471ac0f4452c8を確認した。image6fileも現在版と全bytes一致。
専用detached worktree /tmp/tempest-delivery-race-source-001を同commitで作成し、clean/helper_source dirty=false・同treeを確認した。これはsource snapshotだけで、新definition/root/build/VM作成ではない。
/tmp/tempest-delivery-race-definition-001は未作成を確認済み。監査後に実行する具体標準prepare案は以下。

```sh
sudo -n /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \
  GIT_CONFIG_VALUE_0=/tmp/tempest-delivery-race-source-001 \
  /usr/bin/python3 -E -s -B /tmp/tempest-delivery-race-source-001/image/prepare.py \
  --architecture x86_64 --delivery-race-fixture \
  --izanagi-source /tmp/tempest-izanagi-upstream-review \
  --lws-source /tmp/tempest-lws-upstream-review \
  --iso /var/lib/tempest-izanagi-full-build-003/inputs/base.iso \
  --agent /var/lib/tempest-izanagi-full-build-003/inputs/agent \
  --ebpf /var/lib/tempest-izanagi-full-build-003/inputs/ebpf \
  --http /var/lib/tempest-izanagi-full-build-003/inputs/http \
  --lws /var/lib/tempest-izanagi-full-build-003/inputs/lws \
  --guest /var/lib/tempest-izanagi-full-build-003/inputs/guest \
  --output /tmp/tempest-delivery-race-definition-001
```

rootは親の固定0440入力を読むためだけに用い、git safe.directoryはこのsource1pathだけを当該process環境へ指定する。user/global git設定を書換えない。
Python -E/-sと空環境を使い、script directory内の固定x86/instrument helper importを維持する。
入力binary・ISO SHA/ELFは親固定snapshotへ一致、guest source commit/tree/dirty/versionも親と一致することを要求する。
許可metadata差分はbuilt_at、delivery_race_fixture false→true、実instrumenter/dispatcher/quiesceのderivation SHA、出力/入力path移設と対応template SHAだけ。元compile情報の書換えは禁止。
標準prepare出力をsnapshot新rootへ束縛する際のpath置換/元manifest SHAと、親inputs/image.json hash・全file hashを別provenanceへ記録する。
実prepare・新definition/root/build/VMはまだ未開始。command/source/許可差分の監査後に定義作成とfull validateだけへ進む。

## 標準prepareと定義full validate結果

room16788監査後、同じ空環境で固定3repoのpinned/cleanを確認し、process-local safe.directoryをその3pathだけ指定した。global設定は変更していない。
free20GiB以上・新output不在・旧full001002003 inputs/結果参照file不変と旧endpoint鍵不在を確認後、標準prepare74232が同handle終端exit0。
[正確argv/env/UID記録](LINUX_X86_DELIVERY_RACE_PREPARE_001.json)と[定義16file hash/owner/mode・full validate記録](LINUX_X86_DELIVERY_RACE_DEFINITION_001.json)を保存した。
親compile commit/tree/dirty/version/全binary SHA/ISO/pinned上流commit/architectureは新inputs.jsonとguest image.jsonに一致。fixture=true、実instrument後2scriptとinstrumenter SHA、template SHAを照合した。
親inputsからのmetadata差分はbuilt_at/delivery_race_fixture/derivation_sha256と、親snapshot由来source_manifest_sha256の除去だけ。親manifest実SHAは別provenanceへ保存した。
新definitionだけroot:988/dir0750/file0440へ固定した。固定親Packer/plugin、UID999/env-i/HOME=/nonexistentでfull validate exit0、configuration valid。plugin init/downloadなし。
実prepare argvのGit trustは固定3pathを当該process環境へ限定した。旧source/worktreeや既存imageは変更していない。
ここまで新/tmp定義作成だけで、新/var/lib実験root・Packer build・VMは未開始。次は定義結果監査とbuild-only snapshot/caller/observerの具体計画へ進む。

## build専用observer草案

room16789に従い[build専用observer](../integration/delivery_race_build_observe.py)を用意した。runtime validate_qemu_policyとは分離する。
専用unit tempest-izanagi-delivery-race-build-001.service、新root/work cwd、入力base.isoと新output-debian/debian-x86_64.qcow2、単一QEMU PID/starttimeの全sample一致を要求し、逐次入替も拒否する。
親実観測のinstaller用usernet/SSH127.0.0.1:22222/VNC127.0.0.1:2とHTTP127.0.0.1:18082だけを許可する。runtime restrict/snapshot/9pの代用ではない。
QEMU所有SSH/VNC listenerとunit内HTTPを分け、未知endpoint/外部listener/別cwd/別ISO/diskを拒否する。異常sampleも固定error metadata付きで保存し、GC終端unknownは独立終了証拠と区別する。
3testsで正規build契約、逐次PID/starttime置換と誤入力/ネットワーク/所有者を検査して成功。実observer・build・VMは未実行。

## snapshot/caller/service草案とcompile実値追補

[9compile field実値・親wrapper値・derivation/fixture値](LINUX_X86_DELIVERY_RACE_COMPILE_BINDING_001.json)を保存した。親source_manifest_sha256 fieldの値も参照可能な形で保持する。
[snapshot作成草案](evidence/delivery-race-build-001/prepare_snapshot.py)は旧全入力/結果・鍵不在・source hash・20GiB容量・未使用unit/UID/KVMをroot作成前に照合する。
新rootへの入力コピー後、templateの3固定input path、varsの3artifact path、host manifestの5asset path/template SHAだけを新inputsへ束縛する。guest image.jsonは標準生成bytesを不変更とし、親・標準生成manifest SHAとpath許可差分は別provenance.jsonに記録する。
全入力root:988/dir0750/file0440（Packer/pluginのみ0550）、work/home/tmp/cache/evidenceはUID999:GID988/0700に固定し、copy後free18GiBを要求する。
外部Python/QEMU/qemu-img/systemctl/ss/loader/libcの実hashもsnapshotへ保存する。
[UID検査草案](evidence/delivery-race-build-001/check_preparation.py)は全hash/owner/mode/read可write不可・外部runtime・新output/log不在を照合し、snapshot内Packer/pluginのfull validateだけを行う。
[caller草案](evidence/delivery-race-build-001/run_once.py)と[service草案](../integration/tempest-izanagi-delivery-race-build-001.service)は同一ExecStart、RuntimeMax3600/Stop10/KillModecontrol-group/Restartno/NNP/Delegate=no/UMask0077を指定する。
固定env-iのHOME/TMPDIR/cache/plugin/PACKER_LOGは新work/inputs内だけ、build -color=false -on-error=abort -var-file=新定義vars 新定義hclを一度実行する。
ExecStopPostの同Invocation終了記録も新work/evidenceへ固定する。標準prepare/定義fullvalidate済みと、まだ未作成のbuild snapshot/実buildを混同しない。
[監査用source hash](LINUX_X86_DELIVERY_RACE_BUILD_SOURCE_001.json)をroot作成前に完全一致要求する。source/caller/service構文・verifyを確認した。まだ草案を実行せず、新/var/lib root・build・VMは未開始。

[親003の正規化live profile](LINUX_X86_DELIVERY_RACE_PARENT_PROFILE_001.json)を添付した。保存observer fileの実SHA/行番号/時刻と、選別network/storage argv・unit内listener subsetだけを記録する。
旧sample自体にはstarttime/cwd fieldがないためnullを保持し、後から測定した値で補わない。新observerのPID/starttime/cwd拘束は新buildでの別測定条件である。
全argvや全期間の保証ではなく、既存親003結果を変更しない。

## build-only snapshotとUID検査結果

room16796監査後、serial名をinstaller-serial.logへ修正した64f0429を含むsource57266aaからsnapshotだけを作成した。
[29入力snapshot](LINUX_X86_DELIVERY_RACE_BUILD_SNAPSHOT_001.json)と[専用UID/full validate結果](LINUX_X86_DELIVERY_RACE_BUILD_PREPARATION_001.json)を保存した。
prepare30932/UID6545は同handle終端exit0。canonical tree34e665e1af93a02a1f3a9e2e049cb29d0d947f49a7e4006e6c2968d04c38dc87。
root/inputs0:988/0750、通常入力0440・Packer/plugin0550、専用work700、全hash/owner/mode/read可write不可と外部binary SHA一致を確認した。
入力pathの許可置換/新template SHA/元manifest SHAをsnapshot provenanceへ保存し、guest image.jsonは標準生成bytesと同一。9compile fieldも親と同一。
snapshot内固定Packer/plugin・UID999/env-iでfull validate exit0。新output-debian/debug/installer-serial/exit/log不在、build/VMは未開始。
copy後空き22467149824 bytesで18GiB条件を満たす。旧full/runtime入力・RESULT参照証拠・鍵不在/seed-loss全treeをprepare時照合した。
実build前に正確argv/observer/入力treeの最終監査と、容量/未使用unit/UID/3port・出力不在/旧証拠不変を再確認する。現時点でrun_onceは未実行。
