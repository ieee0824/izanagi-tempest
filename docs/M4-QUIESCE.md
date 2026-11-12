# M4 ゲスト終了確認の実測

## 対象と範囲

#5/#13 のゲスト終了境界を、固定 Izanagi/LWS の派生 QEMU VM で確認した。
host controller・MCP admission と結合した `tempest run` は未実装であり、
この試験を #5 全体や正式なモデル評価の完了とはしない。
Sakura 投稿15170〜15176の指摘を反映した。

| 入力 | SHA-256 / 固定条件 |
|---|---|
| qcow2 | `1d8e564d72c68a39ab7e78551e73e0d6e61190fa9101596e01c53e0e00eb9e7c` |
| host Izanagi | `d7f896b71241da81e81d99e6d4f7b974f867705df5cf5ca4163e8f461632fa34` |
| guest Izanagi agent | `a35d9d16a31545a5b43101e9c082cebbdde0bc312a68270cc617612b67b88c9e` |
| Linux LWS | `aca61cb0899ecd92a1f4c324c716a7e17e9166cf07af0d084986d9973031dc37` |
| tempest-guest | `1c9ed1f98a16d9ad3c83f81a9f757c128d3a8845d15d68b088278eb77508c97c` |
| Izanagi source | `16d0b55947006a166cfa29dcb8bfe71f65f8c36a` |
| LWS source | `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` |
| 実行条件 | macOS arm64 / HVF、snapshot、read-only 9p、`restrict_network=true` |

ビルド元は `d6cbeb7` に本差分を加えた dirty tree。`inputs.json` はその状態と導出scriptのhashを記録する。
guest helper は上記の既存 Linux binary を指定したもので、新しいhostコードからの再ビルドではない。
Izanagi/LWS本体は変更せず、ローカルLWSとダミー入力だけを使用した。

## 実装した順序

1. 認可済みmailboxの `attest` で、root daemon のPID/start ticks/exe hash/systemd InvocationID/cgroupを取得する。
2. `export` は同じidentityを要求し、root helperが現在値と照合する。
3. 固定 `izanagi-agent.service` をfreezeし、kernelの `frozen=1` を有限期限で確認する。
4. 再帰的に所属を読み、MainPID以外を新しい子cgroupへ移動する。UIDや親PIDでは選別しない。
5. 子cgroupへ `cgroup.kill`、`populated=0` を確認し、親にはMainPIDのみ・全子groupにprocessなしを再確認する。
6. root consumerがserviceをfreezeしたままnative exportを実行する。確認と最終化の間に管理execを挟まない。
7. native呼出し終了後にidentityを照合してthawし、保存済み暗号文をhostが取得する。

identity不一致・freeze/kill/空確認の失敗ではnative exportを開始しない。
thaw失敗やnative結果不明も成功にしない。失敗時の通常回収・同VM再実行は認めず、callerがVMを破棄する。
helperはroot consumerからだけ起動し、公開doas entryは暗号文の取得だけを行う。
非rootのguest発TCP9001をIPv4/IPv6 OUTPUT owner規則で拒否し、hostfwdのINPUT経路を維持する。

## 観測結果

同じイメージから新規snapshotを2回起動した。run001/002とも、seed・probe・seal・GET・export・fetchの検査が完了した。

| 検査 | 結果 |
|---|---|
| 親からsetsidで独立し生存中の子 | run001 PID1321、run002 PID1320をkill対象へ移動。export後に消滅/Zを確認 |
| 誤ったstart ticks | native exportへ進まず拒否 |
| daemon freeze中のnative export | 両runでcomplete。root control/LWS/captureの処理が完了 |
| PCAP | run001 37 packets、run002 38 packets、両方drop0。2 GETと両response bodyを照合 |
| fw_cfg token/secret | UID1000でEACCES/EPERM。ENOENTは不合格。run002は同じコードで公開metadata読取を正対照にした |
| cgroup操作 | serviceのprocs/freeze/kill書込拒否。run002はroot/system.sliceの祖先への書込・新group作成も拒否 |
| root RPC | guestの127.0.0.1/::1:9001接続拒否。host管理execは動作 |
| gateway経路（run002） | host実listenerの接続成功を正対照にし、guest 10.0.2.2の9001/実hostfwd portへの接続拒否 |

固定agentの待受実装は `izanagi-agent/src/main.rs` のTCPのみであり、Unix socket待受は実装されていない。
別versionや別待受構成には一般化しない。gateway拒否には固定QEMUのnetwork restrictionも関与するため、
TCP9001 owner規則だけの効果とはしない。

## 再現・証跡

[ビルド手順](../image/README.md)で現在の導出scriptを使う。`prepare.py` は `quiesce.py` のhashも入力manifestに保存する。

```bash
python3 integration/image_smoke.py --izanagi /absolute/path/to/izanagi --image /absolute/path/to/debian-aarch64.qcow2 --build-inputs /absolute/path/to/inputs.json --output /private/tmp/tempest-quiesce-run-001
python3 -m unittest discover -s tests -v
```

私有証跡はGit外の `.m0-evidence/20261112-m4-quiesce/` に保存する。
各runのsummary、guest API/PCAP/manifest、Izanagi logs、ビルド入力manifestを照合する。
新規Python試験は、barrier失敗・identity不足でexportしないこと、native timeoutでもthawを試みること、
exportがfreeze中だけ実行されることを検査する。全18件成功。

## 未確認と後続

- 実host controllerがagent終了を明示closeへ結び、全転送RPCを収束させてからこのexportを呼ぶ結合は未実装。
- daemon再起動、kernel操作失敗/期限切れ、nested cgroup、fork競合を注入した実VM試験は残る。
- 観測した子と権限境界の検査を、全攻撃手法・別kernelの安全性証明とはしない。
- 誤identityの拒否後も観測を続けたのは検証用runの負例であり、正式runtimeの同VM復旧フローではない。
- #13 の配送・露出表、#15 の並行seed/VM破棄、#5 のmock E2Eとclock/run記録は継続する。
