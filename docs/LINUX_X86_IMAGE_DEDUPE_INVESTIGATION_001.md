# Imageコピーの容量調査（変更なし）

room16866に従い、snapshotにSHA `5885abea…` が記録された `inputs/image.qcow2` を読み取り専用で列挙した。seed-loss rootは候補・canonicalとも除外。候補は11パス、device/inode組も11、allocated合計23596412928 bytes。filesystemは `findmnt -T /var/lib` でext4 `/dev/vda1`。statfsの `ext2/ext3` 表示とは区別する。

[メタデータinventory](LINUX_X86_IMAGE_DEDUPE_INVENTORY_001.json)にpath、snapshot参照、device/inode/nlink/blocks、owner/mode、mtime/ctime、xattr値のSHAを保存した。expected image SHAはsnapshot由来で、この調査ではimage全体の再hashをまだ行っていない。public docs直下JSONでcandidate pathとidentity fieldを同じrecordに保存した記録は見つからなかったが、private inventory/全履歴のidentity監査は未完了である。

hardlink統合では各pathのbytes/hash/owner/modeを維持できても、置換対象inode・ctimeとcanonical側のnlinkが変わる。single-linkを要求する既存collectorもあるため、全旧証拠を不変と呼ぶことはできない。該当imageを扱う検査・private inventoryの依存関係と明示的な例外provenanceを先に調べる必要がある。block dedupeの実対応はまだ確認しておらず、書込ioctlによる試行も行っていない。

既存pathの置換/削除/link変更、seed-lossの変更、image buildは一切行っていない。開始前20GiB/コピー後18GiBというimage容量条件は維持する。
