# Image hardlink統合の固定allowlist案（未実行）

room16869のcanonicalは `image-smoke-002/inputs/image.qcow2`。置換候補はimage-smoke-001、image-smoke-001-v2、exec-exposure-001、proc-exposure-001/002/003、sidecar-001の各inputs/image.qcow2のみ。全pathのprefixは `/var/lib/tempest-izanagi-`。seed-loss、presence、normal、endpoint、fixture、元qcow2/private rawは対象外。

[8pathの実SHA検査](LINUX_X86_IMAGE_HARDLINK_PREFLIGHT_001.json)はhandle26101終端0。全てSHA5885abea…、同device、別inode、root:988/0440、regular/nlink1/xattrsなし。読み取り以外の変更なし。

## Identity依存調査

`runtime-normal-001/collect_result.py::verify_snapshot` はfile hash/mode/ownerとsymlink targetだけを比較する。exec/proc/sidecarのcollectorのsingle-link検査は `work/output/exec-evidence` 内のfileを対象とし、inputs/image.qcow2ではない。各prepare/collectorのfull-tree identity検査はruntime-seed-loss-001をreservationのbaseline.private.jsonと比較するもので、この案は両方を不変更とする。

public docs JSONのcandidate pathに付随するinode/ctime/nlink依存は先行調査で見つからなかった。ただし全private metadataの依存監査はまだ完了していない。この案は実行許可ではなくレビュー用である。

## Script草案と例外範囲

[apply.py](evidence/image-hardlink-001/apply.py)は固定8pathのみを開き、全parentをNOFOLLOW/root非write可能条件でFD束縛する。全候補の実SHA/owner/mode/nlink/device/xattrと元target identityを検査してから、canonicalへの一時hardlinkを各targetと同じdirectoryへ作り、実inodeを照合して原子的replaceする。directory fsyncとexclusive/private journalを各段階で保存し、部分実施後の自動再試行を拒否する。`--apply`を付けない実行は拒否する。

物理identityの例外はcanonicalのnlink/ctime、7targetのinode/nlink/ctime等と、変更した7parent directoryのmtime/ctimeを含む。元RESULTやsnapshotを後付けで書き換えない。path/bytes/SHA/owner/mode維持、全snapshot内容検査、public result参照hash、seed-loss全tree完全一致を前後で確認し、追加provenanceで例外を記録する。回収容量は旧FDを閉じた後に実測する。

草案はPython構文確認のみ実施。実mutationやblock-dedupe ioctl、新image buildは行っていない。実行前にはprivate identity依存の残監査、preservation verifierのread-only単独実行、正確なscript/source hashのレビューが必要。容量20/18GiB条件は下げない。
