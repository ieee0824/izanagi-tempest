# x86 image offline inspection 001

固定 qcow2 を再 boot せず read-only で検査した。agent は root:root / mode 0551、HTTP は 0755、eBPF は 0440。
一般 actor の agent 読取 EACCES はこの権限と整合する。3点の実体 SHA256 / ELF machine は build 入力と一致し、image.json は前回 guest 読取と一致した。

[結果](evidence/image-offline-001/report.json)、[計画](evidence/image-offline-001/plan.json)、[provenance](evidence/image-offline-001/provenance.json)、[partition table](evidence/image-offline-001/partition-table.json)、[selection](evidence/image-offline-001/partition-selection.json) を保存した。

既存 qemu-img の convert -f qcow2 -O raw と sfdisk --json を UID999 で使用した。
変換と [選別 helper](evidence/image-offline-001/select_partition.py) は同 handle の終端 exit 0 を確認した。
[抽出 helper](evidence/image-offline-001/extract_artifacts.py) は data partition 非重複、extended container 包含を検証して固定4pathの debugfs stat/dump を行った。正確な argv は結果内に保存した。
抽出 caller の終端値は回収できていない。process 不在と完成 report を確認したが exit 0 と推定していない。

元 qcow2 SHA 前後一致。抽出物は通常 file / 0600 / 非実行で、readelf の header 読取のみ実施した。
mount、debugfs write flag、VM boot、追加 package は使用していない。private binary/raw/partition は repo に含めない。
実行中 daemon の hash、実 eBPF event、HTTP sidecar 起動はこの検査では証明しない。

初回 smoke 原本を保持し、room16557 の確認後、当該 run の dummy transport key だけを削除した。
次回は actor に root-only 実体読取を要求する検査を修正し、既存 attest の実行中 agent hash を build 入力と照合する。新しい unit/root の具体計画で次回を扱う。

## 次回 smoke の検証契約

`integration/image_smoke.py --offline-artifacts REPORT.json` は image SHA256 前後、固定3path、実体 SHA256 と ELF machine を build 入力へ照合する。
report は実行前レビューした read-only snapshot の入力として含め、artifact_evidence.py も snapshot に含める。
任意の自己申告 report だけでは provenance を保証しないため、ここで保存した抽出証拠の監査と immutable snapshot が前提となる。
actor 側は3pathすべてを読み取り、EACCES だけを個別記録する。EACCES は照合済み offline 証拠がある場合のみ通過する。
それ以外の errno、欠落、読取成功時の不一致は停止する。
root-only agent への actor ldd は実施せず、未検証 path を明記する。libc package と読取可能な HTTP/LWS/guest の ldd は維持する。
claim 後は root helper の既存 attest.exe_sha256 と build 入力 agent hash の一致を要求する。
これは offline image byte 照合とは別の実行中 agent 照合であり、eBPF event probe や sidecar 起動の証明を代替しない。

検証: Python 全72件成功（専用 venv）、固定 guest snippet compile 成功。VM 再実行は未実施。

room16570 の指摘に従い provenance に残存記録由来の argv/UID/env と欠測を補足した。元 caller transcript 全体と sfdisk wrapper source は回収できておらず、独立した実行証跡とは扱わない。再変換・再抽出はしていない。

room16572 に対応し、offline profile は今回の root:root agent0551 / HTTP0755 / eBPF0440 に限定する。
actor は agent/eBPF が EACCES、HTTP が読取成功かつ hash 一致することを要求し、読取可能への拡大も拒否する。
別の権限 profile を自動推定して受け入れない。owner/mode/read結果が逆の負例を含む全73testsが成功した。
