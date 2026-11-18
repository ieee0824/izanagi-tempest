# #65 新guestによるfixture定義 001

room16870に従い、固定source `06563333e895924fb0b3892dfd1213a5285eb33f` のclean detached worktreeと、新release guestの実SHA `3bc9fd0a…` を照合した。新artifact `/tmp/tempest-capture-artifacts-001/guest` はroot:988/0550、directoryは0750。

標準prepareの `--architecture x86_64 --delivery-race-fixture` で新 `/tmp/tempest-capture-definition-001` のみ導出し、exit0。[正確argv/env](LINUX_X86_CAPTURE_PREPARE_001.json)にprocess-localな3 safe.directoryと旧固定ISO/agent/eBPF/HTTP/LWS、新guestのpathを保存した。global git設定は変更していない。

[定義検証](LINUX_X86_CAPTURE_DEFINITION_001.json)では、新source commit/helper tree/dirty=false、新guest実SHA、全asset実SHA、inputsとimage metadata一致、実instrument後dispatcher/quiesce bytes、各derivation SHAを照合した。旧full003固定入力のSHAを再検証し、定義全fileをroot:988/0440、directoryを0750へ固定した。

固定旧Packer/pluginとUID999/GID988、空環境でfull validateはexit0（`The configuration is valid.`）。plugin init/downloadなし。実validate argv/envと定義全file hash/owner/modeを保存した。

新guest/source metadataの導出であり、旧fixtureのsourceを後付け変更したものではない。新 `/var/lib` build root、Packer build、新VMは未開始。image開始前20GiB/コピー後18GiB条件は維持し、容量対策は別レビューを待つ。
