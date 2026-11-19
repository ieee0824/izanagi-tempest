# Capture build 001 snapshot準備結果

room16881の固定prepare実行92623は同handle終端exit0、UID検査72174も同handle終端exit0。新root `/var/lib/tempest-izanagi-capture-build-001` に29入力を固定した。

[全snapshot rows/source hash/provenance](LINUX_X86_CAPTURE_BUILD_SNAPSHOT_001.json)のcanonical input rows SHAは `9536047ed2c0ef72de57bcd9e6489a2674a84a6d6f1910187f4094aa8e684db7`。新guest/sourceのcompile9値、標準定義metadata不変、旧固定assets/Packer/plugin、path置換とhardlink追補を束縛した。

[UID検査](LINUX_X86_CAPTURE_BUILD_PREPARATION_001.json)で全input SHA/owner-mode/singlelink、read可/write不可、directory0750、work999:988/0700、external runtimeとoutput不在を確認。固定snapshot内Packer full validateはexit0。

[容量・handle記録](LINUX_X86_CAPTURE_BUILD_PREPARATION_LIFECYCLE_001.json)にcopy前root不在時のfree23864639488 bytesとcopy後のfreeを保存した。prepare内でもcopy前20GiB/後18GiB条件を検査した。旧原本や元RESULTは変更していない。build/新VMは未開始で、snapshot結果レビューを待つ。
