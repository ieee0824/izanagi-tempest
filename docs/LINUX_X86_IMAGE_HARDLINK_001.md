# 固定7 imageコピー統合の追補 001

room16876の実行指示により、固定script SHA `f603096a1efabc5ff92a50ba51273d13e3839799b404a983aa03851fbf034765` をroot Python-I-Bで一度だけ実行した。handle84449は同handle終端exit0。exclusive private journalは17recordでcompletedまで保存した。

canonicalはimage-smoke-002/inputs/image.qcow2。置換はimage-smoke-001、image-smoke-001-v2、exec-exposure-001、proc-exposure-001/002/003、sidecar-001の7inputs/image.qcow2だけ。各pathのSHA5885abea…/bytes/root:988/0440を維持し、全8pathはcanonicalの同inode/nlink8を参照する。

[追補結果JSON](LINUX_X86_IMAGE_HARDLINK_001_RESULT.json)に全pathの前後device/inode/nlink/blocks/uid-gid/mode/mtime-ctime、7parent directoryの変更後metadata、前後の保存検証、authorization参照・実scriptSHA・journalSHAを保存した。

物理identityの明示例外はcanonicalのnlink/ctime、7targetのinode/nlink/mtime/ctime、7parent directoryのmtime/ctimeである。元snapshot/RESULT文書は書き換えていない。旧pathの物理identityまで不変とは扱わず、この追補と一緒に解釈する。今後canonical/targetの変更は全8pathへ影響するため、read-only inputとして維持する。

前後ともseed-lossの全tree identity/content/xattr比較、全保存snapshotの内容・owner-modeと既知public RESULT参照fileのSHA比較が成功した。seed-loss/presence/normal/endpoint/fixture/元qcow2/private rawは統合対象に含めていない。

freeは8849870848から23865704448 bytes、差15015833600 bytes（約13.98 GiB）。これはホストの前後空き容量差であり、他プロセスの一時使用量から独立したquota計測ではない。image開始前20GiBを上回ったが、新buildは別snapshot/caller/observer監査を要する。新image build・VMは未開始。
