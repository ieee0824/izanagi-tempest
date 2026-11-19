# Linux x86 HTTP sidecar 検証案

## 状態と目的

#36の未確認項目であるIzanagi HTTP sidecar実起動を、M3のLWS capture proxyと分けて検証する案。
Sakura16717で議論を開始した。proc-exposure003の回収を優先し、この文書だけでは新root作成・VM起動を開始しない。
実装・固定計画・入力snapshot・実機結果はまだない。

固定対象はIzanagi `16d0b55947006a166cfa29dcb8bfe71f65f8c36a` とfull003 image。
上流sourceとimageを変更せず、restrict_network=true、read-only mapped share、専用KVM userとdummyだけを維持する。
classifierはmock、allow_export=falseとし、実model・credential・AWS・外部receiverを使用しない。

## 固定sourceから確認した起動経路

- `src/vm_agent_tracer.rs::prepare_inner` はbehavior設定がある場合、認証後にStartBehaviorを送りTraceStartedを待つ。Readyだけをsidecar準備成功としない。
- `izanagi-agent/src/sidecar.rs::validate_start/spawn_proxy/wait_ready` はroot-ownedでgroup/world write不可の固定`/usr/local/bin/izanagi-http-capture`を起動する。listenはguest loopbackの非0port、metadata socketのdirectory0700/socket0600、sidecar readiness応答を要求する。
- `izanagi-agent/src/connection.rs::exec` はactive proxyをhttp_proxy/HTTP_PROXYへ設定し、no_proxy/NO_PROXYを空にする。環境変数だけでは転送成功の証拠にならない。
- 上流`tests/manual/behavior_vm.py`はrestrict_network=falseとwritable shareをassertし、macOS/PTTYとaarch64を前提とする。この実行手順をTempestへそのまま移植しない。

## 1VMの検査案

新しい専用root/unit/profile/observerと固定closureを用意し、現在の正常smoke入力へbehavior有効・guest loopback fixtureの明示差分を加える。
正確なconfig/argv・source hash・依存・容量・未使用unitとUID状態を固定計画で監査してから単発実行する。

公開helperは秘密を含まないreceiver/clientの必要最小sourceだけとし、VM前にguest root所有のreadonly領域へ配置する。
user xattr設定はhost owner-write可能な間に行い、その後host0444へ固定する。既存PR58の回帰と実Linux非root権限検査を使用する。
receiverはguest actorがguest loopbackの固定fixture portだけで起動し、期限・request/body件数・bytesに有限上限を置く。
workspaceへの書込や一般HTTP forward、任意target引数を追加しない。起動/終了・結果の取出し方式は実装レビューで確定する。

正例は固定proxy経由のdummy HTTP要求が、当該loopback receiverで対応するnonceとbodyとして到着し、固定responseがclientへ戻ること。
副作用の判定にはclientのexit0だけでなくreceiver側の件数/nonce/bytesを使う。
負例は許可fixture以外のloopback endpoint/Hostでの拒否とreceiver未到着を、正常receiverの対照と組み合わせる。
実外部宛てへの接続はこの試験に含めない。

sidecarの存在はPID/starttime/親/UID/固定argvの観測と、offline artifactのhash/ELF・StartBehavior準備確認を組み合わせる。
actorからroot processのexe実体が読めない場合は読取拒否として保存し、実稼働exe hashを読めたと主張しない。
telemetryはrun/session/boot/sourceの識別とHTTP metadata/時刻/件数を固定source schemaへ照合する。
期待するevent variantや保存先・遅延上限は実装時に固定し、見つかった行を後から期待値にしない。
writer correlationや分類結果がunknown/abstainならそのまま残し、HTTP転送成功を全writer attributionの成功に変えない。

## 証跡と未確認範囲

既存private exec保存/marker scan、events/alerts/behavior rotations、up stdout/stderrを保存する。
管理token/reply key/private payloadと、公開dummy HTTP bodyを別種として扱い、秘密の非保存とHTTP metadataの最小化を混同しない。
rawと目印値はprivateのまま、安全な件数/controls/識別binding/結果scopeを選別公開する。

caller/observerの同handle終端、同Invocationのtrusted journal/exit recorder、cgroup/UID/port回収、固定入力/旧証拠不変を分けて確認する。
失敗時は当該unitだけ回収し、暗黙retryせず部分証拠を保持する。

この検査は外部通信拒否のpositive control、forced delivery race、全route/全期間、classifier精度、実Claude認証/正式比較を完了しない。
既存sourceがrestricted構成を拒否する場合は制約との不整合として#36で議論し、restrict解除や共有書込へのfallbackを行わない。
