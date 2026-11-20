# Linux direct profile/report schema案

Issue #36の設計案です。実credential、login、外部callは行いません。

## 既存relay契約

`capability_proof::LauncherProfile`の必須u64 request count/budget、
`local_deterministic_stub_through_relay`、`model_api_relay_only`の検証は維持します。
既存artifactの読み方とLaunchPermit発行経路は変更しません。

directは別の`DirectInvestigationProfile`と`DirectInvestigationReport`を新設し、
`schema_version=1`、`mode=linux_direct_investigation`を必須にします。
relay profileへの自動fallback、untagged enum、欠落modeの推測は禁止します。
direct reportは調査結果のみで、LaunchPermitへ変換するAPIを設けません。

## 観測型

値は`Evidence<T>`のtagged enumで表します。

```rust
enum Evidence<T> {
    Unobserved { reason: UnobservedReason },
    Unknown { reason: UnknownReason, sources: Vec<EvidenceRef> },
    Observed { value: T, sources: Vec<EvidenceRef> },
}
```

`Unobserved`は測定経路なし、`Unknown`は測定を試みたが判定不能です。
どちらもvalueを持たず、0、空配列、false、verifiedへ変換しません。
Observedはverifiedと同義にせず、検証者・scope・binary hash・run bindingを別に保持します。
reason/source kindは固定enum、未知field拒否、参照件数と文字列長に上限を設けます。
公開reportにheader本文、credential、任意path、raw streamを保存しません。

| 対象 | 型・scope | directの既定 |
| --- | --- | --- |
| request catalog/schema | Evidence<digest/count>、request IDごと | Unobserved |
| header | Evidence<固定header名の存在bool>、request IDごと | Unobserved |
| provider request count/retry | Evidence<u64>、run/requestごと | Unobserved |
| budget設定 | Evidence<u64>、設定scope | Unobserved |
| budget強制 | Evidence<bool>、provider request scope | Unobserved |
| stream-json tool一覧 | Evidence<digest/count>、stream初期化scope | request catalogへ昇格不可 |

EvidenceRefは`stream_json_listing`、`agent_self_report`、`pinned_binary_static`、
`os_observation`を区別します。自己申告や静的binary解析はwire観測へ変換しません。
OSのPIDFD/cgroup観測もprovider request内容・回数を直接証明しません。
設定上のbudgetと実際の強制、retryの未観測とretryなしを分けます。

## 必須負例

- direct artifactを既存relay profile/proof verifierへ渡すと拒否し、permitを発行しない。
- mode欠落、未知mode、relay/direct混合field、未知field、schema version不一致は拒否。
- Unobserved/Unknownへvalueを追加、Observedのsource欠落、source scope不一致は拒否。
- stream一覧のdigest一致をrequest catalog exactへ、自己申告をOS検証へ変換しない。
- 未観測count/retry/budgetを0へ補完しない。observed zeroは測定scopeと独立証拠が必要。
- direct reportの全観測がtrueでも既存relay LaunchPermitの入力にはしない。

この案の型実装・負例テスト・受入は未完です。

## semantic validatorの固定条件

未改変direct方式ではrequest単位catalog/schema/header/count/retry/budget強制は
`Unobserved`を必須にします。上記4種のEvidenceRefがあっても`Observed`や`Unknown`へ
昇格させません。wire観測経路を追加する場合は新しいmode/schemaと別の受入が必要です。

EvidenceRefは固定source enum、固定scope enum、run ID、profile SHA256、binary SHA256、
artifact SHA256から構成します。run IDは親発行16-byte nonceの32桁hex、digestは64桁hexです。
report本体のrun/profile/binary bindingとの完全一致を必須にします。
sourceは1〜8件、同じsource/scope/artifactの重複を拒否します。

| source | 許可scope |
| --- | --- |
| stream_json_listing | initialization_tool_listing |
| agent_self_report | agent_claim |
| pinned_binary_static | binary_configuration |
| os_observation | process_isolation |

request_wire scopeはこのmodeに存在しません。source単独を信頼度の序列へ変換せず、
scopeの異なる観測を合成してrequest観測へ昇格させないvalidatorにします。
負例にはbinding不一致、source/scope不一致、0件/9件/重複source、
各request項目のObserved/Unknown偽装を含めます。

## 比較レポートへの取り込み（Issue #7）

比較計画には実行前に固定した接続経路を含めます。比較スロットの ID と
直結レポートの `binding.run_id`（親が発行した nonce）は形式が異なるため、
親が保存した実行記録で対応を確認します。同じ実行のプロファイルとバイナリの
SHA-256 を照合できた場合に、項目別の観測状態を集計へ渡します。
受入時は、親の記録を基準に、検査対象、観測者、許可した source/scope と成果物 ID を
同じ実行へ結び付けます。許可された成果物の実バイトから SHA-256 を再計算し、
親の記録およびレポートの参照に照合します。対応付けや証跡が欠落する場合、
またはいずれかの照合に失敗した場合は、そのスロットの観測レポートを欠測とします。
固定合成試験の証跡は本番比較の観測に使用しません。
[出所のレビュー記録](https://github.com/ieee0824/izanagi-tempest/issues/7#issuecomment-7032414990)

実行後の観測状態は集計のグループや分母を変更しません。設定上の予算を
`BinaryConfiguration` の証跡で記録できる場合も、プロバイダーによる予算の
強制は `Unobserved` と表示します。実行記録と比較スロットの対応付け、
直結レポートの実行時生成および集計への取り込みは未実装です。

比較計画の直結経路は `connection_route: claude_subscription_direct` とする。
計画でこの値を指定した評価済みスロットは、親側の証跡経路が未実装の間、
集計 JSON の `direct_observation` に `missing` と
`parent_evidence_unavailable` を記録し、Markdown に補足表を出す。
評価状態、経路の確認状況、分母は従来の集計を使う。実行入口は
`mock_in_process` と `model_relay` のみを発行し、計画と照合する。

読み取り専用の出所検証器は、呼び出し側が信頼して確定した同一世代の
親記録とディレクトリ FD を受け取る。呼び出し中は同世代の公開状態と
成果物への書き込みを固定する。観測参照をその親記録と照合し、固定名の
`process-isolation.json` を同じ FD から開く。通常ファイルのみ、最大
64 KiB とし、開いたファイルの実バイトの SHA-256 を照合する。
合成回帰は検証の成否だけを確認する。集計への結線は未実装であり、
既存の確定評価マニフェストと欠測表示を使う。
