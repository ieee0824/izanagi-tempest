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
