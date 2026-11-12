# Phase 1 追加案の採否

2026-11-12。既存の検討Issue #16〜#19について、実装済みM0〜M3の完了条件を変えずに判断する。
room投稿15145〜15147を参照。採用していない機能を対応済みと表示しない。
#16のHTTP契約試験と#17の指標別適格性は引き続き設計・実装中で、本書の見送り判断で閉じない。

## #18: 独自IAM評価器はPhase 1では採用しない

| 方式 | 利点 | 費用・乖離リスク | 判断 |
|---|---|---|---|
| 既存の構造/policy構文/capability検査 | VM起動前に不正な入力を診断できる | 認可結果を判定しない | 維持 |
| harness独自のIAM evaluator | VM起動前に限定的なpolicy自己整合を診断できる | action/resource/glob・大小文字・Deny優先・複数policy等をLWSと二重実装し、依存先更新時の差分検出/比較試験が必要 | 初版では見送り |
| 固定LWSに対するseed後のprobe | 実際の対象/主体/操作に対する応答を確認できる | VM起動とseedが必要。未知キー/不完全/501をdenyへ誤分類しない必要がある | self-check/retestで維持 |

現行のS3過剰権限シナリオは、expectの本来のdenyと誤設定policyによるfinding allowが
意図的に異なる。独自評価器を足して「expectとpolicyが違う」を一律不正にしてはならない。
finding/retestがない正常系・negative controlも引き続き静的に受理する。

[M1検証](../crates/tempest-model/src/validation.rs)は認可評価を行わない。
[M2分類](../crates/tempest-guest/src/seed.rs)とmapping試験は、未知キー403・不完全応答・
未対応501を本来の認可denyと区別する。
[M4契約](M4-CONTRACT.md)ではresolved actorのキーで実probeし、
findingが未設定ならself-checkを生成しない。静的validate/plan成功を実行時保証と呼ばない。

したがって独自評価器の実装や差分比較用の新しい保証は追加しない。
再検討する場合は、実際に必要な早期診断、対応する意味論とLWSとの比較保守計画を示す。
その判断を今回未解決のまま残すのではなく、Phase 1では**不採用**とする。

## #19: 追加request条件・SES identityスキーマは初版では採用しない

固定LWS/lqs/lesの対応根拠は[capability catalog](../crates/tempest-model/src/capability.rs)。
ここでの「条件」はrequestの必要入力であり、未対応のIAM Conditionを新たに認める判断ではない。
現在のシナリオはS3 GetObjectで完結する。次の拡張を必要とする既存ユースケースはなく、
Check/Setupだけでなくseed/probe/recorder/参照検査へ一貫して条件を運ぶ設計費用が生じるため見送る。

| 対象操作 | 現入力で表せないもの | 初版の判断 |
|---|---|---|
| s3:GetObjectVersion / s3:DeleteObjectVersion | versionId、versionを選ぶためのsetup/参照 | 拡張しない |
| sqs:SendMessage / sqs:SendMessageBatch | MessageBody / batch entries | 拡張しない |
| sqs:DeleteMessage / sqs:ChangeMessageVisibility / sqs:DeleteMessageBatch / sqs:ChangeMessageVisibilityBatch | ReceiptHandle / VisibilityTimeout / batch entries | 拡張しない |
| sqs:SetQueueAttributes / sqs:TagQueue / sqs:UntagQueue | Attributes / Tags / TagKeys | 拡張しない |
| sqs:AddPermission / sqs:RemovePermission | permission parameters / Label | 拡張しない |
| ses:SendEmail | sender identity setup、destination、message | 拡張しない |
| ses:VerifyEmailIdentity / ses:VerifyDomainIdentity / ses:DeleteIdentity | EmailAddress / Domain / Identity | 拡張しない |
| ses:CreateEmailIdentity / ses:GetEmailIdentity / ses:DeleteEmailIdentity | EmailIdentity | 拡張しない |

すべて既存の`input representation error`を維持する。LWS自体の501、未知APIとは区別する。
versionIdの「最新版」、identityやmessageの既定値をharnessが補って通さない。
未採用フィールドの追加もunknown fieldとして拒否し、既存の成功例と省略契約は変えない。

例（意図的な拒否入力の断片）:

```yaml
expect:
  - api: s3:GetObjectVersion
    resource: arn:aws:s3:::public-data/readme.txt
    result: allow
```

versionIdのないこの操作は表現不能として拒否する。`versionId: v1`を勝手に足しても
既存Checkのfieldではないため拒否する。SES identityをSetupへ黙って足しても同様。
YAML成功例や移行形式を新たに採択していないので、既存シナリオへのmigrationは不要。
[M1契約試験](../crates/tempest/tests/validation.rs)で表現不能20操作の全check配置、
未知/strict未対応との区別、追加fieldの拒否と既存シナリオ互換性を確認する。

将来この対象を必要とするシナリオが追加された場合は、対象操作ごとの入力・seed・probe・
観測・参照形式と移行を改めて設計する。今回の判断はPhase 1初版の拡張**不採用**である。
