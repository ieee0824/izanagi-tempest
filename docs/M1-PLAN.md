# M1 / Issue #2 実装計画

状態: **M1 実装に対応する計画・入力契約。Rust 実測と room レビューを反映済み。**
更新日: 2026-11-11。基準: main `e0774ea`、[Issue #2](https://github.com/ieee0824/izanagi-tempest/issues/2)。
本書は実装に使う具体的な入力契約の推奨を含む。各拒否条件が旧文書にすべて明記されていた、
または room の賛同がユーザーの仕様変更承認である、という意味ではない。

参照: [DESIGN.md 5.1](DESIGN.md#51-シナリオ定義フォーマット)、
[IMPLEMENTATION.md 7.1](IMPLEMENTATION.md#71-シナリオの追加フィールド)、
[M0 の結果](M0-RESULTS.md)、[Rust YAML 実測](M1-YAML-PROBE.md)。

## 1. 到達点と受入範囲

Rust edition 2024 の workspace と `tempest validate <scenario>` を1本の PR にまとめる。
`s3-overread-001` を受理し、Issue #2 の不正入力を理由付きで拒否できれば M1 の到達点とする。
M0 は完了済み。M1 を妨げる新たな VM 前提は見つかっていない。

| Issue #2 の要件 | 成果物・確認方法 |
|---|---|
| workspace | root Cargo.toml、Cargo.lock、tempest-model / tempest / tempest-guest の雛形 |
| シナリオ型 | DESIGN 5.1 と IMPLEMENTATION 7.1 の共有型、構文と意味検証の分離 |
| YAML 検証 | 下記の一つの読み込み経路、構造・型・重複・未知フィールドの診断 |
| 未対応ポリシー要素の拒否 | setup / retest の双方に固定 LWS の構文サブセット検査 |
| 対応 API | expect / evidence / retest.expect が同じ capability 照会を使う |
| 参照 | API に応じた ARN 種別と setup の bucket / object / queue を照合 |
| SHA-256 | 正規化前の元ファイルのバイト列から計算 |
| 正常例と不正例 | scenarios/s3-overread-001.yaml、各拒否項目に対応する理由付きテスト |
| 開発手順 | README、実装状態の説明、fmt / clippy / test の実コマンド |

`validate` の成功は静的検証の成功である。実行時の主体選択、認可結果、finding / retest の成功、
VM の隔離、モデル比較を保証しない。未実施の検証を成功として数えない。

## 2. 決めた読み込み経路

`yaml_serde = 0.10.7` を選ぶ推奨とし、Cargo.lock を固定する。
Rust 1.99.0 / clang 17 の計画用 ScenarioInput で、2候補・4経路・36 fixture を比較した。
両候補の挙動は比較範囲では同じだった。採用理由は、下記の経路が実測で条件を満たしたこと、
[上流の保守説明](https://github.com/yaml/yaml-serde)、実際の lock の依存構成であり、
ダウンロード数や更新日を安全性の保証にはしない。

```text
元バイト列（保持・SHA-256）
  → 単一 YAML document を yaml_serde::Value に読む
  → 重複キーを拒否した状態で AST を検査
  → JSON 互換 Value へ変換
  → serde_path_to_error 経由で ScenarioInput
  → policy / capability / resource 等の意味検証
```

- native Value の段階で root と nested policy の重複を拒否できることを確認した。
- JSON Value へ直接読む経路は重複を後勝ちにしたため採らない。
- 型への直接デコードは数値・bool・null を String に変換したため採らない。
- native Value→型だけの経路でも budget:null が既定値になったため採らない。
- JSON 化の前に非文字列キー、custom tag、merge key、非有限数を拒否する。
- 通常の非循環 alias は展開後の値として扱う。循環 alias の拒否を実測した。
- 型・意味エラーはフィールド経路と理由を必須とする。行・列は元パーサーが提供した場合だけ出す。
  変換後の型エラーに架空の位置情報を付けない。

最終契約39 fixture を本体の共有型・意味検証まで通す回帰テストへ移した。
計画用 DTO の比較結果と、本体の意味検証を含むテスト結果は区別する。

## 3. 実装に使う推奨入力契約

IMPLEMENTATION 7.1 の任意記述を維持する。親を必須化する案は今回採らない。
親を指定した場合の構造、null、補完は次の契約で明示し、実装 PR で設計文書と同期する。
39 fixture の追加プローブで、構造デコードと presence の扱いを確認した。

| 入力 | 推奨結果・意味 |
|---|---|
| finding と retest の両方あり | それぞれを静的検証 |
| expected_finding のみ省略 | finding を生成せず、finding_present=false |
| retest のみ省略 | 修正ポリシー・確認を生成せず、retest_present=false |
| 両親省略 | 他の定義を静的検証。発見・修正確認については何も成功を主張しない |
| 親の明示 null | 省略とは区別して入力エラー |
| finding を指定 | description と構造化 evidence の api / resource / result を要求 |
| evidence の result | finding の成功証跡として allow を要求 |
| retest を指定 | policy / expect を要求し、同じ policy・API・参照検証を適用 |
| retest.user 省略、setup.users が1人 | そのユーザーを補完 |
| retest.user 省略、複数ユーザー | 明示指定を要求。自然文 task から推定しない |
| retest.user が null / 未知ユーザー | 入力エラー |
| 複数 setup.users と既存 expect / evidence | 全ユーザーの policy と API・参照を静的検証。主体別の認可は検証しない |
| budget 省略 / {} | max_calls=50、timeout=15m |
| budget の部分指定 | 指定した値を保ち、省略された子だけ補完 |
| budget / その子が null | 型エラー |
| max_calls=0 | u64 として許容。独自の正値要件を増やさない |
| timeout | ms / s / m / h の非負整数 duration。空・型違い・解釈不能・overflow は拒否。0の強制動作はM4 |
| success_criteria 省略 | 空の配列 |
| success_criteria の各要素 | 文字列、または1ラベル→文字列の mapping。既存の「- 発見: ...」を保持 |
| deviation 省略 | allow / deny とも空の配列 |
| deviation の非空項目 | JSON互換値として保持し、ルール意味論は未検証と明示。M1では適用しない |

`expect` は本来の基準線である。expect の deny と finding の allow の併存は正当な例として受理し、
差分がない入力を一律エラーにしない。

`expect` / `evidence` に新しい user フィールドは追加しない。複数ユーザーの存在だけで一律拒否せず、
M1 の静的検証と、後続で必要な実行主体の設計を分ける。
`{rule,target}` という deviation 非空項目の追加形も今回採らない。ルール適用前の仕様化・検証は後続。

この表の parent/null 等の拒否は明示した推奨契約であり、すべてが旧文書の確定済み要件という主張ではない。
LWS ポリシー自身の任意 Version / Sid と、シナリオ制御項目の省略規則は別に扱う。

## 4. capability と意味検証

固定 LWS `2c0ea463f334f10a562e54f1cdc7ba8a474029e2` を根拠に、
tempest-model の型付き Rust 定数表を正本とする。
API / action / resource 種別 / 対応条件 / source commit・位置を持たせる。
静的照合と実行時の契約試験の状態は分ける。M1 成功から実行時保証を導かない。

- S3 / SES の gateway に加え、SQS の認可 hook と
  [LWS が固定する lqs 依存](https://github.com/ieee0824/lws/blob/2c0ea463f334f10a562e54f1cdc7ba8a474029e2/Cargo.toml#L16)
  `ebbe2ad5bdf58fc24849e8486559b50e5590c1d8` を確認する。lqs は誤記ではない。
- 独立した網羅的な棚卸し一覧を新たな受入成果物にはしない。必要な根拠は capability 表に持たせる。
- S3 の縦スライスから始めても、元 Issue の範囲を S3 専用へ縮めない。
- expect / expected_finding.evidence / retest.expect は同じ関数で API と resource を検証する。
- 未知 API、LWS の未対応、現入力スキーマでは必要条件を表せない操作を区別して診断する。
  version 条件や未定義の SES identity setup を暗黙に生成しない。新パラメーター・setup 拡張は別提案。
- policy は固定 LWS の構文へ合わせ、Version / Sid、Statement の単体・配列、Action / Resource の単体・配列を扱う。
  Condition / Principal / Not* / policy pattern の `${...}` 等は理由付きで拒否する。
- policy の wildcard と、期待値の具体的な ARN 参照を分ける。認可評価器は作らない。
- API が求める global `*` と、setup の bucket / object / queue が必要な場合を区別する。
- setup の名前重複、具体リソースの未定義・ARN 種別の不一致、未知の retest.user、ID 形式等を検査する。
  判定には文字列の単なる prefix 一致を使わない。

## 5. 実装順序と成果物

```text
Cargo.toml / Cargo.lock
crates/
  tempest-model/src/
    scenario.rs       ScenarioInput と静的検証済み型、presence / 未検証範囲
    policy.rs         LWS ポリシー構文の型と検査
    capability.rs     一つの対応表と照会関数
    validation.rs     診断、参照解決、意味検証
  tempest/src/
    main.rs           validate CLI
    scenario.rs       元バイト列、hash、選択した読み込み経路
  tempest-guest/src/  M2 用の雛形
scenarios/s3-overread-001.yaml
```

1. workspace と lock、共有型、上記読み込み経路を追加し、正常例と duplicate/type/null fixture を通す。
2. 固定 capability と policy 構文検査を追加する。
3. 具体参照・既定値・retest.user 等の意味検証を追加する。
4. CLI、正常シナリオ、拒否理由のテスト、文書を仕上げる。

DESIGN の既存例は削除せず scenarios/ に追加し、内容を同期する。
CLI は成功0、検証エラー1、引数・読込等のエラー2を推奨する。
成功時は ID・元バイト列 SHA-256・固定 LWS commit・静的検証の範囲と presence / 未検証範囲を表示する。
失敗時はフィールド経路と理由を stderr に出す。成功を実験・認可・finding の合格と表示しない。

## 6. 完了の確認

実装の確認コマンド:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --locked -p tempest -- validate scenarios/s3-overread-001.yaml
python3 -m unittest discover -s tests -v
```

元 Issue の拒否項目と fixture を一対一に対応させ、理由を検査する。
正常例、retest だけに不正を含む例、nested policy の重複、文字列の暗黙変換、
raw hash の決定性、ARN prefix の誤一致、policy wildcard の保持を回帰確認する。
README に実際に成功した setup / build / run / test を記載し、必要なら AGENTS.md の実装状態も更新する。
CI を追加する場合も同じチェックを使うが、CI 新設自体を元 Issue の必須条件には加えない。

独自 IAM 評価器、内部認可引数の観測、実行前証跡ゲート、実行主体フィールド、
新しい SES setup、deviation の意味論、M2 の recorder / seed / seal は後続の別項目とする。
それらの採否や内部観測の成否を理由に、M1 の静的実装全体を止めない。

## 7. 議論の記録

- 計画初稿: room #14951、[Issue コメント](https://github.com/ieee0824/izanagi-tempest/issues/2#issuecomment-6794269628)。
- #14952〜#14974: 既存要件と追加案を分類。同じ ScenarioInput 終点、Value 前の重複検査が必要と整理。
- #14983: 36ケース実測。親必須案は #14986 等で任意記述との相違を指摘され、採らない。
- #14993・#14995・#14997: 複数ユーザーの静的検査と主体選択を分離。一律拒否を追加しない。
- #14999: 任意の親を維持する最終契約と39ケースの追加確認を共有。

議論後、この契約を本体の共有型・読み込み・静的検証へ実装した。M2 以降の実行検証は別範囲とする。
