# M1 YAML 読み込みの計画用実測

実施日: 2026-11-11。Rust 1.99.0 / Apple clang 17.0.0 / macOS aarch64。

DESIGN 5.1 の YAML 全体を読む同一の計画用 `ScenarioInput` を終点に、36 fixture × 2ライブラリ × 4経路を比較した。
この DTO は採否判断用のプロトタイプであり、本体 M1 やドメイン意味検証を実装した結果ではない。

固定版: yaml_serde 0.10.7（libyaml-rs 0.3.0）、serde_yaml_ng 0.10.0（unsafe-libyaml 0.2.11）、
serde 1.0.229、serde_json 1.0.154、serde_path_to_error 0.1.20。

## 同じ終点まで通した結果

以下の受理／拒否は両ライブラリで一致した。

| 入力 | YAML→型 | YAML→YAML Value→型 | YAML→JSON Value→型 | 選択案: YAML Value事前検査→JSON→型 |
|---|---|---|---|---|
| valid_documented_scenario | 受理 | 受理 | 受理 | 受理 |
| root_duplicate | 拒否 | 拒否 | 受理 | 拒否 |
| nested_policy_duplicate | 拒否 | 拒否 | 受理 | 拒否 |
| unknown_root | 拒否 | 拒否 | 拒否 | 拒否 |
| unknown_policy | 拒否 | 拒否 | 拒否 | 拒否 |
| unquoted_policy_date | 受理 | 受理 | 受理 | 受理 |
| id_integer | 受理 | 拒否 | 拒否 | 拒否 |
| id_boolean | 受理 | 拒否 | 拒否 | 拒否 |
| id_null | 受理 | 拒否 | 拒否 | 拒否 |
| id_leading_zero | 受理 | 受理 | 受理 | 受理 |
| id_quoted_integer | 受理 | 受理 | 受理 | 受理 |
| name_yes | 受理 | 受理 | 受理 | 受理 |
| name_off | 受理 | 受理 | 受理 | 受理 |
| name_true | 受理 | 拒否 | 拒否 | 拒否 |
| multiple_documents | 拒否 | 拒否 | 拒否 | 拒否 |
| alias | 受理 | 受理 | 受理 | 受理 |
| recursive_alias | 拒否 | 拒否 | 拒否 | 拒否 |
| custom_tag | 受理 | 受理 | 拒否 | 拒否 |
| budget_partial | 受理 | 受理 | 受理 | 受理 |
| budget_null | 拒否 | 受理 | 拒否 | 拒否 |
| budget_child_null | 拒否 | 拒否 | 拒否 | 拒否 |
| budget_zero | 受理 | 受理 | 受理 | 受理 |
| retest_user_null | 受理 | 受理 | 拒否 | 拒否 |
| missing_finding | 拒否 | 拒否 | 拒否 | 拒否 |
| missing_retest | 拒否 | 拒否 | 拒否 | 拒否 |
| null_finding | 拒否 | 拒否 | 拒否 | 拒否 |
| null_retest | 拒否 | 拒否 | 拒否 | 拒否 |
| nonfinite_policy_version | 受理 | 拒否 | 受理 | 拒否 |
| nonfinite_budget | 拒否 | 拒否 | 拒否 | 拒否 |

## 採用を推奨する経路

1. 元バイト列を保持し、そのバイト列から SHA-256 を計算する。
2. yaml_serde 0.10.7 の native Value へ単一文書を読む。この段階で root / policy 内の重複を拒否する。
3. 変換前に非文字列キー・custom tag・merge key・非有限数を拒否する。通常の非循環 alias は展開後の値として許容する。
4. 検査後に JSON 互換 Value へ変換し、serde_path_to_error 経由で同じ ScenarioInput へ読む。
5. policy / API / resource / ID 等のドメイン意味検証を実行する（今回のプローブ外）。

`retest.user:null` と複数ラベルの success_criteria は、ライブラリの機能ではなく
JSON→型の直前に置いた独自の入力契約チェックで拒否している。比較と追加チェックを混同しない。

JSON Value へ直接読む経路は重複キーを後勝ちにし、型検査では救えなかった。
String への直接デコードは42・true・nullを文字列に変換した。
YAML Value→型だけでも budget:null が既定値として受理されたため、採用しない。
非有限数は JSON 化すると情報を失う可能性があるので、変換前に拒否する。

id: 0123 や引用した42が上表で受理されるのは文字列としてのデコードまで。
M1 の ID 形式検証で許可することを意味しない。budget の0は型上受理し、独自の正値条件を追加しない案。

重複診断は setup.users[0].policy.Statement[0] と line 12 / column 13 を取得できた。
変換後の型エラーはフィールドパスを取得できるが、行・列は失われる。
M1 はフィールドパス・理由を必須とし、元パーサーが持つ位置だけを表示する。意味エラーに架空の行番号を付けない。

既存 success_criteria の箇条書きは YAML では単一キーの mapping になる。
プロトタイプは文字列または1ラベルの文字列 mapping を扱い、既存例をそのまま受理した。

## 再現と証跡

コード・fixture・Cargo.lock・全結果・環境情報は Git 対象外の `.m0-evidence/20261111-m1-yaml-probe/` に保存。
同ディレクトリで `cargo run --release --locked --bin tempest-m1-yaml-probe` を実行すると全36ケースを再現できる。
最終契約39 fixture は `crates/tempest/tests/fixtures/yaml-regressions.json` へ移し、
`cargo test --locked -p tempest --test validation measured_yaml_regressions_reach_production_semantics`
で本体の意味検証まで確認する。計画プローブで型として受理した `id: 0123` / 引用した42は
本体では ID 形式エラー、`name: yes` / `off` は残った `retest.user: worker` の参照エラーになる。
上の比較表は当時の型デコード結果のまま保存し、本体の受理結果とは区別する。

| 対象 | SHA-256 |
|---|---|
| Cargo.toml | `37b84397a3bb75322785a97bbd4bc5f99a012fadb9b4c8097bf6761f8ac9a546` |
| Cargo.lock | `665195f6743e1db207e0773e8043cff08a19ee37c57b57306cc643a2a83f1102` |
| src/main.rs | `422f18aec4173a7c95fb9153da00517c90887db28f936197ef9580aaa94c2cb0` |
| scenario.yaml | `7c2cc8dacc784c9f2dc079f7ac61f7d2983617fea1c8757b75f059fa30d8fb69` |
| results.json | `2e40a7b7928d651d885fd9d36191f73c15d1114f0241da6baf56af35684541b1` |

上流の採用根拠は [yaml_serde の上流説明](https://github.com/yaml/yaml-serde)と、
この固定版での実測・依存 lock。両候補の挙動差を捏造せず、比較した範囲では同じだったと記録する。
更新日・ダウンロード数だけを保守や安全性の保証とは扱わない。


## 最終入力契約の確認（追加39ケース）

親を任意のままにする案を、別バイナリ `contract` の同じ DTO 終点で確認した。
ライブラリ・4経路の条件は上記と同じ。これはライブラリ差の追加主張ではなく、
推奨する省略・null の契約を実装可能な形で確かめるプロトタイプである。

| 入力 | 選択経路の結果（両ライブラリ一致） |
|---|---|
| finding と retest の両方あり | 受理、両方 present |
| finding だけ省略 | 受理、finding_present=false |
| retest だけ省略 | 受理、retest_present=false |
| 両親省略 | 受理、両方 present=false |
| 親の明示 null | 独自の入力契約検査で拒否 |
| 親あり evidence 欠落 / null | 型検査で拒否 |
| budget 省略 / {} | 受理、50 / 15m |
| budget.max_calls=3 のみ | 受理、timeout=15m |
| budget null / 子 null | 拒否 |
| max_calls=0 | 型上受理 |
| retest.user=null | 独自の入力契約検査で拒否 |
| deviation の非空項目 | 値を保持し deviation_semantics_unchecked=true |

API・ポリシー・ID・retest.user 参照などの意味検証は、この調査では実装していない。
親省略で静的デコードに成功したことを、未実施の発見・修正確認の成功とは扱わない。

再現: `cargo run --release --locked --bin contract`。
コードは `src/bin/contract.rs`、結果は `contract-results.json`、全39 fixture は `contract-fixtures/`。

| 対象 | SHA-256 |
|---|---|
| src/bin/contract.rs | `c3cdbe217deace384175560c678b151f430ff02eb1652bc79c6399a8e1850a26` |
| contract-results.json | `c68e53698fc846ce2664854f64b8980eb5dfa2a20ddc3def5912a69f7d86fcdb` |
