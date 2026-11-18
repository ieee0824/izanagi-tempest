# proc-exposure002 ページ観測案

## 001を保持する

001はbefore_claimでPID集合が128を超え、pid_set_truncated=trueにより停止した。
positive controlsは成立したが、後2時点と最終exec scanには未到達。失敗判定と原本を保持し、
001を再開・遡及合格にしない。002は別root/unit/profile/sourceとして固定する。

## 1回の上限内で列挙集合を追跡する

1. 固定guest guard後にPIDとstarttimeを列挙する。上限4096PID、列挙応答も128KiB以内。
2. 列挙集合を最大127PIDのページへ分割する。各ページへ観測process自身1PIDを加え、既存128PID上限を維持する。
3. 各ページはcmdline/environ各8192B・応答128KiB以内。最大33ページと列挙1回、各時点の合計応答は34×128KiB以内。
4. requested PID/starttimeと返却recordを照合し、欠落/重複ページを拒否する。消滅・PID再利用・identity不安定は区別して保持する。
5. 全ページでargv/env公開canary・自身FD一覧を確認する。FD内容は読まない。
6. marker scanとraw private保存は各exec返却前と最終時のまま。truncation/error/coverage不一致を成功へ読み替えない。

ページ間は同時刻ではない。列挙後の新規process、短命native、全期間の非露出を証明しない。
3時点それぞれに列挙・全ページの観測期間とcountsを保持する。

## probeの配送

probe sourceは秘密を含まない検証用public helperとして既存read-only test領域へ起動前に固定する案とする。
Python -cへ全sourceを入れず、各ページのown cmdlineがsourceの長さだけで8192Bを超えないようにする。
公開argv canaryは明示引数、env canaryとpage PID/starttimeはenvで渡す。private token/keyをprobeへ渡さない。
helperのmode0444とmapped metadata、共有read-onlyを確認し、guestの変更を許さない。

## 検証と開始条件

列挙129PID以上の全ページcoverage、ページ欠落/重複/別PID/別starttime、control不成立、
truncation、総量上限、PID消滅/再利用をsynthetic fixtureで検査する。
001部分RESULTと回収/入力不変を保存した後、002のsource/closure/具体commandをroomで照合して単発開始する。
現時点では設計案であり、002実装・snapshot・VMは未実施。
