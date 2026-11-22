# #36 B案: vsock 上流中継の設計メモ

状態: ownerのvsock方式承認（#18281/#18282）と設計レビュー（#18289）を確認済み。
外部接続・実credentialなしの実装/ローカル検証へ進む。本人loginは実行しない。
#18256/#18259/#18272/#18273 のレビュー材料として、既存条件を保つ変更点だけを記す。

## 経路と担当

```text
固定CLI UID999 -> 世代専用TCP CONNECT gateway -> AF_VSOCK host CID2:23105
                                                    |
                                     hostが承認数値IP:443へTCP接続
                                                    |
                                   TLSは固定CLIと認証サーバーで終端
```

CLIからのAF_VSOCK作成は禁止する。gatewayはtrusted root helperとしてのみ接続し、
その接続FDをCLIへ継承しない。PID/net/mount隔離、直接TCP/DNS拒否も維持する。
CIDはVMの識別でありguest内のUID識別ではない。実入口のsocket filterを前提とし、
netnsだけでは代替しない。root gateway/guest管理者を悪意ある主体とする設計ではない。

| 接続 | 用途 | 実行主体と制限 |
| --- | --- | --- |
| host CID2:23100 | 台帳のpreflight/consume/query | 既存8worker/2秒/同CID1要求を維持 |
| host CID2:23105（候補） | 上流dialとTLS不透明中継 | 独立4接続上限、制御workerを占有しない |
| guest 127.0.0.1:39271 | 固定CLIからのCONNECT | 既存UID/宛先制約を維持 |

portは起動前に未使用を確認する。制御とデータは別socket・別worker制限とする。
既存host daemonを同じprocess内の独立listener/poolで拡張する案に絞る。
制御からのfresh状態はprocess内で共有し、長寿命relayを短期応答poolへ載せない。
プロセスを追加分離する場合はfresh状態の配送方式が別途必要なので、この案では行わない。

## ホストが保持する原本

root0700/0600の管理登録、独立承認、台帳/checkpoint、署名済み公開世代と信頼鍵を使う。
署名済み宛先の検証を既存validatorと共用できる境界へ分け、guestが指定した値や
unsignedのIP一覧だけでdialを許可しない。受理するのは既存version/schemaだけとする。

- target/permit/generation/guest boot、CID、QEMU PID/start ticks/QMP実CIDを照合する。
- 最新台帳が同scopeのconsumed、独立checkpointと一致することを要求する。relayで再consumeしない。
- manifest digest、IP revision、固定authority、数値peerと443、最早の通信/許可/公開世代期限を束縛する。
- DNS再解決、request由来の任意IP/port、未承認redirect先、別VM/別bootを受け入れない。

既存のcontrolが成功した後だけ、scope/sequenceと単調時計のfresh期限を短く公開する。
公開は署名応答の送信成功後。期限はhost受理時の単調時計＋署名寿命以下と原本の
最早期限の早い方とし、送信時を寿命の起点にしない。guestの単調時計はhostへ持ち込まない。
このfresh状態は新しいdialと既存relayの両方に必要とし、relay自身の処理では更新しない。
control更新が止まれば最後の最長2秒の期限で閉鎖する。SQLite lockを中継中に保持しない。

## 接続開始と署名応答

1. gatewayが親の有効leaseを確認し、専用portへ接続する。host CID/portを照合する。
2. 2秒の絶対期限内に1 KiB以下の要求を1フレームだけ送る。version、scope、guest boot、
   manifest digest、IP revision、authority、新challengeを含める。dial先はhost原本から選ぶ。
3. hostが実peer CID、QEMU生存、原本、fresh control、期限を確認してから、固定peerへ接続する。
   host自身で実TCP peer_addrを照合する。TCP接続完了後も認可を再確認する。
4. hostが要求全体・実peer・manifest・sequence・最早期限を専用domainで署名し、4 KiB以下で返す。
   domain案は `izanagi-tempest:login-egress:v1\0`。台帳receiptと相互流用しない。
5. gatewayが独立信頼鍵、challenge、対象、宛先版、期限を照合した後だけCLIへCONNECT 200を返す。
   それ以前の拒否/切断は上流TCPも閉じ、TLSのデータモードへ進めない。

vsockをTcpStreamに偽装しない。guest側のpeer確認はsockaddr_vmのCID/portで行う。
既存のTcpStream.peer_addrによるIP検査をguest側のvsockへ適用しない。
TCPとvsockのRead/Write/clone/shutdown/pollを明示的な接続型で分け、期限を共有する。

## 中継と終了

署名応答のフレーム終了後は双方向の不透明bytesだけを流す。TLS終端/復号、token抽出、
URL/code/HTTP body/PCAPの記録はしない。各接続のbuffer上限案は方向ごと64 KiB。
ログはscopeの識別参照、開始/停止理由、接続/回収結果だけに制限する。

host側は独立した監視経路でfresh control/台帳/署名世代/独立承認/期限/QEMUを再照合する。
更新失敗、失効、期限、親/guest切断、QEMU終了では新規dialを止め、既存のTCP/vsockを
shutdown両方向→closeし、workerの終了を回収する。停止ラッチは同一実行で解除しない。
中継期限は認可期限そのもの。終了確認の猶予でconnect/read/writeを継続しない。
片方向EOFでも両方向を閉じる。停止確認に失敗した世代は既存どおり隔離し、再利用しない。

## 変更箇所と受入範囲

- guest: login_connect.rsの上流transportと署名応答検証を追加。固定authority/子のfilterは維持。
- host: control成功のfresh状態公開、独立data listener/pool、署名済み宛先検証、dial/relay/回収を追加。
- 配備: root原本とサービス設定、同じ専用user/KVM VMのvsock device、専用port、最早期限を記録。
- 条件確定後のdummy受入: 正常TLS中継、宛先拒否で上流dialなし、失効/更新停止で両端閉鎖、
  CLI迂回拒否と既存proxy正常対照。既存#36の回収契約を検証し、周辺境界の拡張は追加しない。

このメモだけで新経路が成立したとは扱わない。方式回答と設計レビュー後の実装段階である。
現在のowner VMやhostのforward/NAT設定は変更しない。実認証は通信条件と本人操作の判断後。
