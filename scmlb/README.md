# Scmlb

scmlb は XDP を利用したシンプルな L4 ロードバランサーです．

scmlb は ロードバランサー本体のデーモンプログラムの `scmlbd` と それを操作するための CLI プログラムの `scmlb` の二つのプログラムから構成されます．

以下の図は scmlb の概要図です．
`scmlbd` がホスト上で動作し，upstream, backend の 各 NIC に XDP プログラムがロードされています．
upstream から受信した VIP 当てのパケットを backend として登録されたホストに転送します．
`scmlb` コマンドを介して backend の登録や解除，状態の参照を行います．

![overview](./images/overview.drawio.svg)

## ビルド

ビルドには Go 言語の 1.20 以上が必要です．
もしビルドするマシンの Go 言語が 1.20 未満の場合は以下を実行して Go 言語を再インストールしてください．

```
$ sudo rm -rf /usr/local/go
$ make -C ../ setup-golang
$ go version
```

次に，eBPF を利用するためのセットアップと gRPC を利用するためのセットアップを行います．

```
# eBPF のセットアップ
$ make -C ../ setup
# gRPC のセットアップ
$ make setup
```

最後にプロジェクトをビルドします．

```
$ make build
```

ビルドが完了すると `bin/` に実行ファイルが生成されます．

## 使い方

### scmlbd

### scmlb
