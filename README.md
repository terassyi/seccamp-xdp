# Seccamp-XDP

このリポジトリは 「XDP 入門」の講義資料及びサンプルコードです．

> **Note**
> 以下の資料は [SECCON Workshop Fukuoka](https://www.seccon.jp/2023/seccon_workshop/xdp.html) で使用したものです．
> この資料は XDP 入門の資料をアップデートしたものとなっています．

[スライド - XDP で作って学ぶファイアウォールとロードバランサー](https://docs.google.com/presentation/d/1EUC4c68r0T36sDWz6M6zGk4WFGEKqZ6Q6F_peICAZng/edit?usp=sharing)

---

## 想定対象者

- eBPF/XDP に興味がある方
- ネットワークロードバランサーやファイアウォールの実装に興味がある方
- とりあえず eBPF/XDP で動くものを作ってみたい方

## 進め方

> **Warning**
> XDP プログラムを動作させるためには Linux 環境が必要です．
> Docker, WSL 環境では動作しません．

本資料を使ったハンズオンは基礎編と実践編の二つのパートで構成されています．
XDP の知識が少ない方は基礎編，実践編の順に進めることをお勧めします．
XDP のコードを書いたことのある方は実践編のみでよいです．

基礎編では `hello world` を出力するだけの簡単なプログラムからパケットカウンタの XDP プログラムを実装，動作させることで XDP プログラムの書き方や動かし方を学びます．

実践編では最終的にシンプルなネットワークロードバランサーである `scmlb` を実装して動かすことをゴールとしています．
`scmlb` は以下の機能を有します．

- パケットカウンタ
- ファイアウォール
- 非常に単純な DoS 攻撃防御機能
- ラウンドロビンによるロードバランサー

データプレーンは XDP で実装し，コントロールプレーンには Go 言語を利用しています．

詳しくは [scmlb/README.md](https://github.com/terassyi/seccamp-xdp/tree/main/scmlb)を参照してください．


## 構成

ディレクトリ構成は以下のようになっています．

- app
	- ハンズオンで利用するテスト用アプリケーションのコード及びビルドスクリプト
- scmlb
	- ハンズオンの実践編で利用するネットワークロードバランサーの実装
	- 詳しくは [scmlb/README.md](https://github.com/terassyi/seccamp-xdp/tree/main/scmlb)を参照してください．
- topology
	- ハンズオンで利用するネットワークを作成するためのスクリプト群
- tutorial
	- ハンズオンの基礎編で利用する XDP 関連コード

## セットアップ

必要なツールをセットアップします．

セットアップは各々の環境によって異なるので必要に応じて実行してください．

### ビルド/ネットワーク操作関連ツール

```console
$ make setup
```

### Go 言語

本リポジトリで実装するロードバランサー(scmlb) のコントロールプレーンに Go 言語を利用しています．
動作させるために バージョン `1.20` 以上の Go 言語が必要です．
インストールには以下のコマンドを実行してください．

```console
$ make setup-golang
```

任意のバージョンを指定してインストールしたい場合は以下のように実行してください．

```console
$ make GO_VERSION=<インストールしたいバージョン> setup-golang
```

### bpftool

bpftool は eBPF プログラムやマップを操作するためのコマンドです．
以下のコマンドでインストールできます．

```console
$ make bpftool
```

### gRPC 関連

本リポジトリで実装するロードバランサー(scmlb) でデーモンプログラム(scmlbd) と CLIプログラム(scmlb) の通信を gRPC を利用して実装しています．
以下のコマンドで gRPC 関連のツールのセットアップができます．

```console
$ make -C scmlb setup
```
