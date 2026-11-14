# passmeter 构建入口。
#
# 目标顺序：数据 → 核心 → WASM → 站点 → 服务端。
# 「make all」是全新克隆后的完整构建。

SHELL := /bin/bash
RAW   := data/raw
GEN   := data/generated
WEB   := web

.PHONY: all data breach core wasm web server test lint bench compare clean help

help:
	@echo "make data     从 data/raw 构建词典索引"
	@echo "make breach   构建 k-匿名泄露库"
	@echo "make wasm     编译 WASM 并复制到 web/"
	@echo "make server   编译查询服务"
	@echo "make test     跑全部测试"
	@echo "make compare  生成对比测试报告"
	@echo "make bench    跑性能基准"
	@echo "make all      以上全部"

all: data breach core wasm web server

data:
	@test -f $(RAW)/rockyou-withcount.txt || { echo "缺少 $(RAW)/rockyou-withcount.txt，先跑 tools/fetch_data.sh"; exit 1; }
	python3 -I tools/build_data.py

breach: data
	python3 -I tools/build_breach_db.py

core:
	cargo build --release -p passmeter-core

wasm:
	cargo build --target wasm32-unknown-unknown --release -p passmeter-wasm
	@mkdir -p $(WEB)
	cp target/wasm32-unknown-unknown/release/passmeter_wasm.wasm $(WEB)/
	cp $(GEN)/dict2.bin $(WEB)/
	@ls -lh $(WEB)/passmeter_wasm.wasm $(WEB)/dict2.bin

web: wasm
	@echo "站点已就绪：web/index.html"

server:
	cargo build --release -p passmeter-server

test:
	cargo test --release --workspace
	@echo "— 对比测试（相关性护栏）—"
	cargo test --release -p passmeter-core --test compare

compare:
	python3 -I tools/gen_compare_set.py
	@mkdir -p crates/passmeter-core/tests/data
	@cp tests/data/compare_set.txt tests/data/truth.tsv crates/passmeter-core/tests/data/
	cargo run --release -q -p passmeter-core --example dump_json < tests/data/compare_set.txt > /tmp/ours.json
	node tools/run_zxcvbn.js < tests/data/compare_set.txt > /tmp/zx.json
	python3 -I tools/compare.py --ours /tmp/ours.json --zxcvbn /tmp/zx.json --truth tests/data/truth.tsv --min-len 6

bench:
	cargo run --release -q -p passmeter-core --example bench

lint:
	cargo clippy --workspace --all-targets -- -D warnings

clean:
	cargo clean
	rm -f $(WEB)/passmeter_wasm.wasm $(WEB)/dict2.bin
