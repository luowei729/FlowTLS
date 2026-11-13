# sing-box (FlowTLS rev) 构建脚本
#
# 设计要点：
#   1. 二进制名保持 `sing-box`，只用版本号区分官方版；
#   2. 版本号是纯构建期注入（ldflags），**不改上游任何源码**；
#   3. 上游源码在 sing-box/ 子目录（git subtree），本文件只加 with_flowtls tag。
#
# 版本号格式：<上游版本>-rev.<自增>，例如 1.14.4-rev.1
#   - 合法 semver prerelease，第三方客户端可直接 parse；
#   - 排序低于同版本官方版，不会被误判成「比官方新」。
# 唯一真源是同目录的 VERSION 文件。

VERSION      := $(shell cat VERSION)
UPSTREAM_DIR := sing-box
PREFIX       ?= dist
# GOOS/GOARCH 必须在 BIN 之前定义：BIN 用的是 := 立即展开，
# 如果写在后面，$(GOOS) 展开成空串，产物名会变成 sing-box-1.14.4-rev.1--。
GOOS         ?= linux
GOARCH       ?= amd64

# 上游默认 tags 是逗号分隔，必须用逗号拼接，不能换成空格
UPSTREAM_TAGS := $(shell cat $(UPSTREAM_DIR)/release/DEFAULT_BUILD_TAGS_OTHERS)
TAGS          := $(UPSTREAM_TAGS),with_flowtls

# 上游 LDFLAGS 只有 godebugDefault 和 checklinkname，不含 Version，
# 所以这里追加 Version 不会覆盖任何东西。
LDFLAGS_UPSTREAM := $(shell cat $(UPSTREAM_DIR)/release/LDFLAGS)
LDFLAGS          := -X 'github.com/sagernet/sing-box/constant.Version=$(VERSION)' $(LDFLAGS_UPSTREAM)

GOFLAGS_COMMON := -trimpath -tags "$(TAGS)" -ldflags "$(LDFLAGS) -s -w -buildid="
BIN            := $(PREFIX)/sing-box-$(VERSION)-$(GOOS)-$(GOARCH)

.PHONY: build
build:
	cd $(UPSTREAM_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(GOFLAGS_COMMON) -o ../$(BIN) ./cmd/sing-box
	@echo "built: $(BIN)"

# 交叉编译：make build GOARCH=arm64
.PHONY: release
release:
	$(MAKE) build GOOS=$(GOOS) GOARCH=$(GOARCH)

# 软路由/NAS 是主力场景：静态 musl 版本单独出
.PHONY: release-musl
release-musl:
	cd $(UPSTREAM_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(GOFLAGS_COMMON) -o ../$(PREFIX)/sing-box-$(VERSION)-linux-amd64-musl ./cmd/sing-box
	@echo "built: $(PREFIX)/sing-box-$(VERSION)-linux-amd64-musl"

# 验收：版本号里必须带 rev，tags 里必须带 with_flowtls
.PHONY: verify
verify: build
	@echo "=== version ==="
	@./$(BIN) version
	@echo "=== assertions ==="
	@./$(BIN) version --name | grep -qx '$(VERSION)' \
		|| { echo "FAIL: version name mismatch"; exit 1; }
	@./$(BIN) version | grep -q 'with_flowtls' \
		|| { echo "FAIL: with_flowtls tag missing"; exit 1; }
	@echo "OK"

# 配置校验（不需要 root，这是硬要求）
.PHONY: check
check: build
	@./$(BIN) check -c $(CONFIG)

# 单测（含竞态检测）。Rust 参考实现已冻结，主分支只跑 Go。
#
# 两部分：flowtls 模块本身的传输层/规则层，以及 sing-box 侧适配层。
# 适配层原来一个测试都没有，直到 masquerade 的配置校验被放到 Start 里
# 导致 check 静默通过——那件事之后补上了（见 DEVTIPS 第 76 条）。
.PHONY: test
test:
	cd flowtls && go test -race ./...
	cd $(UPSTREAM_DIR) && go test -race ./protocol/flowtls/...

# 冻结向量门禁：验证 wire format 没有漂移，不需要 root、不需要 Rust
.PHONY: interop
interop:
	bash docs/interop_check.sh

# 真链路矩阵（需要 root）。未设 RUST_FLOWTLS 时只跑 Go↔Go
.PHONY: e2e
e2e: build
	bash docs/e2e_matrix.sh

# 同步上游：pull 后预期只有 include/registry.go 的 2 行冲突
.PHONY: upstream-pull
upstream-pull:
	@test -n "$(TO)" || { echo "usage: make upstream-pull TO=v1.15.0"; exit 1; }
	git subtree pull --prefix $(UPSTREAM_DIR) https://github.com/SagerNet/sing-box $(TO) --squash

.PHONY: clean
clean:
	rm -rf $(PREFIX)
