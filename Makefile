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

# 上游默认 tags 是逗号分隔，必须用逗号拼接，不能换成空格。
#
# **Windows 有独立的 tag 列表**（release/DEFAULT_BUILD_TAGS_WINDOWS），
# 比 OTHERS 多 with_naive_outbound 与 with_purego。
# 曾经这里只读 OTHERS，结果 windows 构建永远少两个特性，而 sing-box 官方
# 发的是带这两个 tag 的——同一个版本号下两个二进制能力不同，很难被发现。
TAGS_FILE := $(UPSTREAM_DIR)/release/DEFAULT_BUILD_TAGS_OTHERS
ifeq ($(GOOS),windows)
TAGS_FILE := $(UPSTREAM_DIR)/release/DEFAULT_BUILD_TAGS_WINDOWS
endif
UPSTREAM_TAGS := $(shell cat $(TAGS_FILE))
TAGS          := $(UPSTREAM_TAGS),with_flowtls

# 上游 LDFLAGS 只有 godebugDefault 和 checklinkname，不含 Version，
# 所以这里追加 Version 不会覆盖任何东西。
#
# 注意 `-checklinkname=0` 不是可选项：tfo-go 用 linkname 挂到 net 包的
# 内部符号（net.(*netFD).init），开启了链接器检查的平台会直接编译失败。
LDFLAGS_UPSTREAM := $(shell cat $(UPSTREAM_DIR)/release/LDFLAGS)
LDFLAGS          := -X 'github.com/sagernet/sing-box/constant.Version=$(VERSION)' $(LDFLAGS_UPSTREAM)

GOFLAGS_COMMON := -trimpath -tags "$(TAGS)" -ldflags "$(LDFLAGS) -s -w -buildid="
# Windows 产物必须带 .exe，否则下载下来双击打不开。
# 用 $(if $(filter ...)) 而不是 ifeq：这是赋值语句的一部分，不是指令块。
BIN := $(PREFIX)/sing-box-$(VERSION)-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe)

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

# 验收：版本号里必须带 rev，tags 里必须带 with_flowtls，且不含真实地址/凭据
#
# leak_check 必须在这里，不能只放 CI：2026-11-15 有一次先写了测量脚本、
# 忘了跑门禁就提交，真实跳板与服务端 IP 直接进了远端。
# 本地验收入口能拦住的事，不该等 CI。
#
# platforms 也在这里：它只要几秒，但能拦住「改了 rawSocket 字段名导致
# macOS/Windows 编译不过」这类回归——历史上 socket_stub.go 漏了 localIP
# 字段，macOS 长期编译不过而没人发现（发行目标只有 Linux）。
.PHONY: verify
verify: build platforms
	@echo "=== version ==="
	@./$(BIN) version
	@echo "=== assertions ==="
	@./$(BIN) version --name | grep -qx '$(VERSION)' \
		|| { echo "FAIL: version name mismatch"; exit 1; }
	@./$(BIN) version | grep -q 'with_flowtls' \
		|| { echo "FAIL: with_flowtls tag missing"; exit 1; }
	@echo "=== leak check ==="
	@bash docs/leak_check.sh
	@echo "OK"

# 全平台编译门禁（只编 flowtls 模块，不编 sing-box，几秒内跑完）。
#
# 为什么要覆盖 darwin/freebsd：这两个平台永远不会运行，但它们**必须能编译**——
# `sing-box check` 在 macOS 上是常事，编译不过等于适配层白写。
# 只编不跑，因此不需要任何特权。
PLATFORMS := linux/amd64 linux/arm64 linux/arm windows/amd64 windows/386 \
             darwin/amd64 darwin/arm64 freebsd/amd64

.PHONY: platforms
platforms:
	@set -e; cd flowtls; \
	for p in $(PLATFORMS); do \
		os=$${p%%/*}; arch=$${p##*/}; \
		if out=$$(GOOS=$$os GOARCH=$$arch go build ./... 2>&1); then \
			echo "  ok   $$os/$$arch"; \
		else \
			echo "  FAIL $$os/$$arch"; echo "$$out"; exit 1; \
		fi; \
	done

# 单独的泄露检查（不需要 build，提交前随时跑）
.PHONY: leak
leak:
	bash docs/leak_check.sh

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

# Windows 产物（本机交叉编译，只用于验证能编译；正式发布走 build.yml）
.PHONY: windows
windows:
	$(MAKE) build GOOS=windows GOARCH=amd64

# 冻结向量门禁：验证 wire format 没有漂移，不需要 root、不需要 Rust
.PHONY: interop
interop:
	bash docs/interop_check.sh

# 真链路矩阵（需要 root）。未设 RUST_FLOWTLS 时只跑 Go↔Go
.PHONY: e2e
e2e: build
	bash docs/e2e_matrix.sh
# PassWall 补丁包（.ipk/.apk，架构无关）
#
# 这个包不含内核，所以不依赖 build。apk 的容器格式需要 apk-tools，
# 用 APK_TOOL 指过去（OpenWrt SDK 的 staging_dir/host/bin/apk）；
# 不指定时只出 .ipk。
#
# 本地签名需要 deploy/apk-signing.key（已被 .gitignore 忽略）。
.PHONY: passwall
passwall:
	@set -e; cd passwall-flowtls-patchpackage; \
	APKARG=''; [ -n "$(APK_TOOL)" ] && APKARG="--apk-tool $(APK_TOOL)"; \
	KEYARG=''; [ -n "$(SIGN_KEY)" ] && KEYARG="--sign-key $(SIGN_KEY)"; \
	sh scripts/pack.sh --out dist $$APKARG $$KEYARG

# 补丁包的纯逻辑单测（不需要 OpenWrt、不需要 root）
.PHONY: passwall-test
passwall-test:
	@cd passwall-flowtls-patchpackage && lua scripts/luatest.lua .
# 同步上游：pull 后预期只有 include/registry.go 的 2 行冲突
.PHONY: upstream-pull
upstream-pull:
	@test -n "$(TO)" || { echo "usage: make upstream-pull TO=v1.15.0"; exit 1; }
	git subtree pull --prefix $(UPSTREAM_DIR) https://github.com/SagerNet/sing-box $(TO) --squash

.PHONY: clean
clean:
	rm -rf $(PREFIX)
