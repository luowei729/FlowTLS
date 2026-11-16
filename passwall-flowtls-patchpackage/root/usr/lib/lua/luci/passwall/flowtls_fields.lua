-- FlowTLS × PassWall —— 节点配置界面扩展
--
-- 本文件由 passwall-flowtls apply 注入到
--   /usr/lib/lua/luci/model/cbi/passwall/client/type/1_sing-box.lua
-- 调用点用 loadfile + setfenv(getfenv(1)) 加载，所以本文件里的全局名
-- （translate / Value / ListValue …）继承的是 PassWall 自己的环境。
-- **不能用 dofile**：dofile 恒定用 _G，而 translate 不在 _G 里，
-- 症状是「协议能选 FlowTLS，但下面的端口/SNI 等字段一个都不出现」。
--     local _ok, _f = pcall(dofile, "<本文件>")
--     if _ok and type(_f) == "function" then _f(m, s, s1) end
--
-- 为什么必须插在 type_cbi_section 之前：
--   那个函数把临时 section s 里的控件搬到真正的 section s1，
--   之后再 s:option(...) 加进来的控件会挂在已经搬空的临时 section 上，
--   页面上根本不会出现（症状是「填了保存不了，刷新就没了」）。
--
-- 为什么新增协议而不是新增一个独立 type：
--   FlowTLS 就是一个 sing-box 出站，走 PassWall 的 sing-box 主实例最省资源
--   （不额外起进程、不额外占端口）。独立 type 会被 PassWall 当成
--   「另一个客户端程序」，要走 app.sh 的 run_socks 分支，成本高得多。
--
-- 失败必须留痕：
--   注入点的 pcall 会吞掉所有异常，而「界面少几个字段」本身不报错，
--   只会表现为「协议选 FlowTLS 后没有端口/口令可填」。所以这里自己再包
--   一层 xpcall，把错误连同调用栈写进 /tmp 与 syslog。
--   同时保证**无论如何都不影响其它协议的正常使用**。

local ERR_FILE = "/tmp/passwall-flowtls-ui.err"

local function report(err)
	local msg = "FlowTLS 节点界面扩展失败：" .. tostring(err)
	pcall(function()
		local f = io.open(ERR_FILE, "w")
		if f then
			f:write(msg, "\n")
			f:close()
		end
	end)
	pcall(function()
		local sys = require "luci.sys"
		sys.call("logger -t passwall-flowtls " .. string.format("%q", msg))
	end)
end

local function build(m, s, s1)
	if type(s) ~= "table" or type(s.fields) ~= "table" then
		return
	end

	-- translate 的兜底兼容：正常路径下它来自 PassWall 的环境，
	-- 万一将来环境变了也不会整个扩展挂掉（只丢翻译，不丢字段）。
	local tr = _G.translate
	if type(tr) ~= "function" then
		local ok, i18n = pcall(require, "luci.i18n")
		tr = (ok and type(i18n.translate) == "function") and i18n.translate
			or function(text) return text end
	end

	-- protocol 列表由 1_sing-box.lua 创建，我们只是追加一个取值。
	local proto = s.fields["protocol"]
	if not proto then
		return
	end
	proto:value("flowtls", "FlowTLS")

	-- 共享字段必须手动登记 flowtls，否则页面上就不存在「地址」和「端口」。
	--
	-- 原因：1_sing-box.lua 末尾有一段循环，拿 protocol 的 keylist 逐个
	-- 给 address / port / domain_resolver / domain_strategy 挂
	-- depends({protocol=v})：
	--     local protocols = s.fields["protocol"].keylist
	--     for _, v in ipairs(protocols) do ... s.fields["address"]:depends(...) end
	-- 那段循环在我们追加 flowtls **之前**就跑完了，所以流着 flowtls 时
	-- 这四个字段一个 depends 都不命中，被判定成一整行不渲染。
	-- 现象就是「选了 FlowTLS 后没有服务器地址/端口可填」，而密码能填
	-- （密码有单独一行 depends，我们已经补过）。
	--
	-- 同样给 password 补一条（其余协议都靠各自 type 文件里逐行 depends）。
	for _, name in ipairs({ "address", "port", "domain_resolver",
		"domain_strategy", "password" }) do
		local f = s.fields[name]
		if f and type(f.depends) == "function" then
			f:depends({ protocol = "flowtls" })
		end
	end

	-- 统一构造：都挂 depends({protocol="flowtls"})，
	-- 选别的协议时自动隐藏，不影响原有界面。
	local function opt(class, name, title, desc)
		local o = s:option(class, name, title, desc)
		if o then
			o:depends({ protocol = "flowtls" })
		end
		return o
	end

	-- 固定源端口 ------------------------------------------------------------
	-- 为什么必须固定：客户端防火墙规则按源端口精确匹配内核回出的 RST，
	-- 端口随机的话规则写不出来（只能整段 DROP，会误伤正常流量）。
	-- 同一台机器上有多个 FlowTLS 节点时，每个节点必须用不同端口。
	local o = opt(Value, "source_port", tr("源端口"),
		tr("固定源端口，客户端防火墙靠它精确拦截内核 RST。多个 FlowTLS 节点必须互不相同。"))
	if o then
		o.datatype = "port"
		o.default = "44300"
		o.rmempty = false
	end

	-- IP ID 标记 ------------------------------------------------------------
	-- 伪包识别特征：IP 头的 ID 高字节。必须与服务端的 ip_id_mark 完全一致，
	-- 且每个部署应不同（它是抗主动探测的一部分，公开就等于交出指纹）。
	o = opt(Value, "ip_id_mark", tr("IP ID 标记"),
		tr("伪包识别标记（十进制 0-65535），必须与服务端 ip_id_mark 一致。例如 0xF107 = 61703。"))
	if o then
		o.datatype = "port"
		o.default = "61703"
	end

	-- SNI ------------------------------------------------------------------
	o = opt(Value, "sni", tr("SNI"),
		tr("只影响伪 ClientHello 的外观，不参与任何校验。填一个真实的、与你服务器同域名的站点。"))

	-- 握手方式 --------------------------------------------------------------
	o = opt(ListValue, "handshake", tr("握手方式"),
		tr("symbolic 是标准三次握手（默认）。none 只在链路无状态检查时可用，会导致严格 NAT 丢包。"))
	if o then
		o.default = "symbolic"
		o:value("symbolic", "Symbolic")
		o:value("none", "None")
	end

	-- 防火墙规则落地方式 ----------------------------------------------------
	o = opt(ListValue, "iptables_mode", tr("防火墙模式"),
		tr("auto 自动写入 nftables/iptables 规则（推荐）。none 表示由你自己维护。"))
	if o then
		o.default = "auto"
		o:value("auto", tr("自动（推荐）"))
		o:value("none", tr("不处理"))
	end

	-- 拥塞窗口上限 ----------------------------------------------------------
	o = opt(Value, "max_cwnd", tr("最大拥塞窗口"),
		tr("字节。默认 8388608（8MB）。跨境小带宽链路建议 1048576（1MB）。应与服务端一致。"))
	if o then
		o.datatype = "uinteger"
		o.default = "8388608"
	end

	-- UDP 三态 --------------------------------------------------------------
	-- 留空＝跟随核心默认（开启）。刻意不写成 Flag：
	-- Flag 的「关」会写 0，而「没配过」是空——两者语义不同，
	-- 混在一起会让默认值的变化被静默继承。
	o = opt(ListValue, "udp_enabled", tr("UDP"),
		tr("留空＝跟随核心默认（开启）。关闭后 QUIC/UDP 流量无法通过隧道。"))
	if o then
		o.default = ""
		o:value("", tr("跟随核心默认（开启）"))
		o:value("1", tr("开启"))
		o:value("0", tr("关闭"))
	end
end

return function(m, s, s1)
	-- xpcall + traceback：出错时把调用栈一起记下来，
	-- 否则只有一句 "attempt to call a nil value"，无从定位。
	local ok, err = xpcall(function()
		build(m, s, s1)
	end, function(e)
		return tostring(e) .. "\n" .. debug.traceback()
	end)
	if not ok then
		report(err)
	end
end
