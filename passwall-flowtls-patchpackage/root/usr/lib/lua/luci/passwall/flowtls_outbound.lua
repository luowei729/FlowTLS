-- FlowTLS × PassWall —— 出站字段补全
--
-- 本文件由 passwall-flowtls apply 注入到 util_sing-box.lua：
--     local _w = _f(gen_outbound)   -- 包住全局函数
--     if type(_w) == "function" then gen_outbound = _w end
--
-- 为什么用「包装全局函数」而不是往文件中间插代码：
--   util_sing-box.lua 里 gen_outbound 是**全局**函数
--   （`function gen_outbound(...)` 没有 local），而且 gen_config 内部
--   也是按全局名调它。所以只要在文件尾部把 _G.gen_outbound 换掉，
--   所有调用点自动生效，**不用碰 gen_outbound 的任何一行内部实现**。
--   这正是「最小侵入」的关键：PassWall 把 gen_outbound 重写得面目全非
--   也不影响我们，只要它仍然返回一张以 type 表示协议的出站表。
--
-- 协议无关性：包装器对非 flowtls 节点原样返回，零开销、零行为变化。
return function(orig)
	if type(orig) ~= "function" then
		return nil
	end

	-- 数字字段转成数字；空串/nil 一律当成「没填」，交给核心默认值。
	local function num(v)
		if v == nil then return nil end
		local n = tonumber(v)
		if n == nil or n <= 0 then return nil end
		return n
	end

	-- 字符串字段：空串视为未填
	local function str(v)
		if type(v) ~= "string" then return nil end
		if v == "" then return nil end
		return v
	end

	return function(flag, node, tag, proxy_table)
		local result = orig(flag, node, tag, proxy_table)

		-- 只处理 flowtls；其它协议原样返回，行为和没打补丁时完全一致。
		if type(result) ~= "table" or result.type ~= "flowtls" then
			return result
		end

		-- PassWall 会按「TLS 传输层 + 多路复用 + v2ray 传输」的通用逻辑
		-- 往里塞字段。FlowTLS 自带伪 TLS，用不到这些，而且 sing-box 的
		-- flowtls 出站不认识它们（未知字段会导致启动失败），必须清掉。
		result.tls = nil
		result.multiplex = nil
		result.transport = nil
		result.udp_over_tcp = nil
		result.packet_encoding = nil

		-- 与服务端一致的认证口令（外层 AEAD 密钥来源）
		result.password = node.password

		-- 源端口：**刻意不写**，交给内核自动分配。
		--
		-- 一条 FlowTLS 隧道就是一个固定四元组，服务端靠它定位会话。
		-- 固定源端口等于「一条隧道占一个端口」，而两台机器（或同一台
		-- 机器的多个节点）经同一个 NAT 去同一台服务端时，源端口相同就会
		-- 四元组撞车——服务端只认一个会话，新 SYN 把旧会话踢掉，两边反复
		-- 互踢（真机踩过：haproxy 把 FlowTLS 后端反复标 DOWN）。
		--
		-- 旧版必须固定，是因为客户端防火墙规则按源端口匹配内核回的 RST。
		-- 现在规则改为按**服务端地址**匹配（见 flowtls/rules.go 的
		-- clientRules），与源端口无关，所以可以不写这个字段。
		--
		-- 如果旧配置里已经存了 source_port（升级前的数据），一并清掉：
		-- 留着它会让该节点继续退回固定端口，问题照旧。
		result.source_port = nil

		-- IP ID 标记：**刻意不写**，由核心从 password 派生。
		--
		-- 派生能同时满足两个硬要求（见 flowtls/mark.go）：
		--   - 两端自动一致 —— password 本来就两端共享，客户端和服务端
		--     各自 HKDF 一次就得到同一个 mark，不需要任何手工同步；
		--   - 部署间自动不同 —— password 不同，mark 自然不同，不留公开指纹。
		-- 多用户时服务端会为每个用户的 password 各派生一个，全部纳入识别
		-- 范围（内核层判断「是不是我们的包」时还没解密，不知道对端是谁）。
		--
		-- 旧配置里若存过 ip_id_mark，一并清掉：留着它就等于把 mark 钉回
		-- 一个固定值，失去上面两个好处。
		result.ip_id_mark = nil

		-- 只影响伪 ClientHello 的外观，不参与任何校验
		result.sni = str(node.sni)

		-- 三次握手：symbolic（默认）/ none
		result.handshake = str(node.handshake)

		-- 防火墙规则：**刻意不写**。核心库已改为强制写入（没有开关），
		-- 因为那两条规则（notrack + RST 抑制）不是可选优化，而是协议
		-- 能工作的前提。写个 iptables_mode=none 只会让隧道静默不通。
		-- 旧配置里若还留着这个字段，一并清掉。
		result.iptables_mode = nil
		result.max_cwnd = num(node.max_cwnd)

		-- UDP 三态：留空＝跟随核心默认（开启），1＝开，0＝关。
		-- 用三态是因为「没填」和「显式关闭」语义不同：
		-- 前者要继承服务端默认，后者要真的关掉。
		if node.udp_enabled == "1" then
			result.udp_enabled = true
		elseif node.udp_enabled == "0" then
			result.udp_enabled = false
		end

		return result
	end
end
