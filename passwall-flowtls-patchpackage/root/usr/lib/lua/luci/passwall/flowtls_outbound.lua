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

		-- 固定源端口。客户端防火墙规则靠它精确匹配内核回出的 RST，
		-- 端口随机的话规则写不出来。同一台机器上多个 FlowTLS 节点
		-- 必须用不同的 source_port。
		result.source_port = num(node.source_port)

		-- 伪包识别标记（IP ID 高字节）。必须与服务端 ip_id_mark 一致。
		result.ip_id_mark = num(node.ip_id_mark)

		-- 只影响伪 ClientHello 的外观，不参与任何校验
		result.sni = str(node.sni)

		-- 三次握手：symbolic（默认）/ none
		result.handshake = str(node.handshake)

		-- 防火墙规则落地方式：auto / none
		result.iptables_mode = str(node.iptables_mode)

		-- QUIC 拥塞窗口上限（字节）
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
