-- FlowTLS × PassWall —— 客户端日志开关
--
-- 本文件由 passwall-flowtls apply 注入到 util_sing-box.lua：
--     local _w = _f(gen_config)   -- 包住全局函数
--     if type(_w) == "function" then gen_config = _w end
--
-- ## 为什么需要它
--
-- PassWall 的 haproxy 后端（面板里那些 `M1-xxx` / `B1-xxx`）是由
-- `haproxy.lua` 调 `app.sh run_socks` 起的，而那次调用**不传 log_file**：
--
--     sys.call(string.format('/usr/share/%s/app.sh run_socks "%s" > /dev/null',
--         appname, string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s", ...)
--
-- 于是 app.sh 里的 `[ -n "$log_file" ] || log_file="/dev/null"` 命中，
-- 接着 `json_add_string "log" "0"`，最终生成的配置里是：
--
--     "log": { "disabled": true, "output": "/dev/null" }
--
-- 结果：**客户端侧出任何问题都没有任何记录**。2026-11-28 排查
-- 「节点反复 DOWN」时就卡在这里——只能靠服务端日志和服务端侧的
-- 每 2 秒路径统计反推，客户端到底是在收包、还是在阻塞，完全看不见。
--
-- ## 为什么只开 warn 级
--
-- 这台路由器是**单核**，而且卡顿本身很可能就来自 CPU 争抢
-- （同时跑着 haproxy + 两个 sing-box + PassWall 的 nft 规则）。
-- 开 info/debug 会按「每条连接一行」的速度写内存盘，既吃 CPU 又吃 RAM，
-- 等于给正在排查的问题添柴。warn 级只记错误（发送失败、流异常、
-- 连接错误），量极小，却能覆盖绝大多数「为什么断了」的分支。
--
-- 需要短期抓细节时，写一个 marker 文件再重跑 apply 即可升到 debug：
--     echo debug > /tmp/etc/passwall/flowtls-log-level
--     /usr/bin/passwall-flowtls apply
-- 排查完删掉 marker、再 apply 一次就回到 warn（零残留）。
--
-- ## 怎么临时关掉
--
--     rm -f /tmp/etc/passwall/flowtls-client.log.on
--     /usr/bin/passwall-flowtls apply
-- 之后新生成的配置恢复成原来的 disabled=true。
return function(orig)
	if type(orig) ~= "function" then
		return nil
	end

	local LOG_ON   = "/tmp/etc/passwall/flowtls-client.log.on"
	local LOG_FILE = "/tmp/etc/passwall/flowtls-client.log"
	local LVL_FILE = "/tmp/etc/passwall/flowtls-log-level"

	local function exists(path)
		local f = io.open(path, "r")
		if f then f:close() return true end
		return false
	end

	-- 日志级别：默认 warn；marker 文件里写 info/debug/trace 可以临时提高。
	-- 只接受四个合法值，写错就落回 warn，避免把非法值喂给 sing-box
	-- （它会在解析配置时直接退出，表现为「节点起不来」）。
	local function level()
		local f = io.open(LVL_FILE, "r")
		if not f then return "warn" end
		local v = f:read("*l")
		f:close()
		v = type(v) == "string" and v:gsub("%s", ""):lower() or ""
		if v == "info" or v == "debug" or v == "trace" or v == "warn" then
			return v
		end
		return "warn"
	end

	return function(var)
		-- 开关文件不存在时**完全不动** var，行为与没打补丁时一致。
		if exists(LOG_ON) and type(var) == "table" then
			-- 只在 PassWall 自己关掉了日志时接管；用户显式开了日志的
			-- 配置不去覆盖（尊重用户的选择）。
			if var["log"] ~= "1" then
				var["log"] = "1"
				var["logfile"] = LOG_FILE
				var["loglevel"] = level()
			end
		end
		return orig(var)
	end
end
