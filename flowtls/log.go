package flowtls

// 本文件定义 flowtls 的**诊断日志出口**，让所有日志受宿主的日志级别控制。
//
// # 为什么需要它（改造前的真实问题）
//
// 改造前，flowtls 主包的诊断日志全走标准库 `log.Printf`。这些行**无条件**
// 写到 stderr，完全绕过 sing-box 的 `log.level`：
//
//	"log": { "level": "error" }   ← 用户以为这就安静了
//	但「flowtls: 发送失败（累计 N 次）」仍然照刷
//
// 与此同时 `QUIC 路径统计` 走的是 `logger.Debug`（受 log.level 控制），
// 于是同一份日志里一半受控、一半不受控——用户无法用一个开关关掉全部噪声。
//
// # 设计取舍：不加自己的开关，直接复用宿主的 logger
//
// 方法签名刻意与 sing-box `log.ContextLogger`（实为 sing/log/logger.Logger）
// 的 Debug / Info / Warn / Error **完全一致**，所以适配层直接传 logger 进来即可，
// **不需要任何适配器代码**：
//
//	// sing-box 适配层
//	cfg := ft.ClientConfig{ /* ... */ , Logger: o.logger }
//
// 级别过滤全部交给宿主：传了就是允许，不传就是静默。
// flowtls 自己不判断级别、不维护 `debug: true` 这类自造参数——
// v1/v2 的自造字段都因为「配上去没有任何效果」被删过一遍。
//
// # 为什么 nil 表示静默而不是回退到标准库
//
// 库不该在宿主不知情时往 stderr 写字。回退到标准库会让「不传 Logger」
// 变成「行为与传之前一样吵」，注入就失去了意义。
// 需要看日志的联调工具显式用 StdLogger() 即可（见文件末尾）。

import (
	"fmt"
	"log"
)

// Logger 是 flowtls 的诊断日志出口。
//
// 与 sing-box `log.ContextLogger` 的前四个方法签名逐字一致，因此
// 适配层可以**直接把 logger 赋值给配置字段**，无需适配器。
//
// nil 是合法值，语义为「静默」；调用点统一经 loggerOr 归一，
// 不需要每次判空。
type Logger interface {
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
}

// nopLogger 是静默实现，用于 Logger 为 nil 时兜底。
type nopLogger struct{}

func (nopLogger) Debug(args ...any) {}
func (nopLogger) Info(args ...any)  {}
func (nopLogger) Warn(args ...any)  {}
func (nopLogger) Error(args ...any) {}

// loggerOr 把 nil 归一成 nopLogger，让调用点可以无条件调方法。
func loggerOr(l Logger) Logger {
	if l == nil {
		return nopLogger{}
	}
	return l
}

// stdLogger 把标准库 log 适配为 Logger，**仅用于联调工具与单测**。
//
// 生产路径由 sing-box 适配层注入自己的 logger；这里保留一份标准库实现，
// 是为了让 `cmd/ftdial`、`cmd/ftserver` 这类不依赖 sing-box 的工具
// 也能看到完整日志，而不必各自抄一遍适配器。
type stdLogger struct{}

func (stdLogger) Debug(args ...any) { log.Print("DEBUG flowtls: ", fmt.Sprint(args...)) }
func (stdLogger) Info(args ...any)  { log.Print("INFO flowtls: ", fmt.Sprint(args...)) }
func (stdLogger) Warn(args ...any)  { log.Print("WARN flowtls: ", fmt.Sprint(args...)) }
func (stdLogger) Error(args ...any) { log.Print("ERROR flowtls: ", fmt.Sprint(args...)) }

// StdLogger 返回一个输出到标准库 log 的 Logger（联调工具与单测用）。
//
// **不要在生产适配层用它**：那等于绕过 sing-box 的 log.level，
// 正是本次改造要消除的行为。
func StdLogger() Logger { return stdLogger{} }
