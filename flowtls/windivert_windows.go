//go:build windows && (amd64 || 386)

package flowtls

// WinDivert 驱动的用户态封装（Windows 专用）。
//
// # 为什么需要它
//
// 微软自 Vista 起禁止用 raw socket 构造 TCP/UDP 包（防源地址伪造）：
// `IP_HDRINCL` 只对 ICMP 生效，也没有 `AF_PACKET` 的对应物。
// 所以在 Windows 上「自己写 IP/TCP 头」这件事**只能**借助内核包拦截驱动。
//
// WinDivert 基于 WFP（Windows Filtering Platform）：
//
//	WinDivertRecv → 扣留匹配的包（内核看不到，直到我们放行或丢弃）
//	WinDivertSend → 把我们构好的包注入网络栈
//
// 这与 Linux 的 `AF_PACKET`（被动复制，内核照常处理）**语义完全不同**，
// 差异清单见 PROJECT_PLAN.md §W2。
//
// # 与本机验证能力的关系
//
// 本文件**没有在本仓的任何 Windows 主机上运行过**（开发环境没有 Windows）。
// 它能通过的是交叉编译与静态检查；设备 IOCTL、驱动安装、注入时序
// 全部未验证。首次部署必须按 PROJECT_PLAN.md §W9 的手工清单逐项确认。
//
// 协议常量（IOCTL 编号、magic、结构体大小）与 WinDivert 2.2.2 一致，
// 与 sing-box 的 `common/windivert` 同源。
//
// # 许可
//
// 嵌入的 `windivert_assets/WinDivert64.sys` / `WinDivert32.sys` 是
// WinDivert 官方发行版，按 LGPL v3 再分发，许可证见同目录 LICENSE.txt。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinDivert 服务名与设备名（驱动固定值，不随版本变化）。
const (
	wdivDriverService = "WinDivert"
	wdivDriverDevice  = `\\.\WinDivert`
)

// wdivAssetVersion 是嵌入驱动的版本号，也是落盘路径的一部分。
//
// 带版本目录是为了让升级后不会用到旧驱动（驱动与 DLL 版本必须匹配，
// 不匹配时 `initialize` 阶段的 magic 校验会失败）。
const wdivAssetVersion = "2.2.2"

// 驱动安装的重试参数。
//
// Windows 的驱动加载是异步的：`StartService` 返回后设备节点可能还没出现，
// 所以必须轮询 `CreateFile` 而不是假定立即可用。
const (
	wdivDriverReadyTimeout = 60 * time.Second
	wdivDriverPollInterval = 50 * time.Millisecond
)

// wdivDebug 是诊断开关，**进程内只读一次**。
//
// 不能在 `ioctl` / `Recv` 里直接调 `os.Getenv`：那两个函数在每收发一个报文时
// 都执行一次，而 Windows 的 `os.Getenv` 要进 syscall。按 10MB/s、1400 字节
// 一包计算约 7000 次/秒，纯读一个调试开关就白白消耗 syscall 预算，
// 表现为吞吐下降与延迟抖动。
//
// 开关只在启动前设置（`$env:FLOWTLS_WDIV_DEBUG = 1` 再启进程），读一次完全等价。
var wdivDebug = os.Getenv("FLOWTLS_WDIV_DEBUG") == "1"

// wdivHandle 是一个 WinDivert 句柄。
//
// 一个句柄同时承担「收」和「发」：**必须只有一个**。
// 驱动保证「同一优先级只扣留一次」，所以本句柄注入的包不会被自己再次扣留；
// 若拆成两个句柄（收一个、发一个），注入的包会被收的那个捕获，形成自环。
type wdivHandle struct {
	device windows.Handle
	// recvEvent / sendEvent 是**两个独立**的覆盖 I/O 事件对象。
	//
	// **必须分开，这是本文件最容易出错的一处。**
	// Windows 的 overlapped I/O 靠 event 通知「这个 IRP 完成了」。一个 event
	// 同时只能对应一个未完成请求：如果 Recv 正挂在 event 上空等（隧道没流量
	// 时它大部分时间都挂着），此时 Send 复用同一个 event 发起，那么 Send
	// 完成时 signal 会把这个 event 点亮 —— Recv 的 GetOverlappedResult
	// 于是立刻返回，拿到的却是别人的完成状态。
	//
	// 症状极具误导性：Send 看起来完全正常（包真的发出去了），
	// 而 Recv 永远阻塞或返回垃圾，表现为「握手超时」，且没有任何错误日志。
	// 本项目的第一次真机测试就栽在这里。
	//
	// 同一方向只会有一个未完成请求（readLoop 单协程收、txLoop 单协程发），
	// 所以两个 event 足够，不需要每次 ioctl 现建一个。
	//
	// 每个方向内复用是安全的：`NtDeviceIoControlFile` 在排队请求前会把 event
	// 清成未信号，不需要我们 ResetEvent。
	recvEvent windows.Handle
	sendEvent windows.Handle

	// 复用缓冲，避免每次调用都分配。
	recvAddr  wdivAddr
	recvAddrs []wdivAddr
	sendAddrs []wdivAddr
}

// wdivOpen 打开一个 WinDivert 句柄。
//
// filter 为 nil 表示「不扣留任何包」（只用于注入，本实现不用）。
// 失败时会尝试安装驱动；安装失败通常意味着没有管理员权限或被杀软拦截。
func wdivOpen(filter *wdivFilter) (*wdivHandle, error) {
	filterBin, filterFlags, err := filter.encode()
	if err != nil {
		return nil, err
	}
	device, err := wdivAcquireDevice()
	if err != nil {
		return nil, err
	}
	recvEvent, err := windows.CreateEvent(nil, 1, 0, nil) // manual reset, unsignaled
	if err != nil {
		_ = windows.CloseHandle(device)
		return nil, os.NewSyscallError("CreateEvent", err)
	}
	sendEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(recvEvent)
		_ = windows.CloseHandle(device)
		return nil, os.NewSyscallError("CreateEvent", err)
	}
	h := &wdivHandle{device: device, recvEvent: recvEvent, sendEvent: sendEvent}

	// 诊断输出：直接看驱动实际收到的过滤器字节。
	// 排查「收不到包」时这是唯一能区分「过滤器错」和「驱动没 divert」的手段。
	if wdivDebug {
		fmt.Fprintf(os.Stderr, "[wdiv-debug] filter=%d bytes flags=%#x bin=%x\n",
			len(filterBin), filterFlags, filterBin)
	}

	if err = h.initialize(); err != nil {
		_ = h.Close()
		return nil, err
	}
	if err = h.startup(filterBin, filterFlags); err != nil {
		_ = h.Close()
		return nil, err
	}
	return h, nil
}

// ---- 设备获取与驱动安装 ----

// wdivAcquireDevice 打开 `\\.\WinDivert`，必要时先安装驱动。
func wdivAcquireDevice() (windows.Handle, error) {
	device, err := wdivOpenDevice()
	if err == nil {
		return device, nil
	}
	// 权限不足 / 被安全软件拦截：重试没有意义，直接给出可操作的错误。
	if fatal := wdivFatalOpenError(err); fatal != nil {
		return 0, fatal
	}

	// 设备不存在（ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND /
	// ERROR_NO_SUCH_DEVICE）→ 装驱动。
	if installErr := wdivInstallDriver(); installErr != nil {
		return 0, installErr
	}

	// 驱动加载是异步的，轮询到设备出现为止。
	deadline := time.Now().Add(wdivDriverReadyTimeout)
	for {
		device, err = wdivOpenDevice()
		if err == nil {
			return device, nil
		}
		if fatal := wdivFatalOpenError(err); fatal != nil {
			return 0, fatal
		}
		if time.Now().After(deadline) {
			return 0, os.NewSyscallError("open WinDivert device (timeout)", err)
		}
		time.Sleep(wdivDriverPollInterval)
	}
}

func wdivOpenDevice() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(wdivDriverDevice)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
}

// wdivFatalOpenError 把这些错误归类为「重试无用，必须人工处理」。
func wdivFatalOpenError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return ErrWindivertUnsupported
	case errors.Is(err, windows.ERROR_DRIVER_BLOCKED):
		// 1275：被安全软件或虚拟化环境拦截。这是 Windows 上最常见的失败原因，
		// 单独指出，否则用户只会看到一句无法理解的 syscall 错误。
		return ErrWindivertUnsupported
	case errors.Is(err, windows.ERROR_INVALID_IMAGE_HASH):
		// 驱动签名无效：嵌入资产被篡改或系统策略过严。
		return ErrWindivertUnsupported
	}
	return nil
}

// wdivInstallDriver 把嵌入的 .sys 落盘并注册成内核服务。
//
// 落盘路径用 `%LocalAppData%\flowtls\windivert\v<版本>\`：
// 带版本目录保证升级后不会复用旧驱动（版本不匹配时 initialize 会失败）。
func wdivInstallDriver() error {
	sysPath, err := wdivWriteDriverAsset()
	if err != nil {
		return err
	}
	sysPathW, err := windows.UTF16PtrFromString(sysPath)
	if err != nil {
		return err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		// 打开 SCM 需要管理员权限；这是最常见的失败点。
		return ErrWindivertUnsupported
	}
	defer windows.CloseServiceHandle(manager)

	serviceNameW, _ := windows.UTF16PtrFromString(wdivDriverService)
	service, err := wdivOpenOrCreateService(manager, serviceNameW, sysPathW)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	err = windows.StartService(service, 0, nil)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return os.NewSyscallError("StartService WinDivert", err)
	}
	// 标记为删除：驱动会一直运行到最后一个句柄关闭，之后自动卸载。
	// 与 WinDivert 官方 DLL 的行为一致，避免留下常驻服务。
	_ = windows.DeleteService(service)
	return nil
}

func wdivOpenOrCreateService(manager windows.Handle, nameW, pathW *uint16) (windows.Handle, error) {
	service, err := windows.OpenService(manager, nameW, windows.SERVICE_ALL_ACCESS)
	if err == nil {
		// 服务已存在（可能是官方 sing-box 装的旧路径）：改指向我们的路径。
		changeErr := windows.ChangeServiceConfig(service,
			windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE,
			pathW, nil, nil, nil, nil, nil, nil)
		if changeErr != nil {
			_ = windows.CloseServiceHandle(service)
			return 0, os.NewSyscallError("ChangeServiceConfig", changeErr)
		}
		return service, nil
	}
	service, err = windows.CreateService(manager, nameW, nameW,
		windows.SERVICE_ALL_ACCESS, windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_NORMAL,
		pathW, nil, nil, nil, nil, nil)
	if err == nil {
		return service, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
		service, err = windows.OpenService(manager, nameW, windows.SERVICE_ALL_ACCESS)
		if err == nil {
			return service, nil
		}
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return 0, ErrWindivertUnsupported
	}
	return 0, os.NewSyscallError("CreateService WinDivert", err)
}

// wdivWriteDriverAsset 把嵌入的驱动写到用户缓存目录，返回落盘路径。
func wdivWriteDriverAsset() (string, error) {
	asset, name, err := wdivDriverAsset()
	if err != nil {
		return "", err
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", os.NewSyscallError("UserCacheDir", err)
	}
	target := filepath.Join(base, "flowtls", "windivert", "v"+wdivAssetVersion, name)
	if err = os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	// 内容已一致就不重写：驱动的 .sys 在运行时可能被系统占用（不能覆盖），
	// 而且重复写入会让杀软更敏感。
	if existing, readErr := os.ReadFile(target); readErr == nil && bytes.Equal(existing, asset) {
		return target, nil
	}
	// 写临时文件再 rename：避免写到一半被其它进程读到半个驱动。
	tmp := target + ".tmp-" + strconv.Itoa(os.Getpid())
	if err = os.WriteFile(tmp, asset, 0o644); err != nil {
		return "", err
	}
	if err = os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return target, nil
}

// ---- IOCTL ----

// CTL_CODE 布局：(DeviceType << 16) | (Access << 14) | (Function << 2) | Method
const (
	wdivFileDeviceNetwork uint32 = 0x12
	wdivAccessReadWrite   uint32 = 3
	wdivAccessRead        uint32 = 1
	wdivMethodInDirect    uint32 = 1
	wdivMethodOutDirect   uint32 = 2
)

func wdivCtlCode(deviceType, access, function, method uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

var (
	wdivIoctlInitialize = wdivCtlCode(wdivFileDeviceNetwork, wdivAccessReadWrite, 0x921, wdivMethodOutDirect)
	wdivIoctlStartup    = wdivCtlCode(wdivFileDeviceNetwork, wdivAccessReadWrite, 0x922, wdivMethodInDirect)
	wdivIoctlRecv       = wdivCtlCode(wdivFileDeviceNetwork, wdivAccessRead, 0x923, wdivMethodOutDirect)
	wdivIoctlSend       = wdivCtlCode(wdivFileDeviceNetwork, wdivAccessReadWrite, 0x924, wdivMethodInDirect)
)

// initialize 交换 magic 与版本号。magic 不匹配说明驱动与封装版本不配套。
const (
	wdivMagicDLL    uint64 = 0x4C4C447669645724 // "$WdivDLL"
	wdivMagicSYS    uint64 = 0x5359537669645723 // "#WdivSYS"
	wdivVerMajor    uint32 = 2
	wdivVerMinor    uint32 = 2
	wdivIoctlSize          = 16 // sizeof(WINDIVERT_IOCTL)，packed
	wdivVersionSize        = 64 // sizeof(WINDIVERT_VERSION)，packed
)

func (h *wdivHandle) initialize() error {
	var in [wdivIoctlSize]byte
	binary.LittleEndian.PutUint32(in[0:4], wdivLayerNetwork)
	// 优先级 0（中性）。驱动期望「priority + HIGHEST」，使低位区间映射为非负。
	binary.LittleEndian.PutUint32(in[4:8], uint32(int32(0)+int32(30000)))
	binary.LittleEndian.PutUint64(in[8:16], 0)

	var out [wdivVersionSize]byte
	binary.LittleEndian.PutUint64(out[0:8], wdivMagicDLL)
	binary.LittleEndian.PutUint32(out[8:12], wdivVerMajor)
	binary.LittleEndian.PutUint32(out[12:16], wdivVerMinor)
	binary.LittleEndian.PutUint32(out[16:20], uint32(unsafe.Sizeof(uintptr(0))*8))

	if _, err := h.ioctl(wdivIoctlInitialize, in[:], out[:], h.sendEvent); err != nil {
		return os.NewSyscallError("WinDivert initialize", err)
	}
	if got := binary.LittleEndian.Uint64(out[0:8]); got != wdivMagicSYS {
		return errors.New("flowtls: WinDivert 驱动 magic 不匹配（驱动与封装版本不配套）")
	}
	if got := binary.LittleEndian.Uint32(out[8:12]); got < wdivVerMajor {
		minor := binary.LittleEndian.Uint32(out[12:16])
		return errors.New("flowtls: WinDivert 驱动版本过旧: " +
			strconv.Itoa(int(got)) + "." + strconv.Itoa(int(minor)))
	}
	return nil
}

func (h *wdivHandle) startup(filterBin []byte, filterFlags uint64) error {
	var in [wdivIoctlSize]byte
	binary.LittleEndian.PutUint64(in[0:8], filterFlags)
	if _, err := h.ioctl(wdivIoctlStartup, in[:], filterBin, h.sendEvent); err != nil {
		return os.NewSyscallError("WinDivert startup", err)
	}
	return nil
}

// Recv 阻塞收一个包（扣留语义：调用方必须 decide 放行或丢弃）。
func (h *wdivHandle) Recv(buf []byte) (int, wdivAddr, error) {
	if len(buf) == 0 {
		return 0, wdivAddr{}, errors.New("flowtls: windivert recv 缓冲为空")
	}
	var in [wdivIoctlSize]byte
	h.recvAddr = wdivAddr{}
	binary.LittleEndian.PutUint64(in[0:8], uint64(uintptr(unsafe.Pointer(&h.recvAddr))))
	n, err := h.ioctl(wdivIoctlRecv, in[:], buf, h.recvEvent)
	runtime.KeepAlive(h)
	if err != nil {
		return 0, wdivAddr{}, err
	}
	if wdivDebug && n > 0 {
		wdivDebugPkt("RX", buf[:n])
	}
	return int(n), h.recvAddr, nil
}

// wdivDebugPkt 把 IPv4/TCP 头摘要成一行（只在 FLOWTLS_WDIV_DEBUG=1 时调用）。
//
// 排查握手问题时这是必需的：只看字节数（n=60）无法区分 SYN / SYN-ACK / ACK，
// 也无法看出 seq/ack 是否合理。
func wdivDebugPkt(dir string, p []byte) {
	if len(p) < 20 || p[0]>>4 != 4 {
		fmt.Fprintf(os.Stderr, "[wdiv-dbg] %s len=%d (not ipv4)\n", dir, len(p))
		return
	}
	ihl := int(p[0]&0x0F) * 4
	ipid := uint16(p[4])<<8 | uint16(p[5])
	src := fmt.Sprintf("%d.%d.%d.%d", p[12], p[13], p[14], p[15])
	dst := fmt.Sprintf("%d.%d.%d.%d", p[16], p[17], p[18], p[19])
	if p[9] != 6 || len(p) < ihl+20 {
		fmt.Fprintf(os.Stderr, "[wdiv-dbg] %s %s>%s proto=%d len=%d ipid=%#04x\n",
			dir, src, dst, p[9], len(p), ipid)
		return
	}
	sp := uint16(p[ihl])<<8 | uint16(p[ihl+1])
	dp := uint16(p[ihl+2])<<8 | uint16(p[ihl+3])
	seq := uint32(p[ihl+4])<<24 | uint32(p[ihl+5])<<16 | uint32(p[ihl+6])<<8 | uint32(p[ihl+7])
	ack := uint32(p[ihl+8])<<24 | uint32(p[ihl+9])<<16 | uint32(p[ihl+10])<<8 | uint32(p[ihl+11])
	fl := p[ihl+13]
	name := ""
	for _, b := range []struct {
		m byte
		s string
	}{{0x02, "S"}, {0x10, "A"}, {0x01, "F"}, {0x04, "R"}, {0x08, "P"}} {
		if fl&b.m != 0 {
			name += b.s
		}
	}
	payload := len(p) - ihl - int(p[ihl+12]>>4)*4
	fmt.Fprintf(os.Stderr, "[wdiv-dbg] %s %s:%d>%s:%d [%s] seq=%d ack=%d ipid=%#04x plen=%d\n",
		dir, src, sp, dst, dp, name, seq, ack, ipid, payload)
}

// Send 注入一个包。
//
// addr 决定方向（Outbound 位）与校验和是否重算。**原样复用 Recv 返回的 addr**
// 就是「放行」，这是重新注入非本协议包的正确做法。
func (h *wdivHandle) Send(pkt []byte, addr *wdivAddr) (int, error) {
	if len(pkt) == 0 {
		return 0, errors.New("flowtls: windivert send 空包")
	}
	var in [wdivIoctlSize]byte
	binary.LittleEndian.PutUint64(in[0:8], uint64(uintptr(unsafe.Pointer(addr))))
	binary.LittleEndian.PutUint64(in[8:16], uint64(wdivAddressSize))
	n, err := h.ioctl(wdivIoctlSend, in[:], pkt, h.sendEvent)
	runtime.KeepAlive(h)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// SendBatch 注入一批包。
//
// 驱动要求载荷**首尾相接**（无长度前缀），边界由每个包的 IP total length 还原；
// 且若各包 total length 之和与 len(buf) 不等，整批被拒绝。
// 拼接由 wdivPackBatch 完成（已单测）。
//
// addr 的 Outbound 位决定方向；我们只用「从本机发出」方向（服务端回 SYN-ACK
// 与数据、客户端发 SYN 与 ACK），所以这里统一置位。
func (h *wdivHandle) SendBatch(buf []byte, count int) (int, error) {
	if count <= 0 || count > 255 {
		return 0, errors.New("flowtls: windivert send batch 包数非法")
	}
	if len(buf) == 0 {
		return 0, errors.New("flowtls: windivert send batch 空缓冲")
	}
	if h.sendAddrs == nil {
		h.sendAddrs = make([]wdivAddr, 255)
	}
	// 每个包一个地址项，方向都是 outbound。
	// 校验和位不置 1：置 1 会禁止驱动重算，见 socket_windows.go 的 Send。
	var zero wdivAddr
	zero.Bits = wdivBitSet(zero.Bits, wdivBitOutbound, true)
	for i := 0; i < count; i++ {
		h.sendAddrs[i] = zero
	}
	var in [wdivIoctlSize]byte
	binary.LittleEndian.PutUint64(in[0:8], uint64(uintptr(unsafe.Pointer(&h.sendAddrs[0]))))
	binary.LittleEndian.PutUint64(in[8:16], uint64(count*wdivAddressSize))
	n, err := h.ioctl(wdivIoctlSend, in[:], buf, h.sendEvent)
	runtime.KeepAlive(h)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// Close 关闭句柄（驱动在最后一个句柄关闭后自动卸载）。
func (h *wdivHandle) Close() error {
	var firstErr error
	if h.device != 0 {
		if err := windows.CloseHandle(h.device); err != nil {
			firstErr = err
		}
		h.device = 0
	}
	if h.recvEvent != 0 {
		if err := windows.CloseHandle(h.recvEvent); err != nil && firstErr == nil {
			firstErr = err
		}
		h.recvEvent = 0
	}
	if h.sendEvent != 0 {
		if err := windows.CloseHandle(h.sendEvent); err != nil && firstErr == nil {
			firstErr = err
		}
		h.sendEvent = 0
	}
	return firstErr
}

// ioctl 是一次覆盖式 DeviceIoControl。
//
// event 由调用方指定：收用 recvEvent、发用 sendEvent（原因见 wdivHandle 字段注释）。
func (h *wdivHandle) ioctl(code uint32, in, out []byte, event windows.Handle) (uint32, error) {
	var overlapped windows.Overlapped
	overlapped.HEvent = event

	var inPtr, outPtr *byte
	var inLen, outLen uint32
	if len(in) > 0 {
		inPtr = &in[0]
		inLen = uint32(len(in))
	}
	if len(out) > 0 {
		outPtr = &out[0]
		outLen = uint32(len(out))
	}
	var returned uint32
	err := windows.DeviceIoControl(h.device, code, inPtr, inLen, outPtr, outLen, &returned, &overlapped)
	if err == nil {
		if wdivDebug {
			fmt.Fprintf(os.Stderr, "[wdiv-debug] ioctl code=%#x immediate n=%d\n", code, returned)
		}
		return returned, nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		if wdivDebug {
			fmt.Fprintf(os.Stderr, "[wdiv-debug] ioctl code=%#x FAIL err=%v\n", code, err)
		}
		return 0, err
	}
	if wdivDebug {
		fmt.Fprintf(os.Stderr, "[wdiv-debug] ioctl code=%#x pending...\n", code)
	}
	if err = windows.GetOverlappedResult(h.device, &overlapped, &returned, true); err != nil {
		if wdivDebug {
			fmt.Fprintf(os.Stderr, "[wdiv-debug] ioctl code=%#x overlapped FAIL err=%v\n", code, err)
		}
		return 0, err
	}
	if wdivDebug {
		fmt.Fprintf(os.Stderr, "[wdiv-debug] ioctl code=%#x overlapped n=%d\n", code, returned)
	}
	return returned, nil
}

// wdivDriverAsset 返回当前架构对应的驱动与文件名。
func wdivDriverAsset() ([]byte, string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return wdivSysBytes64, "WinDivert64.sys", nil
	case "386":
		return wdivSysBytes32, "WinDivert32.sys", nil
	default:
		// 官方没有 arm64 驱动资产。这里明确报错而不是让 CreateFile 失败，
		// 因为后者的错误信息完全指不出「架构不支持」这个真正原因。
		return nil, "", errors.New("flowtls: Windows " + runtime.GOARCH + " 没有 WinDivert 驱动（仅支持 amd64 / 386）")
	}
}
