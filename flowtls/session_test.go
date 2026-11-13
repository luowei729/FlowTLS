package flowtls

import (
	"sync"
	"testing"
	"time"
)

// TestDeliverNeverBlocks 验证 rx 队列满时 deliver 不会阻塞。
//
// **这是本轮最严重的 bug，必须锁死**。
//
// 服务端所有会话共享**一个** recvLoop（listener.go），
// 而 handleIncoming → deliver 是在这个协程里同步调用的。
// 只要 deliver 在队列满时阻塞，整个 recvLoop 就停摆：
//
//   - 所有会话同时收不到包；
//   - 所有会话都发不出 ACK（ACK 由 handleIncoming 触发）；
//   - 对端 PTO 超时判丢包，BBR 把窗口压到最低；
//   - 表现为「RTT 正常但吞吐 63KB/s」，两台服务器同时复现。
//
// 测试方法：造一个 rx 容量极小的 Session，连续 deliver 远超容量的包，
// 断言调用立即返回（不阻塞）。
func TestDeliverNeverBlocks(t *testing.T) {
	const rxCap = 4
	s := &Session{
		rx:      make(chan []byte, rxCap),
		closeCh: make(chan struct{}),
	}

	payload := make([]byte, 1332)

	// 用 goroutine + 超时来检测阻塞：如果 deliver 阻塞，done 不会关闭
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 灌 10 倍容量
		for i := 0; i < rxCap*10; i++ {
			s.deliver(payload)
		}
	}()

	select {
	case <-done:
		// 正常返回
	case <-time.After(2 * time.Second):
		t.Fatal("deliver 在 rx 队列满时阻塞了——" +
			"这会让服务端唯一的 recvLoop 停摆，所有会话同时失效")
	}

	// 队列应该正好填满，其余被丢弃并计数
	if got := len(s.rx); got != rxCap {
		t.Fatalf("rx 队列长度 %d，期望 %d", got, rxCap)
	}
	dropped := s.rxDropped.Load()
	if want := uint64(rxCap * 9); dropped != want {
		t.Fatalf("丢弃计数 %d，期望 %d", dropped, want)
	}
}

// TestDeliverConcurrentWithCloseNeverPanics 锁死「向已关闭的 rx 发送」这个竞态。
//
// 复现的真实故障：收包改成一次处理 32 包后，Close() 里的 close(s.rx)
// 与 handleIncoming → deliverOwned 的发送时间重叠，
// 客户端直接 `panic: send on closed channel` 崩进程
// （部署到 1080 时实测到，见 DEVTIPS 92）。
//
// 旧写法用 sync.Once 保证「只关一次」，但那不保证「关完没人再 send」；
// Go 对已关闭通道发送是 panic，不是返回错误。
//
// 现在 deliverOwned 与 shutdownRx 用 rxMu 互斥。本测试不需要显式断言：
// 一旦互斥被破坏，goroutine 里的 panic 会直接让整个测试进程失败。
// 用 `go test -race -count=20` 跑才能稳定撞出窗口。
func TestDeliverConcurrentWithCloseNeverPanics(t *testing.T) {
	const rxCap = 8
	s := &Session{
		rx:      make(chan []byte, rxCap),
		closeCh: make(chan struct{}),
	}

	var wg sync.WaitGroup
	// 一侧：持续投递，模拟批量收包（4 个 goroutine 拉高并发）
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				s.deliver(make([]byte, 1332))
			}
		}()
	}
	// 另一侧：中途关闭 rx，模拟会话 Close 与接收协程退出
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(200 * time.Microsecond)
		s.closed.Store(true)
		s.once.Do(func() { close(s.closeCh) })
		s.shutdownRx()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(300 * time.Microsecond)
		s.closeRx() // 另一条关闭路径（接收协程退出）也要走到同一个 shutdownRx
	}()

	wg.Wait()

	// 互斥成立时 rx 必定已关且不会重复关；重复 close 会 panic，
	// 所以能走到这里就说明 shutdownRx 的幂等性也对。
	s.shutdownRx()
}

// TestAdvertisedWindowUsesBytes 验证窗口通告用的是**字节数**。
//
// 之前的 bug：传的是 `len(s.rx)`（包数）。16384 个包实际是 21.8MB，
// 但被当成 16384 字节，于是窗口永远接近满值，对端无限制地发。
//
// 正确行为：未读字节越多，通告窗口越小；达到接收上限时窗口趋近于 0
// （但不会真的为 0，否则会把对端卡死）。
func TestAdvertisedWindowUsesBytes(t *testing.T) {
	const rcvTotal = 16 * 1024 * 1024

	// 空队列：满窗口
	full := AdvertisedWindow(0)
	if full == 0 {
		t.Fatal("空队列时窗口不应为 0")
	}

	// 未读一半：窗口应该约减半
	half := AdvertisedWindow(rcvTotal / 2)
	if half >= full {
		t.Fatalf("未读 %d 字节时窗口 %d 未收缩（空队列时 %d）",
			rcvTotal/2, half, full)
	}
	if half > full/2+2 || half < full/2-2 {
		t.Fatalf("未读一半时窗口 %d，期望约 %d", half, full/2)
	}

	// 接近满：窗口应趋近 0，但被抬到 1（不能声明零窗口）
	nearFull := AdvertisedWindow(rcvTotal - 1)
	if nearFull != 1 {
		t.Fatalf("未读接近上限时窗口 %d，期望 1", nearFull)
	}

	// 超过上限（防御性）：仍然是 1
	if over := AdvertisedWindow(rcvTotal * 2); over != 1 {
		t.Fatalf("未读超上限时窗口 %d，期望 1", over)
	}
}

// TestRxBytesAccounting 验证 rxBytes 的加减配对。
//
// 如果只加不减，窗口会一路收缩到 1，对端彻底停发——
// 现象是「连接活着但完全不动」。
func TestRxBytesAccounting(t *testing.T) {
	s := &Session{
		rx:      make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}

	payload := make([]byte, 1000)
	for i := 0; i < 5; i++ {
		s.deliver(payload)
	}
	if got := s.rxBytes.Load(); got != 5000 {
		t.Fatalf("deliver 5×1000 字节后 rxBytes=%d，期望 5000", got)
	}

	// 模拟 ReadFrom 消费
	buf := make([]byte, 2000)
	for i := 0; i < 5; i++ {
		n, _, err := s.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom 失败: %v", err)
		}
		if n != 1000 {
			t.Fatalf("读到 %d 字节，期望 1000", n)
		}
	}
	if got := s.rxBytes.Load(); got != 0 {
		t.Fatalf("全部读完后 rxBytes=%d，期望 0（只加不减会让窗口收缩到 1）", got)
	}
}
