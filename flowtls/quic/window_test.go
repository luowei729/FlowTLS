package quic

import (
	"testing"

	"github.com/luowei729/flowtls"
)

// TestReceiveWindowFitsInRxQueue 钉住「连接级接收窗口装得进收包队列」。
//
// 2026-11-17 的卡死就是这个不变量被打破：
// receiveWindow = 16MB，而 rxQueueDepth = 8192 时队列只有约 10.9MB。
// 对端按窗口把数据发满，deliver 阻塞，recvLoop 停下来不再发 ACK，
// 对端的发送窗口永远等不到 MAX_DATA。表现是新请求全部超时，
// 而内核侧的套接字队列是空的（数据堵在用户态队列里）。
//
// 两个值分属不同的包，所以必须有这条跨包断言。
func TestReceiveWindowFitsInRxQueue(t *testing.T) {
	capacity := flowtls.RxQueueCapacity()
	if capacity < int(receiveWindow) {
		t.Fatalf("收包队列 %d 字节装不下连接级接收窗口 %d 字节："+
			"deliver 会堵住 recvLoop，对端窗口永远不释放",
			capacity, receiveWindow)
	}
}
