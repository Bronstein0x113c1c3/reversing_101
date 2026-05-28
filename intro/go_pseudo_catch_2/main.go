package main

import (
	"fmt"
	"runtime"
)

//go:noinline
func triggerDebugger(message string, secretCode int) {
	runtime.Breakpoint()
}

func main() {
	fmt.Println("[Child] Khởi động luồng chương trình thực thi...")
	triggerDebugger("Thong Tin Tuyet Mat 2026", 7777)
}
