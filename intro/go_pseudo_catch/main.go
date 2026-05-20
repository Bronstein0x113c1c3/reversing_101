package main

import (
	"fmt"
	"runtime"
)

//go:noinline
func sayHello(message string, count int) {
	// runtime.Breakpoint() sẽ phát ra lệnh INT3 (tín hiệu SIGTRAP về Debugger)
	runtime.Breakpoint()

	// Thân hàm thực tế
	fmt.Printf("Debuggee nhận chuỗi: %s\n", message)
	fmt.Printf("Debuggee nhận số: %d\n", count)
}

func main() {
	fmt.Println("[Debuggee] Chuẩn bị gọi hàm bằng Go và kích hoạt INT3...")

	// Gọi hàm để test.
	// Go String là một cấu trúc gồm: [Địa chỉ bộ nhớ con trỏ] (8 byte) + [Độ dài chuỗi] (8 byte)
	sayHello("Hello From Go Debuggee", 999)

	fmt.Println("[Debuggee] Kết thúc.")
}
