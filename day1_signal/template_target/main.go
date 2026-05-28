package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)
func main(){



	// Khởi tạo channel có đệm
	sig_notify := make(chan os.Signal, 2)

	// Thay thế SIGCONT bằng SIGUSR1
	signal.Notify(sig_notify, syscall.SIGINT, syscall.SIGUSR1)

	pid := os.Getpid()
	log.Println("PID của tiến trình:", pid)
	log.Println("Bắt đầu chờ tín hiệu...")

	// Chờ tín hiệu thứ nhất (ví dụ: Ctrl+C / SIGINT)
	sig1 := <-sig_notify
	log.Println("Đã nhận tín hiệu 1:", sig1)

	// Chờ tín hiệu thứ hai (ví dụ: SIGUSR1)
	sig2 := <-sig_notify
	log.Println("Đã nhận tín hiệu 2:", sig2)

	log.Println("Hoàn thành tất cả!!!!")

}
