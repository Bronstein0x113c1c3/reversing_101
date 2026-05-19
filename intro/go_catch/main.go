package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func main() {
	// Ptrace yêu cầu khóa thread cố định vì Linux gán quyền trace cho từng Thread ID
	runtime.LockOSThread()

	// Đường dẫn đến file thực thi (debuggee) bạn muốn debug
	// Để test, hãy đổi thành file debuggee đã biên dịch của bạn
	debuggeePath := "./intro"

	// 1. Cấu hình SysProcAttr để kích hoạt Ptrace cho tiến trình con
	cmd := exec.Command(debuggeePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true, // Tự động gọi PTRACE_TRACEME ngay sau khi fork, trước khi exec
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 2. Fork và Exec tiến trình con
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Lỗi khởi chạy debuggee: %v\n", err)
		return
	}
	pid := cmd.Process.Pid
	fmt.Printf("[Debugger] Đã fork child với PID: %d\n", pid)

	var wstatus syscall.WaitStatus

	// 3. Vòng lặp giám sát (Event Loop)
	for {
		// Chờ child thay đổi trạng thái (dừng lại do tín hiệu)
		_, err := syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			fmt.Printf("Lỗi Wait4: %v\n", err)
			break
		}

		// Kiểm tra nếu child đã thoát hoàn toàn
		if wstatus.Exited() {
			fmt.Printf("[Debugger] Child đã thoát với mã: %d\n", wstatus.ExitStatus())
			break
		}

		// Kiểm tra nếu child bị dừng bởi một tín hiệu (Signal)
		if wstatus.Stopped() {
			signal := wstatus.StopSignal()

			// Bắt mã lệnh dừng SIGTRAP (do lệnh INT3 sinh ra)
			if signal == syscall.SIGTRAP {
				fmt.Println("[Debugger] Gặp Breakpoint! Gặp lệnh INT3 (SIGTRAP).")

				// Đọc thanh ghi RIP (Instruction Pointer) để xem đang dừng ở đâu
				var regs syscall.PtraceRegs
				if err := syscall.PtraceGetRegs(pid, &regs); err == nil {
					// Trên x86_64, sau khi chạy INT3, RIP sẽ trỏ vào lệnh TIẾP THEO (sau INT3 1 byte)
					fmt.Printf("[Debugger] Đang dừng tại RIP: 0x%x\n", regs.Rip)
				}

				// Bạn có thể xử lý logic breakpoint tại đây...
			} else {
				fmt.Printf("[Debugger] Child dừng do tín hiệu khác: %v\n", signal)
			}

			// 4. Cho phép child chạy tiếp cho đến khi gặp trap tiếp theo
			err = syscall.PtraceCont(pid, 0)
			if err != nil {
				fmt.Printf("Lỗi PtraceCont: %v\n", err)
				break
			}
		}
	}
}
