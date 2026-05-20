package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// Biến toàn cục lưu trữ bảng ký hiệu của file thực thi để tra cứu nhanh
var goSymbolTable *gosym.Table

// Hàm khởi tạo: Đọc file ELF của debuggee và dựng cấu trúc bảng ký hiệu
func initSymbolTable(binaryPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	if err != nil {
		return err
	}

	// 1. Tìm phân đoạn chứa bảng dòng lệnh của Go (.gopclntab)
	pclntabSection := elfFile.Section(".gopclntab")
	if pclntabSection == nil {
		return fmt.Errorf("không tìm thấy phân đoạn .gopclntab trong file ELF. File có thể đã bị stripped")
	}

	pclntabData, err := pclntabSection.Data()
	if err != nil {
		return err
	}

	// 2. Dựng bảng LineTable của Go
	lineTable := gosym.NewLineTable(pclntabData, elfFile.Section(".text").Addr)

	// 3. Khởi tạo bảng ký hiệu hoàn chỉnh
	// Phân đoạn text/symtab của Go có cấu trúc đặc thù, ta truyền mảng rỗng cho symtab thô của ELF
	tab, err := gosym.NewTable([]byte{}, lineTable)
	if err != nil {
		return err
	}

	goSymbolTable = tab
	return nil
}

// Hàm hỗ trợ: Dịch địa chỉ bộ nhớ Hex sang tên hàm tường minh
func resolveAddressToFunctionName(addr uint64) string {
	if goSymbolTable == nil {
		return "Unknown (Bảng ký hiệu chưa được nạp)"
	}
	// Tìm hàm tương ứng với địa chỉ Program Counter (PC/RIP)
	fn := goSymbolTable.PCToFunc(addr)
	if fn != nil {
		return fn.Name
	}
	return "Unknown Function"
}

// --- CÁC HÀM ĐỌC BỘ NHỚ VÀ INTERCEPT VẪN GIỮ NGUYÊN ---

func readGoMemoryContent(pid int, addr uintptr, length int) (string, error) {
	if length <= 0 || length > 4096 {
		return "<Độ dài chuỗi không hợp lệ>", nil
	}
	buf := make([]byte, length)
	for i := 0; i < length; i += 8 {
		chunk := make([]byte, 8)
		_, err := syscall.PtracePeekData(pid, addr+uintptr(i), chunk)
		if err != nil {
			if i > 0 {
				return string(buf[:i]), nil
			}
			return "", err
		}
		rem := length - i
		if rem > 8 {
			rem = 8
		}
		copy(buf[i:], chunk[:rem])
	}
	return string(buf), nil
}

func readAddr(pid int, addr uintptr) (uint64, error) {
	chunk := make([]byte, 8)
	_, err := syscall.PtracePeekData(pid, addr, chunk)
	if err != nil {
		return 0, err
	}
	var val uint64
	for i := 0; i < 8; i++ {
		val |= uint64(chunk[i]) << (8 * i)
	}
	return val, nil
}

// Hàm hỗ trợ phân tích: Kết hợp địa chỉ và Tên hàm cụ thể
func traceCallerCallee(pid int, regs *syscall.PtraceRegs) {
	fmt.Println("  ├──> [Trace Stack] --- PHÂN TÍCH QUAN HỆ CALL HÀM ---")

	// Xác định địa chỉ và tên hàm Callee
	calleeAddress := regs.Rip - 1
	calleeName := resolveAddressToFunctionName(calleeAddress)
	fmt.Printf("  │    ├── [Callee (Hiện tại)]: %s (Địa chỉ: 0x%x)\n", calleeName, calleeAddress)

	// Lần tìm địa chỉ và tên hàm Caller
	var callerAddress uint64
	callerFromRSP, errRSP := readAddr(pid, uintptr(regs.Rsp))
	callerFromRBP, errRBP := readAddr(pid, uintptr(regs.Rbp+8))

	if errRSP == nil && callerFromRSP < 0x7fffffffffff && callerFromRSP > 0x400000 {
		callerAddress = callerFromRSP
	} else if errRBP == nil {
		callerAddress = callerFromRBP
	}

	if callerAddress != 0 {
		callerName := resolveAddressToFunctionName(callerAddress)
		fmt.Printf("  │    └── [Caller (Hàm cha)]:  %s (Địa chỉ: 0x%x)\n", callerName, callerAddress)
	} else {
		fmt.Println("  │    └── [Caller (Hàm cha)]:  Không tìm thấy thông tin Stack Frame.")
	}
}

func main() {
	runtime.LockOSThread()

	debuggeePath := "./pseudo"

	// NẠP BẢNG KÝ HIỆU TRƯỚC KHI CHẠY TIẾN TRÌNH CON
	err := initSymbolTable(debuggeePath)
	if err != nil {
		fmt.Printf("[Cảnh báo] Không thể đọc bảng ký hiệu của %s: %v. Debugger sẽ chỉ hiển thị địa chỉ Hex thô.\n", debuggeePath, err)
	} else {
		fmt.Println("[Debugger] Tải bảng ký hiệu .gopclntab thành công.")
	}

	cmd := exec.Command(debuggeePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		fmt.Printf("Lỗi khởi chạy debuggee: %v\n", err)
		return
	}
	pid := cmd.Process.Pid
	fmt.Printf("[Debugger] Đã kích hoạt giám sát tiến trình con PID: %d\n", pid)

	var wstatus syscall.WaitStatus
	syscall.Wait4(pid, &wstatus, 0, nil)

	isSyscallExitSpace := false

	for {
		err := syscall.PtraceSyscall(pid, 0)
		if err != nil {
			break
		}

		_, err = syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			break
		}

		if wstatus.Exited() {
			fmt.Printf("\n[Debugger] Tiến trình con (PID %d) đã thoát. Mã exit: %d\n", pid, wstatus.ExitStatus())
			break
		}

		if wstatus.Stopped() && wstatus.StopSignal() == syscall.SIGTRAP {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err == nil {
				syscallID := regs.Orig_rax

				if syscallID == 0xffffffffffffffff {
					fmt.Println("\n[Breakpoint Spy] ==========================================================")
					fmt.Println("  Đã chặn đứng điểm dừng phần mềm (Lệnh INT3 / runtime.Breakpoint)!")

					strAddr := regs.Rax
					strLen := int(regs.Rbx)
					intValue := regs.Rcx

					goStr, _ := readGoMemoryContent(pid, uintptr(strAddr), strLen)
					fmt.Println("  ├──> [Tham Số Hàm] --- TRÍCH XUẤT GIÁ TRỊ TỪ THANH GHI ---")
					fmt.Printf("  │    ├── Tham số 1 (Chuỗi Go): \"%s\" (Vị trí: 0x%x, Kích thước: %d bytes)\n", goStr, strAddr, strLen)
					fmt.Printf("  │    └── Tham số 2 (Số nguyên Go): %d\n", intValue)

					// Gọi hàm in vết Stack có dịch tên hàm
					traceCallerCallee(pid, &regs)
					fmt.Println("[Breakpoint Spy] ==========================================================")

					isSyscallExitSpace = false
					continue
				}

				if syscallID == 1 {
					if !isSyscallExitSpace {
						fd := regs.Rdi
						dataAddr := regs.Rsi
						dataLen := int(regs.Rdx)

						if fd == 1 {
							interceptedText, _ := readGoMemoryContent(pid, uintptr(dataAddr), dataLen)
							fmt.Printf("\n[Syscall Interceptor] Phát hiện gọi Syscall 'write' (stdout):\n")
							fmt.Printf("                      -> Đọc lén bộ nhớ tại 0x%x: \"%s\"\n", dataAddr, interceptedText)
						}
					}
					isSyscallExitSpace = !isSyscallExitSpace
				}
			}
		}
	}
}
