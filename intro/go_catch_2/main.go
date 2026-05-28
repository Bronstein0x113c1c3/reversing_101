package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// Cấu trúc lưu trữ Meta-data đầy đủ của một hàm từ DWARF
type FunctionMetaData struct {
	Name       string
	LowPC      uint64
	HighPC     uint64
	Parameters []ParamInfo
}

type ParamInfo struct {
	Name string
	Type string
}

// Biến toàn cục lưu trữ danh sách hàm và dữ liệu DWARF để tra cứu
var dwarfFunctions []FunctionMetaData
var dwarfData *dwarf.Data

// ==========================================
// 1. KHỞI TẠO VÀ PHÂN TÍCH DỮ LIỆU DWARF
// ==========================================

func initDwarfParser(binaryPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	if err != nil {
		return err
	}

	dData, err := elfFile.DWARF()
	if err != nil {
		return fmt.Errorf("không tìm thấy dữ liệu DWARF debug: %v", err)
	}
	dwarfData = dData

	// Duyệt qua cây thực thể của DWARF để thu thập thông tin hàm
	reader := dData.Reader()

	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		// Nếu thực thể là một Hàm (Subprogram)
		if entry.Tag == dwarf.TagSubprogram {
			fnName, _ := entry.Val(dwarf.AttrName).(string)
			lowPC, _ := entry.Val(dwarf.AttrLowpc).(uint64)
			highPC, _ := entry.Val(dwarf.AttrHighpc).(uint64)

			if fnName == "" || lowPC == 0 {
				continue
			}

			fnMeta := FunctionMetaData{
				Name:   fnName,
				LowPC:  lowPC,
				HighPC: highPC,
			}

			// Đi sâu vào các nút con để tìm tham số của hàm này
			for {
				childEntry, err := reader.Next()
				if err != nil || childEntry == nil || childEntry.Tag == 0 {
					break
				}

				if childEntry.Tag == dwarf.TagFormalParameter {
					pName, _ := childEntry.Val(dwarf.AttrName).(string)
					pTypeOffset, _ := childEntry.Val(dwarf.AttrType).(dwarf.Offset)

					pTypeName := "unknown"
					if pTypeOffset != 0 {
						pTypeName = resolveDwarfType(pTypeOffset)
					}

					fnMeta.Parameters = append(fnMeta.Parameters, ParamInfo{
						Name: pName,
						Type: pTypeName,
					})
				}
			}
			dwarfFunctions = append(dwarfFunctions, fnMeta)
		}
	}
	return nil
}

// SỬA LỖI ĐÃ QUA: Dùng Reader độc lập phối hợp Seek() để tìm Type Name từ Offset
func resolveDwarfType(offset dwarf.Offset) string {
	reader := dwarfData.Reader()
	reader.Seek(offset)

	typeEntry, err := reader.Next()
	if err != nil || typeEntry == nil {
		return "unknown"
	}

	name, _ := typeEntry.Val(dwarf.AttrName).(string)
	if name != "" {
		return name
	}

	baseOffset, _ := typeEntry.Val(dwarf.AttrType).(dwarf.Offset)
	if baseOffset != 0 {
		return "*" + resolveDwarfType(baseOffset)
	}

	return "complex_type"
}

// ==========================================
// 2. CÁC HÀM HỖ TRỢ ĐỌC BỘ NHỚ TIẾN TRÌNH CON
// ==========================================

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
		copySize := 8
		if rem < 8 {
			copySize = rem
		}
		copy(buf[i:], chunk[:copySize])
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

// ==========================================
// 3. TRUY VẤN DWARF CHO CẢ CALLER VÀ CALLEE
// ==========================================

func getFunctionDwarfDetails(pcAddress uint64) string {
	for _, fn := range dwarfFunctions {
		if pcAddress >= fn.LowPC && pcAddress < fn.HighPC {
			result := fmt.Sprintf("Hàm: %s (Dải bộ nhớ: [0x%x - 0x%x])\n", fn.Name, fn.LowPC, fn.HighPC)
			if len(fn.Parameters) == 0 {
				result += "         └── (Hàm không nhận tham số)\n"
			} else {
				for idx, param := range fn.Parameters {
					result += fmt.Sprintf("         ├── Tham số #%d: %s \t| Kiểu dữ liệu (Type): %s\n", idx+1, param.Name, param.Type)
				}
			}
			return result
		}
	}
	return "Không tìm thấy thông tin cấu trúc trong DWARF.\n"
}

func inspectCalleeAndCallerMeta(pid int, regs *syscall.PtraceRegs) {
	fmt.Println("  ├──> [DWARF Metadata] --- TRÍCH XUẤT THÔNG TIN CẤU TRÚC HÀM ---")

	// 1. Chi tiết hàm hiện tại (Callee)
	calleePC := regs.Rip - 1
	fmt.Printf("  │    ├── [Callee - Hiện tại]: ")
	fmt.Print(getFunctionDwarfDetails(calleePC))

	// 2. Định vị địa chỉ quay về của hàm cha (Caller) trên Stack
	var callerPC uint64
	callerFromRSP, errRSP := readAddr(pid, uintptr(regs.Rsp))
	callerFromRBP, errRBP := readAddr(pid, uintptr(regs.Rbp+8))

	if errRSP == nil && callerFromRSP < 0x7fffffffffff && callerFromRSP > 0x400000 {
		callerPC = callerFromRSP
	} else if errRBP == nil {
		callerPC = callerFromRBP
	}

	// 3. Chi tiết hàm cha (Caller)
	fmt.Printf("  │    └── [Caller - Hàm cha]:  ")
	if callerPC != 0 {
		fmt.Print(getFunctionDwarfDetails(callerPC))
	} else {
		fmt.Println("Không tìm thấy địa chỉ hàm cha trên bộ nhớ Stack.\n")
	}
}

// ==========================================
// 4. VÒNG LẶP ĐIỀU KHIỂN CHÍNH (MAIN LOOP)
// ==========================================

func main() {
	runtime.LockOSThread()
	debuggeePath := "./pseudo_2"

	// Nạp dữ liệu debug DWARF
	err := initDwarfParser(debuggeePath)
	if err != nil {
		fmt.Printf("[Lỗi DWARF]: %v\n", err)
		return
	}
	fmt.Printf("[Debugger] Đã nạp thành công %d thực thể hàm từ DWARF.\n", len(dwarfFunctions))

	cmd := exec.Command(debuggeePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("Lỗi chạy tiến trình con: %v\n", err)
		return
	}
	pid := cmd.Process.Pid

	var wstatus syscall.WaitStatus
	syscall.Wait4(pid, &wstatus, 0, nil)

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
			break
		}

		if wstatus.Stopped() && wstatus.StopSignal() == syscall.SIGTRAP {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err == nil {
				// Nếu bắt được điểm dừng Breakpoint phần mềm (Orig_rax = -1)
				if regs.Orig_rax == 0xffffffffffffffff {
					fmt.Println("\n[Breakpoint Spy] ==========================================================")
					fmt.Println("  Đã chạm điểm dừng phần mềm (Lệnh INT3 / runtime.Breakpoint)!")

					// Phân tích thông tin DWARF của cả hai thế hệ hàm
					inspectCalleeAndCallerMeta(pid, &regs)

					// Trích xuất giá trị chạy thực tế từ các thanh ghi
					strAddr := regs.Rax
					strLen := int(regs.Rbx)
					intValue := regs.Rcx
					goStr, _ := readGoMemoryContent(pid, uintptr(strAddr), strLen)

					fmt.Println("  ├──> [Giá Trị Chạy Thực Tế] --- THANH GHI CPU TẠI THỜI ĐIỂM DỪNG ---")
					fmt.Printf("  │    ├── Chuỗi chữ của Callee: \"%s\"\n", goStr)
					fmt.Printf("  │    └── Số nguyên của Callee: %d\n", intValue)
					fmt.Println("[Breakpoint Spy] ==========================================================")
					continue
				}
			}
		}
	}
}
