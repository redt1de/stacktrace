package stacktrace

import (
	"errors"
	"log"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                   = windows.NewLazyDLL("kernel32.dll")
	pSuspendThread             = kernel32.NewProc("SuspendThread")
	pInitializeCriticalSection = kernel32.NewProc("InitializeCriticalSection")
	pEnterCriticalSection      = kernel32.NewProc("EnterCriticalSection")
	pLeaveCriticalSection      = kernel32.NewProc("LeaveCriticalSection")
	pGetThreadContext          = kernel32.NewProc("GetThreadContext")
	dbghelp                    = windows.NewLazyDLL("dbghelp.dll")
	pSymFromAddr               = dbghelp.NewProc("SymFromAddr")
	pStackWalk64               = dbghelp.NewProc("StackWalk64")
	pSymInitialize             = dbghelp.NewProc("SymInitialize")
	pSymCleanup                = dbghelp.NewProc("SymCleanup")
)

const (
	PROCESS_ALL_ACCESS                           = 0x1F0FFF
	IMAGE_FILE_MACHINE_I386                      = 0x014c
	IMAGE_FILE_MACHINE_IA64                      = 0x0200
	IMAGE_FILE_MACHINE_AMD64                     = uintptr(0x8664)
	AddrModeFlat                                 = 3
	THREAD_ALL_ACCESS                            = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff
	THREAD_GET_CONTEXT                           = 0x0008
	CONTEXT_AMD64                                = 0x100000
	CONTEXT_CONTROL                              = (CONTEXT_AMD64 | 0x1)
	CONTEXT_INTEGER                              = (CONTEXT_AMD64 | 0x2)
	CONTEXT_SEGMENTS                             = (CONTEXT_AMD64 | 0x4)
	CONTEXT_FLOATING_POINT                       = (CONTEXT_AMD64 | 0x8)
	CONTEXT_DEBUG_REGISTERS                      = (CONTEXT_AMD64 | 0x10)
	CONTEXT_FULL                                 = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
	GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS       = uint32(0x00000004)
	GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = uint32(0x00000002)
	MAX_SYM_NAME                                 = 256
)

/*
// EXAMPLE:

	func main() {
		pid, _ := strconv.Atoi(os.Args[1])
		tid, _ := strconv.Atoi(os.Args[2])
		trace, err := GetTrace(pid, tid)
		if err != nil {
			log.Fatal(err)
		}
		for _, i := range trace {
			fmt.Printf("(0x%x) %s!%s+0x%x\n", i.RetAddress, i.ModName, i.FuncName, i.Offset)
		}

}
*/
func GetTrace(pid, tid int) ([]StackItem, error) {
	var ret []StackItem
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	defer windows.CloseHandle(hProcess)
	if err != nil {
		return ret, errors.New("OpenProcess: " + err.Error())
	}

	hThread, err := windows.OpenThread(THREAD_ALL_ACCESS, false, uint32(tid))
	defer windows.CloseHandle(hThread)
	if err != nil {
		return ret, errors.New("OpenThread: " + err.Error())
	}

	_, _, e := pSuspendThread.Call(uintptr(hThread))
	defer windows.ResumeThread(hThread)
	if e != nil && e.Error() != "The operation completed successfully." {
		return ret, errors.New("SuspendThread: " + e.Error())
	}

	var context = iCONTEXT{ContextFlags: CONTEXT_FULL}
	_, _, e = pGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(&context)))
	if e != nil && e.Error() != "The operation completed successfully." {
		return ret, errors.New("GetThreadContext: " + e.Error())
	}

	if context.Rip == 0 {
		return ret, errors.New("GetThreadContext: invalid context, RIP is 0x0")
	}

	var StackFrame = iSTACKFRAME{}
	StackFrame.AddrPC.Offset = context.Rip
	StackFrame.AddrPC.Mode = AddrModeFlat
	StackFrame.AddrFrame.Offset = context.Rbp
	StackFrame.AddrFrame.Mode = AddrModeFlat
	StackFrame.AddrStack.Offset = context.Rsp
	StackFrame.AddrStack.Mode = AddrModeFlat
	context.ContextFlags = CONTEXT_FULL

	_, _, e = pSymInitialize.Call(uintptr(hProcess), uintptr(0), uintptr(1))
	if e != nil && e.Error() != "The operation completed successfully." {
		return ret, errors.New("SymInitialize: " + e.Error())
	}
	defer pSymCleanup.Call(uintptr(hProcess))
	var CriticalSection uintptr
	_, _, e = pInitializeCriticalSection.Call(uintptr(unsafe.Pointer(&CriticalSection)))
	if e != nil && e.Error() != "The operation completed successfully." {
		return ret, errors.New("InitializeCriticalSection: " + e.Error())
	}

	for {
		// this is required, dbghelp functions and go dont mix. essentially locks these calls to a thread. i think
		_, _, e = pEnterCriticalSection.Call(uintptr(unsafe.Pointer(&CriticalSection)))
		defer pLeaveCriticalSection.Call(uintptr(unsafe.Pointer(&CriticalSection)))
		if e != nil && e.Error() != "The operation completed successfully." {
			return ret, errors.New("EnterCriticalSection: " + e.Error())
		}

		success, _, _ := pStackWalk64.Call(uintptr(IMAGE_FILE_MACHINE_AMD64), uintptr(hProcess), uintptr(hThread), uintptr(unsafe.Pointer(&StackFrame)), uintptr(unsafe.Pointer(&context)))
		if StackFrame.AddrPC.Offset == 0 || success == 0 {
			break
		}
		symbolBuffer := makeSymbolBuffer()
		symbol := (*iSYMBOL_INFO)(unsafe.Pointer(&symbolBuffer[0]))

		var displacement = uint64(0)
		success, _, e = pSymFromAddr.Call(uintptr(hProcess), uintptr(StackFrame.AddrPC.Offset), uintptr(unsafe.Pointer(&displacement)), uintptr(unsafe.Pointer(symbol)))
		if e != nil && e.Error() != "The operation completed successfully." && e.Error() != "Attempt to access invalid address." {
			return ret, errors.New("pSymFromAddr: (note may need to set to UNKNOWN here instead of return)" + e.Error())
		}

		_, _, e = pLeaveCriticalSection.Call(uintptr(unsafe.Pointer(&CriticalSection)))
		if e != nil && e.Error() != "The operation completed successfully." {
			return ret, errors.New("LeaveCriticalSection: " + e.Error())
		}

		if success == 1 {
			var hModule windows.Handle
			lpModuleName := (*uint16)(unsafe.Pointer(uintptr(symbol.Address)))
			err := windows.GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, lpModuleName, &hModule)
			defer windows.CloseHandle(hModule)
			modName := "UNKNOWN"
			if err == nil {
				var baseName uint16
				err = windows.GetModuleBaseName(hProcess, hModule, &baseName, uint32(256))
				if err == nil && baseName != 0 {
					modName = windows.UTF16PtrToString(&baseName)
				}
			}

			// gotta be a better way
			// for some reason symbol.Name is 4 bytes off, so windows.UTF16PtrToString() panics.  MaxNameLen, which is just before, is correct which is odd so IDK what the deal is
			funcName := string(ReadMemory(uintptr(unsafe.Pointer(&symbol.Name))-uintptr(4), int(symbol.NameLen))) // <<<<<<<<<<<<< - uintptr(4) to adjust the position

			tmp := StackItem{
				RetAddress:    StackFrame.AddrPC.Offset,
				SymbolAddress: symbol.Address,
				ModName:       modName,
				FuncName:      funcName,
				Offset:        StackFrame.AddrPC.Offset - symbol.Address, //DWORD offsy = stackFrame.AddrPC.Offset - symbol->Address;
			}
			ret = append(ret, tmp)
		} else { // symbol not found, may be process code.
			modName := "UNKNOWN"
			offsy := uint64(0)
			tHandle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
			defer windows.CloseHandle(tHandle)
			if err != nil {
				log.Fatal(err)
			}

			var entry windows.ModuleEntry32
			entry.Size = uint32(unsafe.Sizeof(windows.ModuleEntry32{}))
			err = windows.Module32First(tHandle, &entry)
			if err != nil {
				log.Fatal(err)
			}

			if StackFrame.AddrPC.Offset >= uint64(entry.ModBaseAddr) && StackFrame.AddrPC.Offset < uint64(entry.ModBaseAddr)+uint64(entry.ModBaseSize) { // is the address within the proccess
				offsy = StackFrame.AddrPC.Offset - uint64(entry.ModBaseAddr)
				modName = filepath.Base(windows.UTF16ToString(entry.ExePath[:]))

			}

			tmp := StackItem{
				RetAddress: StackFrame.AddrPC.Offset,
				ModName:    modName,
				Offset:     offsy,
			}
			ret = append(ret, tmp)
		}

	}
	return ret, nil
}

// ReadMemory
func ReadMemory(addr uintptr, readLen int) []byte {
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), readLen)
	return readmem
}

func makeSymbolBuffer() []byte {
	symbolBuf := make([]byte, unsafe.Sizeof(iSYMBOL_INFO{})+MAX_SYM_NAME)
	for i := range symbolBuf {
		symbolBuf[i] = 0xcc
	}

	// manually set symbol.SizeOfStruct = uint32(unsafe.Sizeof(SYMBOL_INFO{}))
	symbolBuf[0] = 0x58
	symbolBuf[1] = 0x00
	symbolBuf[2] = 0x00
	symbolBuf[3] = 0x00

	// manually set symbol.MaxNameLen = MAX_SYM_NAME
	symbolBuf[80] = 0xd0
	symbolBuf[81] = 0x07
	symbolBuf[82] = 0x00
	symbolBuf[83] = 0x00
	// return uintptr(unsafe.Pointer(&symbolBuf[0]))
	return symbolBuf
}
