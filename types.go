package main

type ProcessInformationClass uint32

const (
	ProcessMemoryPriorityClass = ProcessInformationClass(iota)
	ProcessMemoryExhaustionInfoClass
	ProcessAppMemoryInfoClass
	ProcessInPrivateInfoClass
	ProcessPowerThrottlingClass
	ProcessReservedValue1Class
	ProcessTelemetryCoverageInfoClass
	ProcessProtectionLevelInfoClass
	ProcessLeapSecondInfoClass
	ProcessMachineTypeInfoClass
	ProcessInformationClassMaxClass
)

type ProcessProtectionLevelInformation uint32

// ///////////////////// STACKFRAME //////////////////////

type iADDRESS struct {
	Offset  uint64
	Segment uint16
	Mode    uint32
}

type iKDHELP struct {
	Thread                         uint64
	ThCallbackStack                uint32
	ThCallbackBStore               uint32
	NextCallback                   uint32
	FramePointer                   uint32
	KiCallUserMode                 uint64
	KeUserCallbackDispatcher       uint64
	SystemRangeStart               uint64
	KiUserExceptionDispatcher      uint64
	StackBase                      uint64
	StackLimit                     uint64
	BuildVersion                   uint32
	RetpolineStubFunctionTableSize uint32
	RetpolineStubFunctionTable     uint64
	RetpolineStubOffset            uint32
	RetpolineStubSize              uint32
	Reserved0                      [2]uint64
}

type iSTACKFRAME struct {
	AddrPC         iADDRESS
	AddrReturn     iADDRESS
	AddrFrame      iADDRESS
	AddrStack      iADDRESS
	FuncTableEntry uintptr
	Params         [4]uint32
	Far            bool
	Virtual        bool
	Reserved       [3]uint32
	KdHelp         iKDHELP
	AddrBStore     iADDRESS
}

type LPSTACKFRAME *iSTACKFRAME

// /////////////////////// CONTEXT ///////////////////////////

type iM128A struct {
	Low  uint64
	High int64
}

type iCONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	DUMMYUNIONNAME       [120]uint8
	VectorRegister       [26]iM128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type PCONTEXT *iCONTEXT

// ////////////////////// SYMBOL_INFO /////////////////
type iSYMBOL_INFO struct {
	SizeOfStruct uint32
	TypeIndex    uint32
	Reserved     [2]uint64
	Index        uint32
	Size         uint32
	ModBase      uint64
	Flags        uint32
	Value        uint64
	Address      uint64
	Register     uint32
	Scope        uint32
	Tag          uint32
	NameLen      uint32
	MaxNameLen   uint32
	Name         *byte
}

type StackItem struct {
	RetAddress    uint64
	SymbolAddress uint64
	ModName       string
	FuncName      string
	Offset        uint64
}
