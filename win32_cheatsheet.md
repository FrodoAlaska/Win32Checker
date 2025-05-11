- [Code Injection Techniques](#code-injection-techniques)
  - [1. DLL Injection](#1-dll-injection)
  - [2. PE Injection](#2-pe-injection)
  - [3. Reflective Injection](#3-reflective-injection)
  - [4. APC Injection](#4-apc-injection)
  - [5. Process Hollowing (Process Replacement)](#5-process-hollowing-process-replacement)
  - [6. AtomBombing](#6-atombombing)
  - [7. Process Doppelgänging](#7-process-doppelgänging)
  - [8. Process Herpaderping](#8-process-herpaderping)
  - [9. Hooking Injection](#9-hooking-injection)
  - [10. Extra Windows Memory Injection](#10-extra-windows-memory-injection)
  - [11. Propagate Injection](#11-propagate-injection)
  - [12. Heap Spray](#12-heap-spray)
  - [13. Thread Execution Hijacking](#13-thread-execution-hijacking)
  - [14. Module Stomping](#14-module-stomping)
  - [15. IAT Hooking](#15-iat-hooking)
  - [16. Inline Hooking](#16-inline-hooking)
  - [17. Debugger Injection](#17-debugger-injection)
  - [18. COM Hijacking](#18-com-hijacking)
  - [19. Phantom DLL Hollowing](#19-phantom-dll-hollowing)
  - [20. PROPagate](#20-propagate)
  - [21. Early Bird Injection](#21-early-bird-injection)
  - [22. Shim-based Injection](#22-shim-based-injection)
  - [23. Mapping Injection](#23-mapping-injection)
  - [24. KnownDlls Cache Poisoning](#24-knowndlls-cache-poisoning)
- [Process Enumeration](#process-enumeration)

- [`NtCreateThread`](Undocumented)
- [`RtlCreateUserThread`](Undocumented)

- [`CreateFileMapping`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
  ```c
  HANDLE CreateFileMappingA(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCSTR                lpName
  );
  ```
- [`MapViewOfFile`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
  ```c
  LPVOID MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
  );
  ```
- `OpenProcess` (see above)
- [`memcpy`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy)
  ```c
  void *memcpy(
     void *dest,
     const void *src,
     size_t count
  );
  ```
- `ZwMapViewOfSection` (Documented for kernel-mode)
  ```c
  NTSTATUS ZwMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
  );
  ```
- `CreateThread` (see CreateRemoteThread above)
- `NtQueueApcThread` (Undocumented)
  ```c
  NTSTATUS NTAPI NtQueueApcThread(
    IN HANDLE ThreadHandle,
    IN PIO_APC_ROUTINE ApcRoutine,
    IN PVOID ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
    IN ULONG ApcReserved OPTIONAL
  );
  ```
- `RtlCreateUserThread` (see above)

Additional APIs sometimes used:
- [`VirtualQueryEx`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
  ```c
  SIZE_T VirtualQueryEx(
    HANDLE                    hProcess,
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
  );
  ```
- [`ReadProcessMemory`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
  ```c
  BOOL ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesRead
  );
  ```

Template:
1. Create a file mapping of the DLL with `CreateFileMapping`
2. Map a view of the file with `MapViewOfFile`
3. Open the target process with `OpenProcess`
4. Allocate memory in the target process with `VirtualAllocEx`
5. Copy the DLL contents to the allocated memory with `WriteProcessMemory`
6. Perform manual loading and relocation of the DLL in the target process
- Parse the PE headers
- Allocate memory for each section
- Copy sections to allocated memory
- Process the relocation table:
	- Enumerate relocation entries
	- Apply relocations based on the new base address
- Resolve imports:
	- Walk the import directory
	- For each imported function, resolve its address using GetProcAddress
	- Write the resolved addresses to the IAT
7. Execute the DLL's entry point using one of the thread creation methods

Detection and Defense:
- Implement advanced memory scanning techniques to detect injected code
- Use behavior-based detection to identify suspicious memory allocation patterns
- Monitor for unusual file mapping operations
- Employ heuristic-based detection methods to identify reflective loaders
## 4. APC Injection

This technique allows code execution in a specific thread by attaching to an Asynchronous Procedure Call (APC) queue.  Works best with alertable threads (those that call alertable wait functions).

Key APIs:
- [`CreateToolhelp32Snapshot`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
  ```c
  HANDLE CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
  );
  ```
- [`Process32First`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
  ```c
  BOOL Process32First(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
  );
  ```
- [`Process32Next`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
  ```c
  BOOL Process32Next(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
  );
  ```
- [`Thread32First`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
  ```c
  BOOL Thread32First(
    HANDLE          hSnapshot,
    LPTHREADENTRY32 lpte
  );
  ```
- [`Thread32Next`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next)
  ```c
  BOOL Thread32Next(
    HANDLE          hSnapshot,
    LPTHREADENTRY32 lpte
  );
  ```
- [`QueueUserAPC`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
  ```c
  DWORD QueueUserAPC(
    PAPCFUNC  pfnAPC,
    HANDLE    hThread,
    ULONG_PTR dwData
  );
  ```
- `KeInitializeAPC` (Kernel-mode, undocumented)
  ```c
  VOID KeInitializeApc(
    PRKAPC Apc,
    PRKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ProcessorMode,
    PVOID NormalContext
  );
  ```

Template:
1. Create a snapshot of the system processes with `CreateToolhelp32Snapshot`
2. Enumerate processes and threads using `Process32First`, `Process32Next`, `Thread32First`, and `Thread32Next`
3. Open the target process with `OpenProcess`
4. Allocate memory in the target process with `VirtualAllocEx`
5. Write the malicious code to the allocated memory with `WriteProcessMemory`
6. Queue an APC to the target thread with `QueueUserAPC`, pointing to the injected code

Detection and Defense:
- Monitor for suspicious APC queue operations
- Implement thread execution monitoring to detect unexpected code execution
- Use EDR solutions with capabilities to detect APC abuse
- Employ runtime analysis to identify unusual thread behavior

## 5. Process Hollowing (Process Replacement)

This technique "drains out" the entire content of a process and inserts malicious content into it. 

Key APIs:
- [`CreateProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
  ```c
  BOOL CreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
  );
  ```
- `NtQueryInformationProcess` (Undocumented)
  ```c
  NTSTATUS NTAPI NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
  );
  ```
- [`GetModuleHandle`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
  ```c
  HMODULE GetModuleHandleA(
    LPCSTR lpModuleName
  );
  ```
- `ZwUnmapViewOfSection` / `NtUnmapViewOfSection` (Undocumented)
  ```c
  NTSTATUS NTAPI NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
  );
  ```
- `VirtualAllocEx` (see above)
- `WriteProcessMemory` (see above)
- [`GetThreadContext`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
  ```c
  BOOL GetThreadContext(
    HANDLE    hThread,
    LPCONTEXT lpContext
  );
  ```
- `SetThreadContext` (see above)
- `ResumeThread` (see above)

Template:
1. Create a new process in a suspended state using `CreateProcess` with `CREATE_SUSPENDED` flag
2. Get the process information using `NtQueryInformationProcess`
3. Unmap the original executable from the process using `NtUnmapViewOfSection` after unmapping the original executable, adjust the image base address in the PEB (Process Environment Block) to point to the new allocated memory.
4. Adjust the image base address in the PEB:
- Use `ReadProcessMemory` to read the PEB
- Locate the `ImageBaseAddress` field
- Use `WriteProcessMemory` to update it with the address of the newly allocated memory
5. Allocate memory in the target process with `VirtualAllocEx`
6. Write the malicious executable to the allocated memory with `WriteProcessMemory`
7. Update the thread context to point to the new entry point using `GetThreadContext` and `SetThreadContext`
8. Resume the main thread of the process with `ResumeThread`

Detection and Defense:
- Implement process integrity checks to detect hollowed processes
- Monitor for suspicious process creation patterns, especially with the `CREATE_SUSPENDED` flag
- Use memory forensics tools to identify signs of process hollowing
- Employ behavior-based detection to identify processes with unexpected memory layouts
## 6. AtomBombing

A variant of APC injection that works by splitting the malicious payload into separate strings and using atoms. this technique relies on the fact that atoms are shared across processes.

Key APIs:
- `OpenThread` (see above)
- [`GlobalAddAtom`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globaladdatoma)
  ```c
  ATOM GlobalAddAtomA(
    LPCSTR lpString
  );
  ```
- [`GlobalGetAtomName`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalgetatomaname)
  ```c
  UINT GlobalGetAtomNameA(
    ATOM   nAtom,
    LPSTR  lpBuffer,
    int    nSize
  );
  ```
- `QueueUserAPC` (see above)
- `NtQueueApcThread` (Undocumented, see above)
- `NtSetContextThread` (Undocumented)
  ```c
  NTSTATUS NTAPI NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT ThreadContext
  );
  ```

Template:
1. Split the malicious payload into small chunks
2. For each chunk, use `GlobalAddAtom` to create a global atom
3. Open the target thread with `OpenThread`
4. Queue an APC to the target thread with `QueueUserAPC` or `NtQueueApcThread`
5. In the APC routine, use `GlobalGetAtomName` to retrieve the payload chunks
6. Assemble the payload in the target process memory
7. Execute the payload using `NtSetContextThread` or by queuing another APC

Detection and Defense:
- Monitor for unusual patterns of atom creation and retrieval
- Implement behavior-based detection for processes accessing a large number of atoms
- Use EDR solutions with capabilities to detect AtomBombing techniques
- Employ runtime analysis to identify suspicious APC usage in combination with atom manipulation

## 7. Process Doppelgänging

An evolution of Process Hollowing that replaces the image before the process is created. this technique leverages the Windows Transactional NTFS (TxF) to temporarily replace a legitimate file with a malicious one during process creation.

Key APIs:
- [`CreateTransaction`](https://docs.microsoft.com/en-us/windows/win32/api/ktmw32/nf-ktmw32-createtransaction)
  ```c
  HANDLE CreateTransaction(
    LPSECURITY_ATTRIBUTES   lpTransactionAttributes,
    LPGUID                  UOW,
    DWORD                   CreateOptions,
    DWORD                   IsolationLevel,
    DWORD                   IsolationFlags,
    DWORD                   Timeout,
    LPWSTR                  Description
  );
  ```
- [`CreateFileTransacted`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiletransacteda)
  ```c
  HANDLE CreateFileTransactedA(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile,
    HANDLE                hTransaction,
    PUSHORT               pusMiniVersion,
    PVOID                 lpExtendedParameter
  );
  ```
- `NtCreateSection` (Undocumented)
  ```c
  NTSTATUS NTAPI NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
  );
  ```
- `NtCreateProcessEx` (Undocumented)
  ```c
  NTSTATUS NTAPI NtCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN BOOLEAN InJob
  );
  ```
- `NtQueryInformationProcess` (Undocumented, see above)
- `NtCreateThreadEx` (Undocumented)
  ```c
  NTSTATUS NTAPI NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
  );
  ```
- [`RollbackTransaction`](https://docs.microsoft.com/en-us/windows/win32/api/ktmw32/nf-ktmw32-rollbacktransaction)
  ```c
  BOOL RollbackTransaction(
    HANDLE TransactionHandle
  );
  ```

Template:
1. Create a transaction using `CreateTransaction`
2. Create a transacted file with `CreateFileTransacted`
3. Write the malicious payload to the transacted file
4. Create a section for the transacted file using `NtCreateSection`
5. Create a process from the section using `NtCreateProcessEx`
6. Create a thread in the new process with `NtCreateThreadEx`
7. Rollback the transaction with `RollbackTransaction` to remove traces of the malicious file

Detection and Defense:
- Monitor for suspicious transactional NTFS operations
- Implement file integrity monitoring to detect temporary file replacements
- Use advanced EDR solutions capable of detecting Process Doppelgänging techniques
- Employ behavior-based detection to identify processes created from transacted files

## 8. Process Herpaderping

Similar to Process Doppelgänging, but exploits the order of process creation and security checks. this technique exploits the fact that Windows performs security checks on the executable file before it starts executing the process.

Key APIs:
- [`CreateFile`](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
  ```c
  HANDLE CreateFileA(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
  );
  ```
- `NtCreateSection` (Undocumented, see above)
- `NtCreateProcessEx` (Undocumented, see above)
- `NtCreateThreadEx` (Undocumented, see above)

Template:
1. Create a file with `CreateFile`
2. Write the malicious payload to the file
3. Create a section for the file using `NtCreateSection`
4. Overwrite the file content with benign data
5. Create a process from the section using `NtCreateProcessEx`
6. Create a thread in the new process with `NtCreateThreadEx`

Detection and Defense:
- Implement file integrity monitoring to detect rapid changes in executable files
- Use behavior-based detection to identify processes with mismatched file contents
- Employ advanced EDR solutions capable of detecting Process Herpaderping techniques
- Monitor for suspicious patterns of file creation, modification, and process creation

## 9. Hooking Injection

This technique uses hooking-related functions to inject a malicious DLL. this technique can also be used for API hooking, not just for injection.

Key APIs:
- [`SetWindowsHookEx`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)
  ```c
  HHOOK SetWindowsHookExA(
    int       idHook,
    HOOKPROC  lpfn,
    HINSTANCE hmod,
    DWORD     dwThreadId
  );
  ```
- [`PostThreadMessage`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postthreadmessagea)
  ```c
  BOOL PostThreadMessageA(
    DWORD  idThread,
    UINT   Msg,
    WPARAM wParam,
    LPARAM lParam
  );
  ```

Template:
1. Create a DLL containing the hook procedure
2. Use `SetWindowsHookEx` to set a hook in the target process
3. Trigger the hook by sending a message with `PostThreadMessage`

Detection and Defense:
- Monitor for suspicious usage of `SetWindowsHookEx`, especially with global hooks
- Implement API hooking detection mechanisms
- Use EDR solutions with capabilities to detect abnormal hook installations
- Employ behavior-based detection to identify processes with unexpected loaded modules

## 10. Extra Windows Memory Injection

This technique injects code into a process by using the Extra Windows Memory (EWM), which is appended to the instance of a class during window class registration. less common and might be detected by some security solutions.

Key APIs:
- [`FindWindowA`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa)
  ```c
  HWND FindWindowA(
    LPCSTR lpClassName,
    LPCSTR lpWindowName
  );
  ```
- [`GetWindowThreadProcessId`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid)
  ```c
  DWORD GetWindowThreadProcessId(
    HWND    hWnd,
    LPDWORD lpdwProcessId
  );
  ```
- `OpenProcess` (see above)
- `VirtualAllocEx` (see above)
- `WriteProcessMemory` (see above)
- [`SetWindowLongPtrA`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlongptra)
  ```c
  LONG_PTR SetWindowLongPtrA(
    HWND     hWnd,
    int      nIndex,
    LONG_PTR dwNewLong
  );
  ```
- [`SendNotifyMessage`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendnotifymessagea)
  ```c
  BOOL SendNotifyMessageA(
    HWND   hWnd,
    UINT   Msg,
    WPARAM wParam,
    LPARAM lParam
  );
  ```

Template:
1. Find the target window with `FindWindowA`
2. Get the process ID of the window with `GetWindowThreadProcessId`
3. Open the process with `OpenProcess`
4. Allocate memory in the target process with `VirtualAllocEx`
5. Write the malicious code to the allocated memory with `WriteProcessMemory`
6. Use `SetWindowLongPtrA` to modify the window's extra memory
7. Trigger the execution with `SendNotifyMessage`

Detection and Defense:
- Monitor for suspicious modifications to window properties
- Implement integrity checks for window class data
- Use EDR solutions with capabilities to detect EWM manipulation
- Employ behavior-based detection to identify processes with unexpected changes in window properties

## 11. Propagate Injection

This technique is used to inject malicious code into processes with medium integrity level, such as explorer.exe. It works by enumerating windows and subclassing them. can be particularly effective for privilege escalation.

Key APIs:
- [`EnumWindows`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows)
  ```c
  BOOL EnumWindows(
    WNDENUMPROC lpEnumFunc,
    LPARAM      lParam
  );
  ```
- [`EnumChildWindows`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumchildwindows)
  ```c
  BOOL EnumChildWindows(
    HWND        hWndParent,
    WNDENUMPROC lpEnumFunc,
    LPARAM      lParam
  );
  ```
- [`EnumProps`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumpropa)
  ```c
  int EnumPropsA(
    HWND      hWnd,
    PROPENUMPROCA lpEnumFunc
  );
  ```
- [`GetProp`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getpropa)
  ```c
  HANDLE GetPropA(
    HWND    hWnd,
    LPCSTR lpString
  );
  ```
- [`SetWindowSubclass`](https://docs.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-setwindowsubclass)
  ```c
  BOOL SetWindowSubclass(
    HWND              hWnd,
    SUBCLASSPROC      pfnSubclass,
    UINT_PTR          uIdSubclass,
    DWORD_PTR         dwRefData
  );
  ```
- `FindWindow` (see above)
- `FindWindowEx` (see above)
- `GetWindowThreadProcessId` (see above)
- `OpenProcess` (see above)
- `ReadProcessMemory` (see above)
- `VirtualAllocEx` (see above)
- `WriteProcessMemory` (see above)
- [`SetPropA`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropa)
  ```c
  BOOL SetPropA(
    HWND    hWnd,
    LPCSTR  lpString,
    HANDLE  hData
  );
  ```
- [`PostMessage`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea)
  ```c
  BOOL PostMessageA(
    HWND   hWnd,
    UINT   Msg,
    WPARAM wParam,
    LPARAM lParam
  );
  ```

Template:
1. Enumerate windows using `EnumWindows` and `EnumChildWindows`
2. For each window, check for subclassed windows using `EnumProps` and `GetProp`
3. Open the target process with `OpenProcess`
4. Allocate memory in the target process with `VirtualAllocEx`
5. Write the malicious code to the allocated memory with `WriteProcessMemory`
6. Subclass the window using `SetWindowSubclass`
7. Set a new property with `SetPropA` to store the payload
8. Trigger execution by sending a message with `PostMessage`

Detection and Defense:
- Monitor for suspicious patterns of window enumeration and subclassing
- Implement integrity checks for window subclassing
- Use EDR solutions with capabilities to detect propagate injection techniques
- Employ behavior-based detection to identify processes with unexpected changes in window subclassing

## 12. Heap Spray

While not strictly an injection technique, heap spraying is often used in conjunction with other injection methods to facilitate exploit payload delivery. modern browsers and operating systems have implemented mitigations against this.

Key APIs:
- [`HeapAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
  ```c
  LPVOID HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
  );
  ```
- [`VirtualAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
  ```c
  LPVOID VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
  );
  ```

Template:
1. Allocate multiple memory blocks using `HeapAlloc` or `VirtualAlloc`
2. Fill these blocks with a combination of NOP sleds and the payload
3. Repeat this process to cover a large portion of the process's address space

Detection and Defense:
- Implement memory allocation monitoring to detect suspicious patterns
- Use address space layout randomization (ASLR) to mitigate heap spraying attacks
- Employ EDR solutions with capabilities to detect heap spraying techniques
- Implement browser-specific mitigations, such as randomizing heap allocation

## 13. Thread Execution Hijacking

This technique involves suspending a legitimate thread in a target process, modifying its execution context to point to malicious code, and then resuming the thread. saving and restoring the original thread context required to maintain process stability.

Key APIs:
- `OpenThread` (see above)
- `SuspendThread` (see above)
- `GetThreadContext` (see above)
- `SetThreadContext` (see above)
- `VirtualAllocEx` (see above)
- `WriteProcessMemory` (see above)
- `ResumeThread` (see above)

Template:
1. Open the target thread with `OpenThread`
2. Suspend the thread with `SuspendThread`
3. Get the thread context with `GetThreadContext`
4. Allocate memory in the target process with `VirtualAllocEx`
5. Write the malicious code to the allocated memory with `WriteProcessMemory`
6. Modify the thread context to point to the injected code with `SetThreadContext`
7. Resume the thread with `ResumeThread`

Detection and Defense:
- Monitor for suspicious patterns of thread suspension and resumption
- Implement thread execution monitoring to detect unexpected changes in execution flow
- Use EDR solutions with capabilities to detect thread hijacking techniques
- Employ runtime analysis to identify unusual thread behavior

## 14. Module Stomping

This technique overwrites the memory of a legitimate module in the target process with malicious code, potentially bypassing some security checks. detected by integrity checks on loaded modules.

Key APIs:
- [`GetModuleInformation`](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation)
  ```c
  BOOL GetModuleInformation(
    HANDLE       hProcess,
    HMODULE      hModule,
    LPMODULEINFO lpmodinfo,
    DWORD        cb
  );
  ```
- [`VirtualProtectEx`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
  ```c
  BOOL VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
  );
  ```
- `WriteProcessMemory` (see above)

Template:
1. Open the target process with `OpenProcess`
2. Get information about the target module using `GetModuleInformation`
3. Change the memory protection of the module to writable using `VirtualProtectEx`
4. Overwrite the module's code section with malicious code using `WriteProcessMemory`
5. Restore the original memory protection with `VirtualProtectEx`

Detection and Defense:
- Implement module integrity checks to detect modifications to loaded modules
- Use EDR solutions with capabilities to detect module stomping techniques
- Employ memory forensics tools to identify signs of module stomping
- Implement code signing and verification mechanisms for loaded modules

## 15. IAT Hooking

This technique modifies the Import Address Table (IAT) of a process to redirect function calls to malicious code. detected by comparing the IAT entries with the actual function addresses in the target DLLs.

Key APIs:
- [`GetProcAddress`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
  ```c
  FARPROC GetProcAddress(
    HMODULE hModule,
    LPCSTR  lpProcName
  );
  ```
- [`VirtualProtect`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
  ```c
  BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
  );
  ```

Template:
1. Locate the IAT of the target process
2. Identify the function to be hooked
3. Change the memory protection of the IAT to writable using `VirtualProtect`
4. Replace the original function address with the address of the malicious function
- Calculate the address of the IAT entry for the target function
- Read the original function address from the IAT entry
- Replace the original function address with the address of the malicious function
5. Restore the original memory protection

Detection and Defense:
- Implement IAT integrity checks to detect modifications
- Use EDR solutions with capabilities to detect IAT hooking
- Employ runtime analysis to identify unexpected function redirections
- Implement code signing and verification mechanisms for loaded modules

## 16. Inline Hooking

This technique modifies the first few instructions of a function to redirect execution to malicious code. requires careful handling of multi-byte instructions and relative jumps. 

Key APIs:
- `VirtualProtect` (see above)
- [`memcpy`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy)
  ```c
  void *memcpy(
    void *dest,
    const void *src,
    size_t count
  );
  ```

Template:
1. Locate the target function in memory
2. Change the memory protection to writable using `VirtualProtect`
3. Save the original instructions (usually 5 or more bytes)
4. Overwrite the beginning of the function with a jump to the malicious code
5. In the malicious code, execute the saved original instructions and then jump back to the original function

Detection and Defense:
- Implement function integrity checks to detect modifications to function prologues
- Use EDR solutions with capabilities to detect inline hooking
- Employ runtime analysis to identify unexpected changes in function execution flow
- Implement code signing and verification mechanisms for loaded modules

## 17. Debugger Injection

This technique uses debugging APIs to inject code into a target process. can be detected by anti-debugging checks in the target process.

Key APIs:
- [`DebugActiveProcess`](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess)
  ```c
  BOOL DebugActiveProcess(
    DWORD dwProcessId
  );
  ```
- [`WaitForDebugEvent`](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)
  ```c
  BOOL WaitForDebugEvent(
    LPDEBUG_EVENT lpDebugEvent,
    DWORD         dwMilliseconds
  );
  ```
- [`ContinueDebugEvent`](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent)
  ```c
  BOOL ContinueDebugEvent(
    DWORD dwProcessId,
    DWORD dwThreadId,
    DWORD dwContinueStatus
  );
  ```

Template:
1. Attach to the target process as a debugger using `DebugActiveProcess`
2. Wait for debug events with `WaitForDebugEvent`
3. When a suitable event occurs, inject the malicious code using `WriteProcessMemory`
4. Modify the thread context to execute the injected code
5. Continue the debug event with `ContinueDebugEvent`

Detection and Defense:
- Implement anti-debugging techniques in sensitive applications
- Monitor for suspicious use of debugging APIs
- Use EDR solutions with capabilities to detect debugger-based injection
- Employ runtime analysis to identify unexpected debugging events

## 18. COM Hijacking

This technique involves replacing legitimate COM objects with malicious ones to execute code when the COM object is instantiated. used for persistence, not just for injection.

Key APIs:
- [`CoCreateInstance`](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
  ```c
  HRESULT CoCreateInstance(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID *ppv
  );
  ```
- [`RegOverridePredefKey`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regoverridepredefkey)
  ```c
  LSTATUS RegOverridePredefKey(
    HKEY hKey,
    HKEY hNewHKey
  );
  ```

Template:
1. Create a malicious COM object
2. Modify the registry to replace the CLSID of a legitimate COM object with the malicious one
3. When the application calls `CoCreateInstance`, the malicious object will be instantiated instead

Detection and Defense:
- Implement COM object integrity checks
- Monitor for suspicious registry modifications related to COM objects
- Use application whitelisting to prevent unauthorized COM objects from loading
- Employ behavior-based detection to identify unexpected COM object instantiation

## 19. Phantom DLL Hollowing

This technique involves creating a new section in a legitimate DLL and injecting code into it.

Key APIs:
- [`LoadLibraryEx`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa)
  ```c
  HMODULE LoadLibraryExA(
    LPCSTR lpLibFileName,
    HANDLE hFile,
    DWORD  dwFlags
  );
  ```
- [`VirtualAlloc`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
  ```c
  LPVOID VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
  );
  ```
- [`VirtualProtect`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
  ```c
  BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
  );
  ```

Template:
1. Load a legitimate DLL using `LoadLibraryEx` with `DONT_RESOLVE_DLL_REFERENCES` flag
2. Allocate a new memory section using `VirtualAlloc`
3. Copy the malicious code to the new section
4. Modify the DLL's PE headers to include the new section
5. Change the memory protection of the new section using `VirtualProtect`
6. Execute the injected code

Detection and Defense:
- Implement DLL integrity checks to detect modifications
- Monitor for suspicious patterns of DLL loading and memory allocation
- Use EDR solutions with capabilities to detect phantom DLL hollowing
- Employ memory forensics tools to identify signs of DLL manipulation

## 20. PROPagate

This technique abuses the SetProp/GetProp Windows API functions to achieve code execution.

Key APIs:
- [`SetProp`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropa)
  ```c
  BOOL SetPropA(
    HWND   hWnd,
    LPCSTR lpString,
    HANDLE hData
  );
  ```
- [`GetProp`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getpropa)
  ```c
  HANDLE GetPropA(
    HWND   hWnd,
    LPCSTR lpString
  );
  ```
- [`EnumPropsEx`](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumpropsexw)
  ```c
  int EnumPropsExW(
    HWND          hWnd,
    PROPENUMPROCEXW lpEnumFunc,
    LPARAM        lParam
  );
  ```

Template:
1. Find a target window using `FindWindow` or `EnumWindows`
2. Allocate memory for the payload using `VirtualAllocEx`
3. Write the payload to the allocated memory using `WriteProcessMemory`
4. Use `SetProp` to set a property on the window, with the payload address as the property value
- Create a custom window procedure that executes the payload
- Use `SetWindowLongPtr` to replace the original window procedure with the custom one
6. Trigger the execution by causing the window to enumerate its properties (e.g., by sending a message that causes a redraw)

Detection and Defense:
- Monitor for suspicious modifications to window properties
- Implement integrity checks for window properties
- Use EDR solutions with capabilities to detect PROPagate techniques
- Employ behavior-based detection to identify processes with unexpected changes in window properties

## 21. Early Bird Injection

This technique injects code into a process during its initialization, before the main thread starts executing.

Key APIs:
- [`CreateProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
  ```c
  BOOL CreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
  );
  ```
- `VirtualAllocEx` (see above)
- `WriteProcessMemory` (see above)
- `QueueUserAPC` (see above)
- `ResumeThread` (see above)

Template:
1. Create a new process in suspended state using `CreateProcess` with `CREATE_SUSPENDED` flag
2. Allocate memory in the new process using `VirtualAllocEx`
3. Write the payload to the allocated memory using `WriteProcessMemory`
4. Queue an APC to the main thread using `QueueUserAPC`, pointing to the payload
5. Resume the main thread using `ResumeThread`

Detection and Defense:
- Monitor for process creation with the `CREATE_SUSPENDED` flag
- Implement process initialization monitoring to detect unexpected code execution
- Use EDR solutions with capabilities to detect Early Bird injection techniques
- Employ behavior-based detection to identify processes with abnormal initialization patterns

## 22. Shim-based Injection

This technique leverages the Windows Application Compatibility framework to inject code.

Key APIs:
- [`SdbCreateDatabase`](https://docs.microsoft.com/en-us/windows/win32/api/appcompatapi/nf-appcompatapi-sdbcreatedatabase)
  ```c
  PDB SdbCreateDatabase(
    LPCWSTR pwszPath
  );
  ```
- [`SdbWriteDWORDTag`](https://docs.microsoft.com/en-us/windows/win32/api/appcompatapi/nf-appcompatapi-sdbwritedwordtag)
  ```c
  BOOL SdbWriteDWORDTag(
    PDB  pdb,
    TAG  tTag,
    DWORD dwData
  );
  ```
- [`SdbEndWriteListTag`](https://docs.microsoft.com/en-us/windows/win32/api/appcompatapi/nf-appcompatapi-sdbendwritelisttag)
  ```c
  BOOL SdbEndWriteListTag(
    PDB pdb,
    TAG tTag
  );
  ```

Template:
1. Create a shim database using `SdbCreateDatabase`
2. Write shim data to the database, including the payload and target application
3. Install the shim database using `sdbinst.exe`
4. The payload will be executed when the target application is launched

Detection and Defense:
- Monitor for suspicious shim database creation and installation
- Implement application compatibility shim monitoring
- Use EDR solutions with capabilities to detect shim-based injection techniques
- Employ whitelisting for approved shims and block unauthorized shim installations

## 23. Mapping Injection

This technique uses memory-mapped files to inject code into a remote process.

Key APIs:
- [`CreateFileMapping`](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
  ```c
  HANDLE CreateFileMappingA(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCSTR                lpName
  );
  ```
- [`MapViewOfFile`](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
  ```c
  LPVOID MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
  );
  ```
- `NtMapViewOfSection` (Undocumented)
  ```c
  NTSTATUS NTAPI NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
  );
  ```

Template:
1. Create a file mapping object using `CreateFileMapping`
2. Map a view of the file into the current process using `MapViewOfFile`
3. Write the payload to the mapped view
4. Use `NtMapViewOfSection` to map the view into the target process
5. Execute the payload in the target process

Detection and Defense:
- Monitor for suspicious patterns of file mapping and view creation
- Implement memory mapping monitoring to detect unexpected shared memory usage
- Use EDR solutions with capabilities to detect mapping injection techniques
- Employ behavior-based detection to identify processes with abnormal memory-mapped file usage

## 24. KnownDlls Cache Poisoning

This technique involves replacing a legitimate DLL in the KnownDlls cache with a malicious one.

Key APIs:
- [`NtSetSystemInformation`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntsetsysteminformation) (Undocumented)
  ```c
  NTSTATUS NTAPI NtSetSystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength
  );
  ```

Template:
1. Create a malicious DLL with the same name as a legitimate KnownDlls entry
2. Create a Section object for the malicious DLL:
	- Use NtCreateSection to create a section object
	- Map a view of the section into memory
	- Write the malicious DLL content to the mapped view
3. Use `NtSetSystemInformation` with `SystemExtendServiceTableInformation` to add the malicious DLL to the KnownDlls cache
4. The malicious DLL will be loaded instead of the legitimate one by processes

Detection and Defense:
- Implement KnownDlls integrity checks
- Monitor for modifications to the KnownDlls cache
- Use EDR solutions with capabilities to detect KnownDlls cache poisoning
- Employ whitelisting and code signing verification for DLLs in the KnownDlls cache

## Additional Considerations for Detection and Defense

1. Implement a robust Application Whitelisting strategy to prevent unauthorized executables and DLLs from running.
2. Use Windows Defender Exploit Guard or similar technologies to enable Attack Surface Reduction (ASR) rules.
3. Keep systems and software up-to-date with the latest security patches.
4. Utilize User Account Control (UAC) and principle of least privilege to limit the impact of successful injections.
5. Implement Network Segmentation to limit lateral movement in case of a successful attack.
6. Use Runtime Application Self-Protection (RASP) technologies to detect and prevent injection attempts in real-time.
7. Regularly perform threat hunting activities to proactively search for signs of injection techniques.
8. Implement and maintain a robust Security Information and Event Management (SIEM) system to correlate and analyze security events.
9. Conduct regular security awareness training for users to recognize and report suspicious activities.
10. Perform regular penetration testing and red team exercises to identify vulnerabilities and improve defenses against injection techniques.

## Process Enumeration

```c
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <errhandlingapi.h> // GetLastError
#include <heapapi.h> // HeapCreate, HeapAlloc, HeapDestroy
#include <strsafe.h> // StringCchPrintf
#include <assert.h>
#include <tchar.h>

void ErrorExit(LPCTSTR lpszFunction);
int ProcessEnumerateAndSearch(const wchar_t* ProcessName, PROCESSENTRY32* lppe);
int PrintProcessInfo(const PROCESSENTRY32* lppe);

int PrintProcessInfo(const PROCESSENTRY32* lppe)
{
    assert(lppe);

    wprintf(L"PROCESS : %ls\n", lppe->szExeFile);

    int PID = static_cast<int>(lppe->th32ProcessID);
    if (PID == 0) {
        wprintf(L"ERR : Process Not Found.\n");
        return 0;
    }

    wprintf(L"PID : %i\n\n", PID);
    return 1;
}

void ErrorExit(LPCTSTR functionName)
{
    constexpr DWORD FLAGS = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    constexpr DWORD LANG_ID = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    constexpr size_t EXTRA_CHARS = 40;

    DWORD errorCode = GetLastError();
    LPTSTR messageBuf = nullptr;

    FormatMessage(FLAGS, NULL, errorCode, LANG_ID, (LPTSTR)&messageBuf, 0, NULL);

    if (messageBuf) {
        size_t funcNameLen = _tcslen(functionName);
        size_t messageLen = _tcslen(messageBuf);
        size_t bufSize = (funcNameLen + messageLen + EXTRA_CHARS) * sizeof(TCHAR);

        LPTSTR displayBuf = static_cast<LPTSTR>(LocalAlloc(LMEM_ZEROINIT, bufSize));
        if (displayBuf) {
            StringCchPrintf(displayBuf, LocalSize(displayBuf) / sizeof(TCHAR), TEXT("%s failed with error %d: %s"), functionName, errorCode, messageBuf);
            MessageBox(NULL, displayBuf, TEXT("Error"), MB_OK);

            LocalFree(displayBuf);
        }

        LocalFree(messageBuf);
    }

    ExitProcess(errorCode);
}

int ProcessEnumerateAndSearch(const wchar_t* ProcessName, PROCESSENTRY32* lppe)
{
    assert(ProcessName && lppe);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        ErrorExit(TEXT("CreateToolhelp32Snapshot"));

    lppe->dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, lppe) == FALSE) {
        CloseHandle(hSnapshot);
        ErrorExit(TEXT("Process32First"));
    }

    int pFoundFlag = 0;
    do {
        size_t wcProcessName = wcslen(ProcessName);
        if (wcsncmp(lppe->szExeFile, ProcessName, wcProcessName) == 0) {
            if (!PrintProcessInfo(lppe)) continue;
            pFoundFlag = 1;
            break;
        }
    } while (Process32Next(hSnapshot, lppe));

    CloseHandle(hSnapshot);

    return pFoundFlag;
}

int main(int argc, char** argv)
{
    wchar_t pName[] = L"smss.exe"; // process name we will be injecting
    PROCESSENTRY32 lppe = { 0 };

    if (ProcessEnumerateAndSearch(pName, &lppe)) {
        // do some stuff
    }
    else {
        return 1;
    }

    return 0;
}
```
