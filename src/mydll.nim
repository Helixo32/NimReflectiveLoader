# nim -d:mingw --app=lib --cpu=amd64 --nomain c mydll.nim

import winim/lean



proc NimMain() {.cdecl, importc.}



proc MyExportedFunction(hwnd: HWND, hinst: HINSTANCE, lpszCmdLine: LPSTR, nCmdShow: int) {.stdcall, exportc, dynlib.} =
    MessageBox(0, "Hello from MyExportedFunction", "Information", MB_OK)



proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
  
    if fdwReason == DLL_PROCESS_ATTACH:
        MessageBox(0, "DLL attached !", "Information", MB_OK)

    return true
