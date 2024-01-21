# NimReflectiveLoader

[![Nim Version](https://img.shields.io/badge/nim-2.0.0-orange.svg)](https://nim-lang.org/)

## Overview
NimReflectiveLoader is a tool developed in Nim, specializing in executing DLLs entirely in memory. This project leverages Reflective DLL Loading, a technique that allows DLLs to be loaded and executed without being written to disk, thereby enhancing stealth and efficiency. It also enables the execution of specific exported functions within these DLLs.

## Features
- **Reflective DLL Loading**: Load and execute DLLs entirely in memory.
- **Function Invocation**: Capability to call exported functions from the loaded DLLs.
- **Stealth Operation**: Operates without leaving traces on disk.

## Getting Started
### Installation
1. Clone the repository:
	- git clone https://github.com/Helixo32/NimReflectiveLoader

2. Compile the source code using Nim:
	- Linux
		- nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc c RunRemoteDll.nim
	- Windows
		- nim c RunRemoteDll.nim

## Usage
After compiling, you can load and execute DLLs in memory using the NimReflectiveLoader and also invoke specific exported functions from these DLLs.
You need to change the URL and exported function on lines 445 and 446.

## Demo
[https://github.com/Helixo32/NimReflectiveLoader/raw/main/Demo.mp4](https://github.com/Helixo32/NimReflectiveLoader/assets/73953510/f246e922-19ae-4f24-9490-4bc8ebb1ae5e)

## License
This project is licensed under MIT License - see the LICENSE file for details.

## Acknowledgments
- https://maldevacademy.com/
- https://github.com/S3cur3Th1sSh1t/Nim-RunPE

---

*NimReflectiveLoader - Bridging advanced DLL loading techniques with the efficiency of Nim and the flexibility of exported function invocation.*
