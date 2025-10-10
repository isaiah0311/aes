# AES
An implementation of AES in C.

## Project Structure
```text
├── .vscode                    <- Settings and configurations
├── bin                        <- Compiled binaries
│   ├── debug                  <- Binaries compiled with debugging symbols
│   │   ├── x64                <- 64-bit debug binaries
│   │   └── x86                <- 32-bit debug binaries
│   └── release                <- Binaries compiled with optimization
│       ├── x64                <- 64-bit release binaries
│       └── x86                <- 32-bit release binaries
├── res                        <- Resource files
├── src                        <- Source files
├── .clang-format              <- Coding format file
├── .gitignore                 <- Repository ignores
├── aes.vcxproj                <- Build instructions for msbuild
├── LICENSE                    <- License
├── Makefile                   <- Build instructions for make
└── README.md                  <- You are here
```

## Dependencies
### Windows
- **Compiler:** Microsoft Visual Studio Build Tools 2022 (MSVC)
- **Build System:** `msbuild`
### Linux
- **Compiler:** GCC
- **Build System:** `make`

## How to Build
### VS Code
1. Press Ctrl + Shift + B to open the build menu.
2. Select "Build".
3. Select a configuration.
4. Select a platform.


**Note:** If you are using `msbuild`, start VS Code from the Developer Command
Prompt to set up the environment. Open the Developer Command Prompt, then type
`code`.
### Command Line
1. Navigate to the root of the project.
2. Run either
`msbuild /p:Configuration={ Debug | Release } /p:Platform={ Win32 | x64 }` or
`make CONFIGURATION={ debug | release } PLATFORM={ x86 | x64 }`.


**Note:** If you are using `msbuild`, run it from the Developer Command Prompt.

## How to Run
### VS Code
1. Press Ctrl + Shift + D to open the run and debug menu.
2. Select "(Windows) Launch" to use the Visual Studio Debugger, or "(gdb)
Launch" to use GDB from the drop-down menu.
3. Press F5 or the green play button to the left of the drop-down menu.
4. Select a configuration.
5. Select a platform.
### Command Line
1. Navigate to the root of the project.
2. Run `bin\{ debug | release }\{ x86 | x64 }\aes.exe` if you are on Windows or
`./bin/{ debug | release }\{ x86 | x64 }/aes` if you are on Linux.

## License
This project is licensed under the [MIT License](LICENSE).

## Authors
**Isaiah Lateer**\
GitHub: [isaiah0311](https://github.com/isaiah0311)  
Email: isaiahL0311@gmail.com
