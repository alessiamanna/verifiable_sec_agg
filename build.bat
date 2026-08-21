@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo   HeVerSa Protocol - Windows Build Script
echo =======================================================

:: Set default parameters if not provided
set UPDATE_LEN=16
set MAX_NUM_CLIENTS=10
if not "%~1"=="" set UPDATE_LEN=%~1
if not "%~2"=="" set MAX_NUM_CLIENTS=%~2

echo Configuration: UPDATE_LEN=%UPDATE_LEN%, MAX_NUM_CLIENTS=%MAX_NUM_CLIENTS%

:: Check and add MSYS2 / MinGW to PATH if not already present
where g++ >nul 2>&1
if %errorlevel% neq 0 (
    if exist "C:\msys64\ucrt64\bin\g++.exe" (
        echo [INFO] Found GCC/G++ in C:\msys64\ucrt64\bin, adding to PATH...
        set "PATH=C:\msys64\ucrt64\bin;%PATH%"
    ) else if exist "C:\msys64\mingw64\bin\g++.exe" (
        echo [INFO] Found GCC/G++ in C:\msys64\mingw64\bin, adding to PATH...
        set "PATH=C:\msys64\mingw64\bin;%PATH%"
    ) else (
        echo [ERROR] g++ was not found in PATH or C:\msys64. Please install MinGW/GCC.
        exit /b 1
    )
)

:: Fix Windows Git symlink placeholders in src/sss
if exist "src\sss\randombytes\randombytes.h" (
    copy /Y "src\sss\randombytes\randombytes.h" "src\sss\randombytes.h" >nul
)
if exist "src\sss\randombytes\randombytes.c" (
    copy /Y "src\sss\randombytes\randombytes.c" "src\sss\randombytes.c" >nul
)

:: Create build output directory if missing
if not exist "build" (
    mkdir build
)

echo.
echo [1/3] Compiling C cryptographic dependencies (SSS, TweetNaCl, RandomBytes)...
gcc -O2 -Isrc/sss -c src/sss/sss.c -o build/sss.o
if %errorlevel% neq 0 ( echo [ERROR] Failed compiling sss.c & exit /b %errorlevel% )

gcc -O2 -Isrc/sss -c src/sss/hazmat.c -o build/hazmat.o
if %errorlevel% neq 0 ( echo [ERROR] Failed compiling hazmat.c & exit /b %errorlevel% )

gcc -O2 -c src/sss/tweetnacl.c -o build/tweetnacl.o
if %errorlevel% neq 0 ( echo [ERROR] Failed compiling tweetnacl.c & exit /b %errorlevel% )

gcc -O2 -c src/sss/randombytes.c -o build/randombytes.o
if %errorlevel% neq 0 ( echo [ERROR] Failed compiling randombytes.c & exit /b %errorlevel% )

echo.
echo [2/3] Compiling HeVerSa C++ Protocol Simulator...
g++ -std=c++17 -O2 -DDEBUG=1 -DUPDATE_LEN=%UPDATE_LEN% -DMAX_NUM_CLIENTS=%MAX_NUM_CLIENTS% ^
    -Isrc -Isrc/sss ^
    src/main_ta.cpp ^
    src/heversa_api.cpp ^
    src/heversa_sim.cpp ^
    src/node.cpp ^
    src/server.cpp ^
    src/ta.cpp ^
    src/common_share.cpp ^
    src/puf_manager.cpp ^
    src/crypto_utils.cpp ^
    build/sss.o build/hazmat.o build/tweetnacl.o build/randombytes.o ^
    -lcrypto -lws2_32 -lcrypt32 ^
    -o build/protocol_sim.exe

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Compilation failed!
    exit /b %errorlevel%
)

echo.
echo [3/3] Build succeeded: build\protocol_sim.exe
echo.
echo =======================================================
echo   Running Simulation Test...
echo =======================================================
build\protocol_sim.exe

echo.
echo Build and execution finished successfully!