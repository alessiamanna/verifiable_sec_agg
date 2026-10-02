@echo off
if exist "C:\msys64\ucrt64\bin\python.exe" (
    "C:\msys64\ucrt64\bin\python.exe" "%~dp0run_benchmark.py" %*
) else (
    python "%~dp0run_benchmark.py" %*
)
