@echo off
cls
set SRC_DIR=D:\Universita\Unimercatorum\TESI\SecurityMonster\samples\binary\source
set LIB_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64
set INC_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include

cd /d "%SRC_DIR%"
echo %LIB_PATH%
for %%f in ("%SRC_DIR%\*.c") do (
    echo ######################################################
    echo Compiling %%~nxf...
    cl "%%f" ^
       /Fe:"%%~nf.exe" ^
       /I"%INC_PATH%" ^
       /I"D:\Program Files\OpenSSL-Win64\include" ^
       /I"C:\tmp\vcpkg\installed\x64-windows\include" ^
       /link ^
       /OPT:NOREF /OPT:NOICF ^
       /LIBPATH:"%LIB_PATH%" ^
       /LIBPATH:"D:\Program Files\OpenSSL-Win64\lib" ^
       /LIBPATH:"C:\tmp\vcpkg\installed\x64-windows\lib" ^
       libcrypto.lib libssl.lib zlib.lib ws2_32.lib
)

echo Compilazione cl completata.
pause