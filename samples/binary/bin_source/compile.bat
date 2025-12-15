set SRC_DIR=D:\Universita\Unimercatorum\TESI\SecurityMonster\samples\binary\source
set TGT_DIR=D:\Universita\Unimercatorum\TESI\SecurityMonster\samples\binary
set COMPILER_PATH=D:\msys64\mingw64\bin
set COMPILER=%COMPILER_PATH%\gcc.exe

cd %COMPILER_PATH%
for %%f in (D:\Universita\Unimercatorum\TESI\SecurityMonster\samples\binary\source\*.c) do (
"%COMPILER%" -c %SRC_DIR%/%%~nxf -o %TGT_DIR%/%%~nf.exe -lz  -lcrypto -lssl -lws2_32
"%COMPILER%" -shared %SRC_DIR%/%%~nxf -o %TGT_DIR%/%%~nf.dll -lz -lcrypto -lssl -lws2_32
)
EXIT
echo Compilazione msys64 completata!
pause