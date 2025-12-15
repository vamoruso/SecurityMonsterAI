REM Compila tutti i file .c nella cartella binary usando WSL gcc

set SRC_DIR=/mnt/d/Universita/Unimercatorum/TESI/SecurityMonster/samples/binary/source
set TGT_DIR=/mnt/d/Universita/Unimercatorum/TESI/SecurityMonster/samples/binary

REM Ciclo su tutti i file .c
for %%f in (D:\Universita\Unimercatorum\TESI\SecurityMonster\samples\binary\source\*.c) do (
    echo Compilo %%f ...
    wsl gcc -fPIC -c %SRC_DIR%/%%~nxf -o %TGT_DIR%/%%~nf.o
    wsl gcc -shared -o %TGT_DIR%/%%~nf.so %TGT_DIR%/%%~nf.o -lz -lcrypto -lssl
    wsl ar rcs %TGT_DIR%/%%~nf.a %TGT_DIR%/%%~nf.o

)

echo Compilazione Linux completata!
