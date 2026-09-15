@echo off
set PATH=E:\weixin-hook-4.1.8\hook-wx\toolchain\mingw64\bin;%PATH%
cd /d E:\weixin-hook-4.1.8\hook-wx\m3
gcc -O2 -fms-extensions -shared -o bin\wx_send.dll src\wx_send.c ..\m1\src\ReflectiveLoader.c -Wl,--out-implib,bin\wx_send.a 2>&1
echo EXIT=%ERRORLEVEL%
