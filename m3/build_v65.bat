@echo off
set PATH=E:\weixin-hook-4.1.8\hook-wx	oolchain\mingw64in;%PATH%
cd /d E:\weixin-hook-4.1.8\hook-wx\m3
gcc -O2 -fms-extensions -shared -o bin\wx_send_v65.dll src\wx_send_v65.c ..\m1\src\ReflectiveLoader.c -Wl,--out-implib,bin\wx_send_v65.a 2>&1
echo EXIT=%ERRORLEVEL%
