@echo off
set JAVA_HOME=E:\study\java\JAVA_JDK21
set PATH=%JAVA_HOME%\bin;%PATH%
set GHIDRA=E:\weixin-hook-4.1.8\hook-wx\toolchain\ghidra
"%GHIDRA%\support\analyzeHeadless.bat" "E:\weixin-hook-4.1.8\hook-wx\ghidra_project" Weixin4113 -process Weixin.dll -noanalysis -scriptPath "E:\weixin-hook-4.1.8\hook-wx\m3" -postScript decompile_api2.py > "E:\weixin-hook-4.1.8\hook-wx\m3\api2_decompiled.txt" 2>&1
echo EXIT=%ERRORLEVEL%
