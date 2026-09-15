@echo off
set JAVA_HOME=E:\study\java\JAVA_JDK21
set PATH=%JAVA_HOME%\bin;%PATH%
set GHIDRA=E:\weixin-hook-4.1.8\hook-wx\toolchain\ghidra
set PROJECT_DIR=E:\weixin-hook-4.1.8\hook-wx\ghidra_project
"%GHIDRA%\support\analyzeHeadless.bat" "%PROJECT_DIR%" Weixin4113 -process Weixin.dll -noanalysis -scriptPath "E:\weixin-hook-4.1.8\hook-wx\m2" -postScript decompile_final.py > "E:\weixin-hook-4.1.8\hook-wx\m2\final_decompiled.txt" 2>&1
echo EXITCODE=%ERRORLEVEL%
