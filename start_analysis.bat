@echo off
set JAVA_HOME=E:\study\java\JAVA_JDK21
set PATH=%JAVA_HOME%\bin;%PATH%

echo Starting Ghidra headless analysis of Weixin.dll...
echo This will take 12-24 hours. Do not close this window.
echo.

"E:\weixin-hook-4.1.8\hook-wx\toolchain\ghidra\support\analyzeHeadless.bat" ^
    "E:\weixin-hook-4.1.8\hook-wx\ghidra_project" ^
    Weixin4113 ^
    -import "D:\Weixin\4.1.13.65\Weixin.dll" ^
    -analysisTimeoutPerFile 86400

echo.
echo Analysis complete!
pause
