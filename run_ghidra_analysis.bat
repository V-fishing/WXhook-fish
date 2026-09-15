# Ghidra headless 分析启动脚本
# 分析 Weixin.dll (198MB) - 预计 12-24 小时
@echo off
set JAVA_HOME=E:\study\java\JAVA_JDK21
set PATH=%JAVA_HOME%\bin;%PATH%

set GHIDRA=E:\weixin-hook-4.1.8\hook-wx\toolchain\ghidra
set PROJECT_DIR=E:\weixin-hook-4.1.8\hook-wx\ghidra_project
set PROJECT_NAME=Weixin4113
set DLL_PATH=D:\Weixin\4.1.13.65\Weixin.dll

echo ============================================================
echo   Ghidra Headless Analysis - Weixin.dll (4.1.13.65)
echo   预计分析时间: 12-24 小时
echo   项目目录: %PROJECT_DIR%
echo ============================================================
echo.

"%GHIDRA%\support\analyzeHeadless.bat" "%PROJECT_DIR%" %PROJECT_NAME% -import "%DLL_PATH%" -analysisTimeoutPerFile 86400

echo.
echo ============================================================
echo   分析完成! 
echo   下一步: 运行 Ghidra GUI 打开项目查看分析结果
echo ============================================================
pause
