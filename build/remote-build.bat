@echo off
REM eBPF AI Agent 远程构建 - Windows 启动脚本

echo ========================================
echo eBPF AI Agent 远程构建
echo ========================================
echo.

REM 检查参数
if "%1"=="" goto usage
if "%2"=="" goto usage

setlocal enabledelayedexpansion

set "VM_HOST=%1"
set "VM_USER=%2"
set "VM_PORT=%3"
set "VM_KEY=%4"
set "VM_PASSWORD=%5"

REM 默认端口
if "%VM_PORT%"=="" set "VM_PORT=22"

:parse
if "%~6"=="" goto run
if "%~6"=="--key" (
    set "VM_KEY=%~7"
    shift
    shift
    goto parse
)
if "%~6"=="--password" (
    set "VM_PASSWORD=%~7"
    shift
    shift
    goto parse
)

:run
echo 目标虚拟机: %VM_USER%@%VM_HOST%:%VM_PORT%
echo.

REM 检查 sshpass 是否可用
where sshpass >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARN] sshpass 未安装，密码认证可能不可用
    echo 请使用 --key 指定私钥文件
    echo.
)

REM 调用 bash 脚本
bash "%~dp0remote-build.sh" --host %VM_HOST% --user %VM_USER% --port %VM_PORT% %VM_KEY% %VM_PASSWORD%

goto :end

:usage
echo 用法: remote-build.bat ^<VM_IP^> ^<VM_USER^> [SSH_PORT] [OPTIONS]
echo.
echo 示例:
echo   remote-build.bat 192.168.1.100 ubuntu --key C:\Users\me\.ssh\id_rsa
echo   remote-build.bat 192.168.1.100 ubuntu 22 --password mypassword
echo.
echo   --key ^<file^>     SSH 私钥文件
echo   --password ^<pass^> SSH 密码
echo.
echo 完整用法请查看: bash remote-build.sh --help
echo.

:end
