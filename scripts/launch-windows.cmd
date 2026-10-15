@echo off
setlocal
set "VEIL_CHAT_WORKER_EXECUTABLE=%~dp0worker\veil-chat-ipc-worker.exe"
if not exist "%VEIL_CHAT_WORKER_EXECUTABLE%" (
  echo The Veil Chat Windows package is incomplete. 1>&2
  exit /b 2
)
if not exist "%~dp0VeilChat.Desktop.exe" (
  echo The Veil Chat application executable is missing. 1>&2
  exit /b 2
)
"%~dp0VeilChat.Desktop.exe"
exit /b %ERRORLEVEL%
