:: Author: tsgrgo
:: Completely disable Windows Update
:: PsExec is required to get system privileges - it should be in this directory

@echo off
:: Проверка прав администратора
NET FILE 1>NUL 2>NUL || (ECHO Запустите скрипт от имени Администратора! && PAUSE && EXIT)

:: Настройка политики выполнения PowerShell
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force"

:: Получение прав TrustedInstaller для критичных операций
for %%i in (WaaSMedicSvc, wuaueng) do (
    takeown /F C:\Windows\System32\%%i.dll /A
    icacls C:\Windows\System32\%%i.dll /grant:r Administrators:F /T /C /Q
)

:: Отключение контроля учетных записей (UAC)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

:: Разрешение доступа к планировщику задач
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler\5.0" /v AllowProtectedTasks /t REG_DWORD /d 0 /f

:: Получение полного контроля над файлами задач
takeown /F C:\Windows\System32\Tasks\Microsoft\Windows\* /A /R /D Y
icacls C:\Windows\System32\Tasks\Microsoft\Windows\* /grant:r Administrators:(F) /T /C /Q /L
icacls C:\Windows\System32\Tasks\Microsoft\Windows\* /grant:r *S-1-5-32-544:(F) /T /C /Q /L


:: Disable update related services
for %%i in (wuauserv, UsoSvc, uhssvc, WaaSMedicSvc) do (
	net stop %%i
	sc config %%i start= disabled
	sc failure %%i reset= 0 actions= ""
)

:: Brute force rename services
for %%i in (WaaSMedicSvc, wuaueng) do (
	takeown /f C:\Windows\System32\%%i.dll && icacls C:\Windows\System32\%%i.dll /grant *S-1-1-0:F
	rename C:\Windows\System32\%%i.dll %%i_BAK.dll
	icacls C:\Windows\System32\%%i_BAK.dll /setowner "NT SERVICE\TrustedInstaller" && icacls C:\Windows\System32\%%i_BAK.dll /remove *S-1-1-0
)

:: Update registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v FailureActions /t REG_BINARY /d 000000000000000000000000030000001400000000000000c0d4010000000000e09304000000000000000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f

:: Delete downloaded update files
erase /f /s /q c:\windows\softwaredistribution\*.* && rmdir /s /q c:\windows\softwaredistribution

:: Disable all update related scheduled tasks
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\InstallService\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateAssistant\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WaaSMedic\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\WindowsUpdate\*' | Disable-ScheduledTask"

echo Finished
pause