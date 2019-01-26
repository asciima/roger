@echo off

for /f "tokens=1,2,3,4,5,6* delims=," %%i in ('.\date.exe +"%%Y,%%m,%%d,%%H,%%M,%%S"') do set yy=%%i& set mo=%%j& set dd=%%k& set hh=%%l& set mm=%%m& set ss=%%n

set YMDHM=%yy%-%mo%-%dd%_%hh%_%mm%

if not exist %YMDHM% (
	echo '%YMDHM% not exists, do md %YMDHM%'
	md "%YMDHM%"
)

echo %CD%

COPY /Y "..\build\readme.txt" ".\%YMDHM%\"
COPY /Y "..\build\start_roger_wcp.bat" ".\%YMDHM%\"


XCOPY /S /Q /Y "..\trunk\projects\roger\projects\msvc\roger_client\Debug\roger_Debug.exe" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\msvc\roger_client\Release\roger.exe" ".\%YMDHM%\"

XCOPY /S /Q /Y "..\trunk\projects\roger\projects\msvc\roger\Debug\rserver_Debug.exe" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\msvc\roger\Release\rserver.exe" ".\%YMDHM%\"

XCOPY /S /Q /Y "..\trunk\projects\roger\projects\msvc\roger_client\proxy.pac" ".\%YMDHM%\"

XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\x86_64\roger_client.x86_64_debug" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\x86_64\roger_client.x86_64_release" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\x86_64\roger_server.x86_64_debug" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\x86_64\roger_server.x86_64_release" ".\%YMDHM%\"

XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\armv7ahf\roger_client.armv7ahf_debug" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\armv7ahf\roger_client.armv7ahf_release" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\armv7ahf\roger_server.armv7ahf_debug" ".\%YMDHM%\"
XCOPY /S /Q /Y "..\trunk\projects\roger\projects\build\armv7ahf\roger_server.armv7ahf_release" ".\%YMDHM%\"