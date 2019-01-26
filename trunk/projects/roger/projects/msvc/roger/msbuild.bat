@echo off

set MSBUILD="C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe"

%MSBUILD% rserver.sln /t:Rebuild /p:Configuration=Debug;Platform=Win32
%MSBUILD% rserver.sln /t:Rebuild /p:Configuration=Release;Platform=Win32