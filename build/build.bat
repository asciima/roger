@echo off

pushd %CD%
	cd "..\trunk\projects\roger\projects\msvc\roger_client"
	call msbuild.bat
popd

pushd %CD%
	cd "..\trunk\projects\roger\projects\msvc\roger\"
	call msbuild.bat
popd
