@echo off
title ZTNSS Pro - Java Swing
cd /d "%~dp0"
where javac >nul 2>nul
if errorlevel 1 (echo JDK 17 or newer is required. Install a JDK and add it to PATH.& pause & exit /b 1)
where nmap >nul 2>nul
if errorlevel 1 echo WARNING: Nmap not found in PATH. The dashboard opens, but scanning will not work.
if not exist out mkdir out
javac -encoding UTF-8 -d out src\main\java\com\ztnss\ZTNSSApp.java
if errorlevel 1 (echo Compilation failed.& pause & exit /b 1)
java -cp out com.ztnss.ZTNSSApp
pause
