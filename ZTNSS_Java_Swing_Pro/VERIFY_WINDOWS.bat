@echo off
cd /d "%~dp0"
echo Checking Java build...
if not exist out mkdir out
javac -encoding UTF-8 -d out src\main\java\com\ztnss\ZTNSSApp.java
if errorlevel 1 (echo Java build FAILED & pause & exit /b 1)
echo Checking Python agent/controller syntax...
python -m py_compile endpoint\agent.py endpoint\controller.py
if errorlevel 1 (echo Python syntax FAILED & pause & exit /b 1)
echo Verification passed. To run desktop UI, double-click RUN_ZTNSS.bat
pause
