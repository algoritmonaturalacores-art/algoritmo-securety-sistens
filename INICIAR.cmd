@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
python --version >nul 2>&1
if errorlevel 1 goto sem_python
python programa.py
pause
exit /b
:sem_python
echo E necessario Python 3.10 ou superior.
echo Instala a partir de https://www.python.org/downloads/windows/
echo Ativa a opcao Add python.exe to PATH e volta a abrir este ficheiro.
pause
