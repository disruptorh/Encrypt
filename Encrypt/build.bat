@echo off
set "PYTHON_EXE=python"
set "MAIN_SCRIPT=app.py"
set "OUTPUT_DIR=Encrypt"
set "EXE_NAME=Encrypt"

echo Compilando %MAIN_SCRIPT% con Nuitka...

%PYTHON_EXE% -m nuitka ^
    --standalone ^
    --output-dir=%OUTPUT_DIR% ^
    --windows-console-mode=force ^
    --jobs=5 ^
    --product-name=%EXE_NAME% ^
    --file-version=1.0.0.0 ^
    --company-name=TuCompania ^
    --include-data-dir=static=static ^
    --include-data-dir=templates=templates ^
    --nofollow-import-to=numba ^
    --include-module=requests ^
    %MAIN_SCRIPT%

if %errorlevel% neq 0 (
    echo.
    echo -----------------------------------
    echo  Error durante la compilacion.
    echo -----------------------------------
    pause
    exit /b 1
)

echo.
echo -----------------------------------
echo  Compilacion completada.
echo  El ejecutable se encuentra en: %OUTPUT_DIR%\app.dist\
echo -----------------------------------

pause

