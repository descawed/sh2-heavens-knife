@echo off

rem Set our working directory to the directory containing this batch file.
cd /d "%~dp0"

if not exist sh2pc.exe (
    echo This batch file doesn't appear to be located in the Silent Hill 2 folder.
    echo Please move it to the Silent Hill 2 folder before running it.
    pause
    exit /b
)

echo                 ======================================
echo                 =     Heaven's Knife uninstaller     =
echo                 ======================================
echo.
echo If you have any saves using the mod that you want to keep, then before
echo uninstalling, make sure you unequip any weapons that belong to the other
echo character. The game will crash if you equip a weapon belonging to the other
echo character without the mod active. After uninstalling, any items from the other
echo character that are still in your inventory will have missing or glitched icons.
echo This should be harmless as long as you don't try to equip any of these items.
echo.

set /p ays=Type Y and press enter to confirm uninstallation:
if /i "%ays%" neq "y" (
    echo Uninstallation cancelled.
    pause
    exit /b
)

echo Uninstalling...

set errors=n

rem Delete all mod files without prompting.
rem I settled on doing it this way because I didn't want an error message if a file we're trying to delete is already
rem gone, but I did want error messages to be visible if the file fails to delete for some reason.
if exist knife.asi (
    del /q /f knife.asi
    rem Apparently del doesn't set errorlevel, so we'll check for errors by seeing if the file still exists after we try
    rem to delete it.
    if exist knife.asi set errors=y
)
if exist knife.toml (
    del /q /f knife.toml
    if exist knife.toml set errors=y
)
if exist knife.log (
    del /q /f knife.log
    if exist knife.log set errors=y
)
if exist readme_knife.txt (
    del /q /f readme_knife.txt
    if exist readme_knife.txt set errors=y
)
if exist sh2e\pic\etc\itemmenu3.tex (
    del /q /f sh2e\pic\etc\itemmenu3.tex
    if exist sh2e\pic\etc\itemmenu3.tex set errors=y
)
if exist sh2e\chr\wp\jms_weapon.anm (
    del /q /f sh2e\chr\wp\jms_weapon.anm
    if exist sh2e\chr\wp\jms_weapon.anm set errors=y
)
if exist data\chr\jms\jms_wpcolt.anm (
    del /q /f data\chr\jms\jms_wpcolt.anm
    if exist data\chr\jms\jms_wpcolt.anm set errors=y
)
if exist data\chr\jms\jms_wpknif.anm (
    del /q /f data\chr\jms\jms_wpknif.anm
    if exist data\chr\jms\jms_wpknif.anm set errors=y
)
if exist data\chr2\mar\xmar_wpcsaw.anm (
    del /q /f data\chr2\mar\xmar_wpcsaw.anm
    if exist data\chr2\mar\xmar_wpcsaw.anm set errors=y
)
if exist data\chr2\mar\xmar_wphand.anm (
    del /q /f data\chr2\mar\xmar_wphand.anm
    if exist data\chr2\mar\xmar_wphand.anm set errors=y
)
if exist data\chr2\mar\xmar_wpkaku.anm (
    del /q /f data\chr2\mar\xmar_wpkaku.anm
    if exist data\chr2\mar\xmar_wpkaku.anm set errors=y
)
if exist data\chr2\mar\xmar_wpnata.anm (
    del /q /f data\chr2\mar\xmar_wpnata.anm
    if exist data\chr2\mar\xmar_wpnata.anm set errors=y
)
if exist data\chr2\mar\xmar_wppipe.anm (
    del /q /f data\chr2\mar\xmar_wppipe.anm
    if exist data\chr2\mar\xmar_wppipe.anm set errors=y
)
if exist data\chr2\mar\xmar_wprifl.anm (
    del /q /f data\chr2\mar\xmar_wprifl.anm
    if exist data\chr2\mar\xmar_wprifl.anm set errors=y
)
if exist data\chr2\mar\xmar_wpshot.anm (
    del /q /f data\chr2\mar\xmar_wpshot.anm
    if exist data\chr2\mar\xmar_wpshot.anm set errors=y
)
if exist data\chr2\mar\xmar_wpsp.anm (
    del /q /f data\chr2\mar\xmar_wpsp.anm
    if exist data\chr2\mar\xmar_wpsp.anm set errors=y
)

rem Delete this batch file itself, but only if we didn't encounter any errors
if "%errors%"=="n" (
    echo Uninstallation complete.
    pause

    rem https://stackoverflow.com/questions/20329355/how-to-make-a-batch-file-delete-itself
    start /b "" cmd /c del "%~f0" & exit /b
) else (
    echo The uninstallation process has finished, but one or more errors were
    echo encountered. You may need to delete the remaining files manually.
    pause
)