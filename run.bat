@echo off
chcp 65001 >nul
title Inkvizitor - ShashevPro
python main.py
if errorlevel 1 pause
