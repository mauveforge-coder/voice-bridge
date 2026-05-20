@echo off
REM VoiceBridge バックグラウンド起動スクリプト
REM pythonw を使用してコンソールウィンドウなしで起動する

cd /d "%~dp0"
start "" pythonw server.py
