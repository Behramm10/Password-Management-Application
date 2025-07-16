@echo off
cd /d "C:\Users\behramm.umrigar\Downloads\password_manager"
uvicorn main:app --host 0.0.0.0 --port 8000
