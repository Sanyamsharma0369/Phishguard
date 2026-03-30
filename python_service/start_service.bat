@echo off
echo === PhishGuard CNN Visual Analyzer ===
echo.
cd /d "%~dp0"
echo Installing/checking requirements...
pip install -r requirements.txt --quiet
echo.
echo Checking for trained model...
if not exist "models\brand_cnn.h5" (
    echo Model not found. Training now (takes 3-10 minutes)...
    python train_cnn.py
    echo.
)
echo Starting Flask service on port 5000...
python app.py
pause
