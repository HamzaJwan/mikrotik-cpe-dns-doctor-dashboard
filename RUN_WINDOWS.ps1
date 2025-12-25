# RUN_WINDOWS.ps1
# Requires: Python 3.12
if (!(Test-Path ".\venv312\Scripts\activate")) {
  py -3.12 -m venv venv312
}
.\venv312\Scripts\activate
python --version
pip install -r requirements.txt
python -m uvicorn web.api:app --host 127.0.0.1 --port 8000 --reload
