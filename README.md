# Running the Automation Scripts and Live Platform

> **Note:** Run all commands in **PowerShell**.

## 1. Run the Automation Scripts

Navigate to the Downloads folder:

```powershell
cd C:\Users\A102350\Downloads
```

Run the Node-RED reset script:

```powershell
powershell -ExecutionPolicy Bypass -File ".\reset_all_ieds_nodered.ps1"
```

Run the SV/GOOSE Publisher reset script:

```powershell
powershell -ExecutionPolicy Bypass -File ".\reset_all_pis_svgoosepublisher.ps1"
```

---

## 2. Start the Live Platform

Activate the Python virtual environment:

```powershell
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& C:\Users\A102350\Desktop\ITP_ML_transfer_20260722_111742\ITP_ML\.venv\Scripts\Activate.ps1)
```

When prompted, press **`Y`** to continue.

Navigate to the project directory:

```powershell
cd C:\Users\A102350\Desktop\ITP_ML_transfer_20260722_111742\ITP_ML
```

Start the Live Platform:

```powershell
python -m uvicorn live_platform.app:app --host 127.0.0.1 --port 8000
```

The application will be available at:

- http://127.0.0.1:8000
