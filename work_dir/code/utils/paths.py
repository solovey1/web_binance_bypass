from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent

WORK_DIR = SCRIPT_DIR.parent

BASE_DIR = SCRIPT_DIR

LOGS_DIR = WORK_DIR / "logs"

for dirpath in (LOGS_DIR,):
    dirpath.mkdir(parents=True, exist_ok=True)
