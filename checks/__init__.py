import importlib
from pathlib import Path

IMPORT_ERRORS = []

checks_dir = Path(__file__).parent
for file in checks_dir.glob("*.py"):
    if file.name in ("__init__.py", "EXAMPLE_TEMPLATES.py"):
        continue
    module_name = file.stem
    try:
        importlib.import_module(f"checks.{module_name}")
    except Exception as e:
        IMPORT_ERRORS.append({
            "module": module_name,
            "error_type": type(e).__name__,
            "message": str(e),
        })
        print(f"Warning: Could not import check {module_name}: {type(e).__name__}: {e}")
