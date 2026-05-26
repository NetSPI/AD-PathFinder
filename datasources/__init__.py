from pathlib import Path
from importlib import import_module

for f in Path(__file__).parent.glob('*.py'):
    if f.name != '__init__.py':
        import_module(f'.{f.stem}', __package__)
