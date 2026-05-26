from importlib import import_module
from pkgutil import iter_modules


for module_info in iter_modules(__path__):
    if not module_info.ispkg:
        import_module(f"{__name__}.{module_info.name}")
