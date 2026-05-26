import json


def json_for_script(data, *, separators=None):
    rendered = json.dumps(data, ensure_ascii=False, separators=separators)
    return (
        rendered
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
