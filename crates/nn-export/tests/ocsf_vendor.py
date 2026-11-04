#!/usr/bin/env python3
"""Lot 276: vendor the OCSF schema the exporter pins (crates/nn-export/ocsf/ocsf-1.9.0.json;
docs/operator/EXPORT.md §1). A maintainer's tool, in no shipped build (CodeQL's
paths-ignore holds this directory).

Run with the downloads of the OCSF server in a directory of their own:
  <dir>/<class>.host.schema.json   https://schema.ocsf.io/schema/1.9.0/classes/<class>?profiles=host
  <dir>/api/class-<class>.json     https://schema.ocsf.io/api/1.9.0/classes/<class>?profiles=host
  <dir>/api/object-<object>.json   https://schema.ocsf.io/api/1.9.0/objects/<object>?profiles=host
  <dir>/api/categories.json        https://schema.ocsf.io/api/1.9.0/categories
  python3 -I crates/nn-export/tests/ocsf_vendor.py <dir> > crates/nn-export/ocsf/ocsf-1.9.0.json
It keeps the JSON Schema of each class (titles and descriptions dropped), the
union of their definitions (refused when two differ), the captions of the
enumerations the exporter writes, and the SHA-256 of every file it read.
"""
import hashlib, json, os, sys

VERSION = "1.9.0"
CLASSES = ["base_event", "detection_finding", "process_activity", "file_activity", "network_activity",
           "remediation_activity", "file_remediation_activity",
           "process_remediation_activity", "network_remediation_activity"]
CLASS_ENUMS = ["activity_id", "status_id", "severity_id", "confidence_id"]
OBJECT_ENUMS = {"device": ["type_id"], "file": ["type_id"], "analytic": ["type_id"],
                "fingerprint": ["algorithm_id"],
                "network_connection_info": ["direction_id", "protocol_ver_id"]}

def strip(o, names=False):
    """Drop the annotations `title` and `description` of every schema; the
    keys of a `properties` (or `$defs`) map are names, kept whatever they
    are (OCSF has attributes named `title` and `desc`)."""
    if isinstance(o, dict):
        if names:
            return {k: strip(v) for k, v in sorted(o.items())}
        return {k: strip(v, names=k in ("properties", "$defs")) for k, v in sorted(o.items())
                if k not in ("title", "description")}
    if isinstance(o, list):
        return [strip(v) for v in o]
    return o

def load(path, digests, root):
    raw = open(path, "rb").read()
    digests[os.path.relpath(path, root)] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw)

def captions(attr):
    return {k: v.get("caption") for k, v in sorted(attr["enum"].items(), key=lambda t: int(t[0]))}

def main(root):
    digests, defs, classes, objects = {}, {}, {}, {}
    for c in CLASSES:
        s = load(os.path.join(root, f"{c}.host.schema.json"), digests, root)
        a = load(os.path.join(root, "api", f"class-{c}.json"), digests, root)
        for k, v in s["$defs"].items():
            v = strip(v)
            if k in defs and defs[k] != v:
                sys.exit(f"$defs/{k} differs between classes")
            defs[k] = v
        body = strip({k: v for k, v in s.items() if k not in ("$defs", "$id", "$schema")})
        enums = {k: captions(a["attributes"][k]) for k in CLASS_ENUMS
                 if k in a["attributes"] and "enum" in a["attributes"][k]}
        classes[c] = {"uid": a["uid"], "caption": a["caption"],
                      "category_uid": body["properties"]["category_uid"]["const"],
                      "schema": body, "enums": enums}
    for o, keys in OBJECT_ENUMS.items():
        a = load(os.path.join(root, "api", f"object-{o}.json"), digests, root)
        for k in keys:
            objects[f"{o}.{k}"] = captions(a["attributes"][k])
    cats = load(os.path.join(root, "api", "categories.json"), digests, root)
    cats = cats.get("attributes", cats)
    categories = {str(v["uid"]): v["caption"] for v in sorted(cats.values(), key=lambda v: v["uid"])}
    categories.setdefault("0", "Uncategorized")
    out = {
        "ocsf_version": VERSION,
        "profiles": ["host"],
        "source": {
            "schema": f"https://schema.ocsf.io/schema/{VERSION}/classes/<class>?profiles=host",
            "captions": f"https://schema.ocsf.io/api/{VERSION}/(classes|objects)/<name>?profiles=host",
            "fetched": "2026-11-03",
            "sha256": dict(sorted(digests.items())),
        },
        "categories": categories,
        "classes": classes,
        "object_enums": objects,
        "$defs": dict(sorted(defs.items())),
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")

if __name__ == "__main__":
    main(sys.argv[1])
