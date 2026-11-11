#!/usr/bin/env python3
"""Build the product image locally; never push or deploy it."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Local Docker image tag")
    args = parser.parse_args()
    build_tmp = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
    build_tmp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(build_tmp), GOTMPDIR=str(build_tmp))
    with tempfile.TemporaryDirectory(prefix="product-image-", dir=build_tmp) as directory:
        context = Path(directory)
        subprocess.run(["make", "--no-print-directory", "hub-binary", "HUB_BINARY=" + str(context / "asservat"), "ASSERVAT_BUILD_TMP=" + str(build_tmp)], cwd=ROOT, env=env, check=True)
        subprocess.run(["npm", "run", "build"], cwd=ROOT / "web", env=env, check=True)
        shutil.copytree(ROOT / "web/dist", context / "console")
        shutil.copyfile(ROOT / "packaging/Dockerfile", context / "Dockerfile")
        subprocess.run(["docker", "build", "--tag", args.tag, str(context)], cwd=ROOT, env=env, check=True)
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", args.tag], text=True))[0]
    print(json.dumps({"tag": args.tag, "localImageID": image["Id"], "platform": image["Os"] + "/" + image["Architecture"]}))


if __name__ == "__main__":
    main()
