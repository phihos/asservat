#!/usr/bin/env python3
"""Owned pinned S3-only history capability qualification, never a collector."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("custody_fixture",ROOT/"scripts/test-custody.py")
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
TEST="TestHistoryCiphertextStorageCapabilityWithRealS3"
SEAWEED="chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"

def hashes():
    values=fixture.hashes()
    values[str(Path(__file__).relative_to(ROOT))]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return values

def main(name):
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in name):
        raise ValueError("closed result name required")
    out=ROOT/"test/results"/name
    if out.exists(): raise ValueError("result directory already exists")
    out.mkdir(parents=True)
    cache=Path.home()/".cache/asservat-build"
    cache.mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    report={"scope":"bundled SeaweedFS with compiled regional S3 permissions, synthetic ciphertexts, TLS bridge, multipart delivery, exact-prefix cleanup and cross-region denials","requestedImage":SEAWEED,"sourceBefore":hashes(),"cleanupFailures":[],"selectedTest":TEST,"testExit":1}
    code=1
    with tempfile.TemporaryDirectory(prefix="history-storage-",dir=cache) as directory:
        work=Path(directory);network="asservat-"+work.name;container=network+"-s3"
        made_network=made_container=False
        try:
            env=os.environ.copy()
            env["TMPDIR"]=str(work)
            subprocess.run(["go","test","-count=1","-run","^TestPrepareRegionalStorageFixture$","./test/integration"],cwd=ROOT,env={**env,"ASSERVAT_REGIONAL_STORAGE_FIXTURE_DIR":str(work)},check=True,timeout=240)
            config_path=work/"s3.json"
            fixture.run(["docker","network","create","--internal","--label","asservat.test="+work.name,network]);made_network=True
            fixture.run(["docker","create","--name",container,"--network",network,"--label","asservat.test="+work.name,"--user","1000:1000","--read-only","--memory","768m","--cpus","2","--pids-limit","512","--tmpfs","/tmp:rw,nosuid,nodev,size=64m","-v","/data","-v",str(config_path)+":/config/s3.json:ro","--entrypoint","/usr/bin/weed",SEAWEED,"server","-dir=/data","-ip=127.0.0.1","-ip.bind=127.0.0.1","-master.volumeSizeLimitMB=16","-volume.max=2","-filer=true","-s3=true","-s3.ip.bind=0.0.0.0","-s3.iam=false","-iam=false","-s3.autoCreateBucket=false","-master.telemetry=false","-s3.port.iceberg=0","-s3.port.lance=0","-s3.port=8333","-s3.config=/config/s3.json"]);made_container=True
            fixture.run(["docker","start",container])
            inspection=json.loads(fixture.run(["docker","inspect",container]))[0]
            report["imageID"]=inspection["Image"]
            ip=inspection["NetworkSettings"]["Networks"][network]["IPAddress"]
            endpoint="http://"+ip+":8333"
            for _ in range(80):
                try:
                    urllib.request.urlopen(endpoint,timeout=1).close();break
                except urllib.error.HTTPError as exc:
                    if exc.code in (403,404): break
                except OSError: pass
                time.sleep(.25)
            else: raise RuntimeError("owned S3 readiness failed")
            descriptor=work/"fixture.json"
            data=json.loads(descriptor.read_text())
            data["S3"]=endpoint
            descriptor.write_text(json.dumps(data))
            env["ASSERVAT_HISTORY_STORAGE_FIXTURE"]=str(descriptor)
            env["GOMAXPROCS"]="2";env["GOFLAGS"]="-p=2";env["TMPDIR"]=str(work)
            with (out/"test.log").open("w") as log:
                result=subprocess.run(["go","test","-race","-count=1","-timeout=180s","-v","-run","^"+TEST+"$","./test/integration"],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
            report["testExit"]=result.returncode
            names=fixture.passed_test_names((out/"test.log").read_text(),"^"+TEST+"$")
            report["passedTests"]=names
            code=0 if result.returncode==0 and TEST in names else 1
        except BaseException as exc:
            report["failureType"]=type(exc).__name__
            raise
        finally:
            if made_container:
                try:
                    log=subprocess.run(["docker","logs",container],capture_output=True,text=True,timeout=15)
                    (out/"provider.log").write_text(log.stdout+log.stderr)
                except BaseException as exc:
                    report["cleanupFailures"].append("provider diagnostic failed: "+type(exc).__name__)
                try:
                    cleanup=subprocess.run(["docker","rm","-f","-v",container],capture_output=True,text=True,timeout=30)
                    if cleanup.returncode: report["cleanupFailures"].append("owned container removal failed")
                    if subprocess.run(["docker","inspect",container],capture_output=True,timeout=10).returncode==0: report["cleanupFailures"].append("owned container remains")
                except BaseException as exc:
                    report["cleanupFailures"].append("owned container cleanup failed: "+type(exc).__name__)
            if made_network:
                try:
                    cleanup=subprocess.run(["docker","network","rm",network],capture_output=True,text=True,timeout=15)
                    if cleanup.returncode: report["cleanupFailures"].append("owned network removal failed")
                except BaseException as exc:
                    report["cleanupFailures"].append("owned network cleanup failed: "+type(exc).__name__)
            report["sourceAfter"]=hashes()
            report["sourceUnchangedDuringTest"]=report["sourceBefore"]==report["sourceAfter"]
            report["elapsedSeconds"]=time.monotonic()-started
            if report["cleanupFailures"] or not report["sourceUnchangedDuringTest"]:code=1
            report["exit"]=code
            (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"result":str(out/"result.json"),"exit":code,"elapsedSeconds":report["elapsedSeconds"],"cleanupFailures":report["cleanupFailures"]}),flush=True)
    return code
if __name__=="__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv)==2 else "history-storage-native-1"))
