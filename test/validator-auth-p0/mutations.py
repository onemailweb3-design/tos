"""Require executable, discriminating failures from the specification oracles."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MUTANTS = [
 ('flags','reference.py',"require(get('u16') == 0, 'flags')","get('u16')"),
 ('tail','reference.py',"require(at == len(raw), 'trailing')","require(True, 'trailing')"),
 ('c0-phase','reference.py',"policy['phase'] == 0 and policy['suites']", "policy['phase'] in (0, 1) and policy['suites']"),
 ('exact-quorum','reference.py',"require(3*weight >= 2*total, 'quorum')","require(3*weight > 2*total, 'quorum')"),
 ('expected-context','reference.py',"require(duty == expected_duty, 'expected-context')","require(True, 'expected-context')"),
 ('crypto-result','reference.py',"require(verifier.verify(key, message, signature), 'signature')","require(True, 'signature')"),
 ('tree-canonical','reference.py',"require(node == byte_tree(raw), 'tree-canonical')","require(True, 'tree-canonical')"),
 ('terminal-journal','signer-store.sql',"WHEN OLD.state!='RESERVED' OR NEW.state NOT IN ('COMPLETE','BURNED')","WHEN 0"),
]

def execute(root):
    return subprocess.run([sys.executable,'-B',str(root/'test/validator-auth-p0/test_profile.py'),'-v'],
                          capture_output=True,text=True,timeout=90)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    report=[]
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        for name in ('test/validator-auth-p0','doc/validator-auth-p0'):
            shutil.copytree(ROOT/name,root/name,ignore=shutil.ignore_patterns('__pycache__'))
        baseline=execute(root)
        if baseline.returncode or not re.search(r'Ran [1-9][0-9]* tests',baseline.stderr):
            raise RuntimeError('positive baseline failed: '+baseline.stderr)
        for name,file,before,after in MUTANTS:
            path=root/('doc/validator-auth-p0' if file.endswith('.sql') else 'test/validator-auth-p0')/file
            original=path.read_text()
            if original.count(before)!=1:
                raise RuntimeError('nonunique mutation anchor: '+name)
            try:
                changed=original.replace(before,after)
                if path.suffix=='.py':compile(changed,str(path),'exec')
                path.write_text(changed)
                result=execute(root)
                if result.returncode!=1 or 'FAIL:' not in result.stderr or 'ERROR:' in result.stderr:
                    raise RuntimeError('survived, errored or crashed: '+name+'\n'+result.stderr)
                report.append(dict(guard=name,killed=True,parsed=True,returncode=result.returncode,
                                   failures=re.findall(r'^FAIL: (.*)$',result.stderr,re.MULTILINE),
                                   original_sha256=hashlib.sha256(original.encode()).hexdigest()))
            finally:
                path.write_text(original)
            restored=execute(root)
            if restored.returncode:
                raise RuntimeError('restored baseline failed: '+name)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS:',len(report),'specification mutations; not production-code mutations')

if __name__=='__main__':main()
