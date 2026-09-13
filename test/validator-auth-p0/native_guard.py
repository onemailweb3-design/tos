"""Disable the generated native leaf lower bound and require the negative test to fail."""
import argparse,json,subprocess
from pathlib import Path

def main(build,out):
    build=build.resolve();source=build/'p0-combined.tlb';original=source.read_text()
    before='auth_byte_leaf$0 n:(## 7) { n >= 1 }'
    if original.count(before)!=1:raise ValueError('native mutation anchor')
    def compile_and_run(text):
        source.write_text(text)
        for suffix in ('.cpp','.h'):(build/('p0-native'+suffix)).unlink(missing_ok=True)
        subprocess.run(['cmake','--build',str(build),'--target','test-p0-native','-j2'],check=True)
        return subprocess.run([str(build/'test-p0-native')],capture_output=True,text=True)
    try:
        mutant=compile_and_run(original.replace(before,'auth_byte_leaf$0 n:(## 7) { n >= 0 }'))
        if mutant.returncode!=1 or 'native profile check failed' not in mutant.stderr:
            raise ValueError('native negative control failed to distinguish removed leaf bound')
    finally:
        baseline=compile_and_run(original)
        if baseline.returncode or 'PASS native TL-B/BOC' not in baseline.stdout:
            raise ValueError('restored native baseline failed')
    out.write_text(json.dumps(dict(guard='native-leaf-minimum',compiled=True,killed=True,restored=True),indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',required=True,type=Path);p.add_argument('--out',required=True,type=Path)
    a=p.parse_args();main(a.build,a.out)
