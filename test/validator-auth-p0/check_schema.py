"""Check proposed allocations and compile native TL; not a native TL-B/BOC test."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zlib
import contract_artifacts

ROOT=Path(__file__).resolve().parents[2]
DOC=ROOT/'doc/validator-auth-p0'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tl-parser',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();parser=args.tl_parser.resolve()
    contract_artifacts.main()
    profile=json.loads((DOC/'profile.json').read_text());schema=(DOC/'wire.tl').read_text()
    declarations=re.findall(r'^(validatorAuth\.\w+)#([0-9a-f]{8}) (.*?) = (.*?);$',schema,re.MULTILINE)
    if len(declarations)!=6:raise ValueError('six constructors required')
    seen=set()
    for name,tag,fields,result in declarations:
        if int(tag,16)!=zlib.crc32(f'{name} {fields} = {result}'.encode()):
            raise ValueError('constructor CRC drift: '+name)
        if tag in seen:raise ValueError('duplicate proposed ID')
        seen.add(tag)
    if seen!=set(profile['tl_constructors'].values()):raise ValueError('manifest/schema drift')
    block=(ROOT/'crypto/block/block.tlb').read_text()
    if re.search(r'ConfigParam\s+46\b',block):raise ValueError('proposed Config46 now occupied; review allocation')
    types=(ROOT/'tos/tos-types.h').read_text()
    enum=re.search(r'enum GlobalCapabilities\s*\{(.*?)\}',types,re.DOTALL)
    if not enum:raise ValueError('cannot inspect capability inventory')
    values=[int(v) for v in re.findall(r'=\s*(\d+)\s*[,\n]',enum.group(1)+'\n')]
    if 1024 in values:raise ValueError('proposed capability now occupied; review allocation')
    checks=[]
    with tempfile.TemporaryDirectory() as directory:
        d=Path(directory)
        for base in ('tos_api','lite_api'):
            combined=(ROOT/f'tl/generate/scheme/{base}.tl').read_text()+'\n---types---\n'+schema
            source=d/(base+'.tl');out=d/(base+'.tlo');source.write_text(combined)
            result=subprocess.run([str(parser),'-e',str(out),str(source)],capture_output=True,text=True,timeout=30)
            if result.returncode or not out.exists() or not out.stat().st_size:
                raise ValueError('native TL failed: '+base+'\n'+result.stderr)
            checks.append(base+'-combined-schema')
        source=d/'invalid.tl';source.write_text(combined+'\nvalidatorAuth.invalidV1 data:NeverDeclared = validatorAuth.Invalid;\n')
        bad=subprocess.run([str(parser),'-e',str(d/'bad.tlo'),str(source)],capture_output=True,text=True,timeout=30)
        if bad.returncode==0:raise ValueError('native parser negative control accepted an undefined type')
        checks.append('native-undefined-type-rejected')
    hashes={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
            for directory in (DOC,ROOT/'test/validator-auth-p0') for f in sorted(directory.iterdir()) if f.is_file()}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(dict(success=True,checks=checks,source_sha256=hashes,
                                      scope='allocation and native TL only; no native TL-B/BOC or activation'),indent=2,sort_keys=True)+'\n')
    print('PASS:',', '.join(checks))

if __name__=='__main__':main()
