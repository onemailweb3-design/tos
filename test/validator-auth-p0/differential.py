"""Execute separately implemented C++ and Rust binary codecs against frozen bytes."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import reference as r

HERE=Path(__file__).resolve().parent

def main(out):
    with tempfile.TemporaryDirectory() as directory:
        work=Path(directory)
        schema=work/'schema.txt'
        schema.write_text('\n'.join(n+'|'+(d['tag'] or '-')+'|'+','.join(t for _,t in d['fields']) for n,d in r.SCHEMA['types'].items())+'\n')
        subprocess.run(['c++','-std=c++17','-O2',str(HERE/'codec.cpp'),'-o',str(work/'cpp')],check=True)
        subprocess.run(['rustc','-O',str(HERE/'codec.rs'),'-o',str(work/'rust')],check=True)
        golden=json.loads((HERE/'lifecycle-api-golden.json').read_text())
        positives=negatives=0
        for name,hexed in golden['objects'].items():
            raw=bytes.fromhex(hexed);(work/'input').write_bytes(raw)
            for language in ('cpp','rust'):
                subprocess.run([str(work/language),str(schema),name,str(work/'input'),str(work/'out')],check=True)
                if (work/'out').read_bytes()!=raw:raise ValueError('codec disagreement: '+name)
            positives+=1
            for bad in (raw+b'\0',raw[:-1]):
                if bad==raw:continue
                (work/'input').write_bytes(bad)
                for language in ('cpp','rust'):
                    result=subprocess.run([str(work/language),str(schema),name,str(work/'input'),str(work/'out')],capture_output=True)
                    if result.returncode!=1:raise ValueError('negative accepted/crashed: '+name)
                negatives+=1
        for bad in golden['negatives']:
            (work/'input').write_bytes(bytes.fromhex(bad['hex']))
            for language in ('cpp','rust'):
                result=subprocess.run([str(work/language),str(schema),bad['kind'],str(work/'input'),str(work/'out')],capture_output=True)
                if result.returncode!=1:raise ValueError('frozen negative accepted')
            negatives+=1
        # Disable each independent decoder's flags check after proving its baseline refusal.
        bad=bytearray.fromhex(golden['objects']['key']);bad[7]=1
        (work/'input').write_bytes(bad)
        replacements=[('cpp','codec.cpp','require(read(2)==0);','read(2);'),
                      ('rust','codec.rs','if self.read(2)?!=0{return Err("flags".into());}','self.read(2)?;')]
        for language,filename,before,after in replacements:
            original=(HERE/filename).read_text()
            if original.count(before)!=1:raise ValueError('mutation anchor')
            source=work/filename;source.write_text(original.replace(before,after))
            command=['c++','-std=c++17','-O2'] if language=='cpp' else ['rustc','-O']
            subprocess.run(command+[str(source),'-o',str(work/'mutant')],check=True)
            args=[str(schema),'key',str(work/'input'),str(work/'out')]
            if subprocess.run([str(work/language),*args],capture_output=True).returncode!=1:
                raise ValueError('baseline flags guard did not reject')
            if subprocess.run([str(work/'mutant'),*args],capture_output=True).returncode!=0:
                raise ValueError('disabled guard not observed by negative input')
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(dict(success=True,types=positives,negative_inputs=negatives,compiled_guard_mutations=2,languages=['C++','Rust'],scope='binary field decoding/encoding; semantic/crypto checks are separate'),indent=2)+'\n')
    print('PASS: independent C++/Rust codecs',positives,'types',negatives,'negative inputs')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);main(p.parse_args().out)
