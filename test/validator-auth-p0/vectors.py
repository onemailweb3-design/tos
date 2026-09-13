"""Explicit generation of public C0 fixtures. Tests never rewrite frozen vectors."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import reference as r

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT/'doc/validator-auth-p0'

def h(n):
    return bytes([n])*32

def sign(seed, message):
    with tempfile.TemporaryDirectory() as directory:
        d = Path(directory)
        (d/'key').write_bytes(bytes.fromhex('302e020100300506032b657004220420')+seed)
        (d/'message').write_bytes(message)
        pub = subprocess.run(['openssl','pkey','-inform','DER','-in',str(d/'key'),'-pubout','-outform','DER'],
                             check=True, capture_output=True, timeout=15).stdout
        if len(pub) != 44 or pub[:12].hex() != '302a300506032b6570032100':
            raise RuntimeError('unexpected Ed25519 SPKI')
        signature = subprocess.run(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(d/'key'),
                                    '-in',str(d/'message')], check=True, capture_output=True, timeout=15).stdout
        if len(signature) != 64:
            raise RuntimeError('unexpected signature length')
        return pub[12:], signature

def build():
    policy = dict(revision=1, previous=bytes(32), interface_digest=hashlib.sha256((DOC/'profile.json').read_bytes()).digest(),
                  effective_from=0, phase=0, suites=[dict(suite=1,parameters=1)], max_envelope=4096, max_certificate=524288)
    roster = []
    for i in range(3):
        public, _ = sign(h(i+1), b'public fixture')
        keys = [dict(identity=h(11+i),role=role,suite=1,parameters=1,epoch=1,valid_from=0,valid_until=1000,
                     public_key=public,capacity_domain=bytes(32),capacity_limit=0) for role in range(1,6)]
        roster.append(dict(identity=h(11+i),stake_id=h(21+i),weight=1,adnl_id=h(31+i),keys=keys))
    committee = dict(policy=r.object_id('policy',policy),election=h(41),workchain=-1,shard=1<<63,catchain=7,anchor_mc=100,members=roster)
    session = r.digest('session',struct.pack('>i',42)+h(51)+h(52)+r.object_id('committee',committee)+h(53)+bytes(8))
    candidate = r.CANDIDATE+struct.pack('<I',8)+h(61)
    intent = dict(operation=3,identity=h(11),nonce=8,previous=h(62),effective_from=200,
                  old_key=r.object_id('key',roster[0]['keys'][0]),new_key=b'',new_policy=b'',operation_data=b'')
    payloads = {1:candidate,2:r.VOTE[2]+candidate,3:r.VOTE[3]+candidate,4:r.SKIP+struct.pack('<I',8),5:r.encode('update',intent)}
    cases = []
    for role, payload in payloads.items():
        duty = dict(network=42,genesis_root=h(51),genesis_file=h(52),policy=r.object_id('policy',policy),
                    committee=r.object_id('committee',committee),session=session,workchain=-1,shard=1<<63,
                    anchor_mc=100,catchain=7,position=8,role=role,payload_hash=r.digest('payload',bytes([role])+payload))
        if role == 5:
            duty['session'] = r.digest('admin-session',struct.pack('>i',42)+h(51)+h(52)+h(11))
        records = []
        for i, member in enumerate(roster):
            key = member['keys'][role-1]
            row = dict(identity=member['identity'],components=[{**r.keyref(key),'signature':b''}])
            _, sig = sign(h(i+1),r.statement(duty,row))
            row['components'][0]['signature'] = sig
            records.append(row)
        cert = dict(duty=duty,payload=payload,records=records)
        env = dict(duty=duty,payload=payload,record=records[0])
        cases.append(dict(role=role,certificate=r.encode('certificate',cert).hex(),
                          envelope=r.encode('envelope',env).hex(),statement=r.statement(duty,records[0]).hex()))
    return dict(scope='Public C0 fixtures; admin case is cryptographic only, not ownership/apply evidence',
                public_seeds=[h(i+1).hex() for i in range(3)], policy=r.encode('policy',policy).hex(),
                committee=r.encode('committee',committee).hex(), cases=cases)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--write', type=Path, required=True)
    args = p.parse_args()
    args.write.write_text(json.dumps(build(),indent=2)+'\n')
