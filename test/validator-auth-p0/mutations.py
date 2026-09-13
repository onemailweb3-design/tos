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
 ('due-boundary','lifecycle.py',"p['effective_from'] <= coordinate", "p['effective_from'] < coordinate"),
 ('pending-conflict','lifecycle.py',"r.require(target_slot not in pending, 'pending-conflict')", "r.require(True, 'pending-conflict')"),
 ('accepted-nonce','lifecycle.py',"current['next_nonce'] <= update['nonce'] < MAX_NONCE", "update['nonce'] < MAX_NONCE"),
 ('accepted-predecessor','lifecycle.py',"update['previous'] == r.object_id('identity', current)", "True"),
 ('cancel-target','lifecycle.py',"if r.object_id('transition', p) == update['operation_data']", "if True"),
 ('old-session-copy','lifecycle.py',"selected.append(deepcopy(key))", "selected.append(key)"),
 ('authority-verified','lifecycle.py',"kind in verifiers and verifiers[kind](proof, update, state)", "True"),
 ('json-duplicate','api.py',"r.require(k not in result, 'duplicate-json-key')", "r.require(True, 'duplicate-json-key')"),
 ('response-id','api.py',"r.require(rid == expected_id, 'response-correlation')", "r.require(True, 'response-correlation')"),
 ('cursor-snapshot','api.py',"cursor['anchor'] == req['anchor'] and cursor['query_id']", "cursor['query_id']"),
 ('receipt-result','api.py',"all(body[n] == value for n, value in expected.items()), 'receipt-binding'", "True, 'receipt-binding'"),
 ('proof-authentication','api.py',"r.require(verifier(proof), 'proof-authentication')", "r.require(True, 'proof-authentication')"),
 ('permit-expiry','api.py',"current_mc is not None and body['anchor']['seqno'] <= current_mc <= body['expires_mc']", "True"),
 ('absent-state','api.py',"state['statement_id'] == ZERO and state['fence'] == 0 and not state['result'] and not state['receipt']", "True"),

 ('c0-result-size','api.py',"all(len(x['signature']) == 64 for x in result['record']['components']\n                      if (x['suite'], x['parameters']) == (1, 1))", "True"),
 ('verified-signer-order','api.py',"bool(signers) and signers == sorted(set(signers)) and ZERO not in signers", "True"),
 ('verify-request-context','api.py',"proof['anchor'] == req['anchor'] and proof['kind'] == kind\n                      and proof['object_id'] == cert['duty'][name]", "True"),
 ('terminal-polling','api.py',"r.require(previous == current, 'terminal-state-regression')", "r.require(True, 'terminal-state-regression')"),

]

TARGETS = {
 'c0-result-size': 'test_api_guards.ApiGuardTests.test_c0_sign_result_requires_exact_signature_size',
 'verified-signer-order': 'test_api_guards.ApiGuardTests.test_verified_summary_rejects_noncanonical_signers',
 'verify-request-context': 'test_api_guards.ApiGuardTests.test_verification_request_pins_both_context_proofs',
 'terminal-polling': 'test_api_guards.ApiGuardTests.test_polling_preserves_terminal_state_and_exact_result',

 'due-boundary': 'LifecycleTests.test_before_exact_after_replay_and_old_session',
 'pending-conflict': 'LifecycleTests.test_explicit_cancel_and_conflict_no_silent_replace',
 'accepted-nonce': 'LifecycleTests.test_nonce_predecessor_boundaries_and_atomic_refusal',
 'accepted-predecessor': 'LifecycleTests.test_nonce_predecessor_boundaries_and_atomic_refusal',
 'cancel-target': 'LifecycleTests.test_explicit_cancel_and_conflict_no_silent_replace',
 'old-session-copy': 'LifecycleTests.test_before_exact_after_replay_and_old_session',
 'authority-verified': 'LifecycleTests.test_four_authorities_cannot_substitute',
 'json-duplicate': 'ApiTests.test_strict_json_duplicate_keys_before_mapping',
 'response-id': 'ApiTests.test_endpoint_inventory_and_transport_responses',
 'cursor-snapshot': 'ApiTests.test_cursor_snapshot_and_page_correlation',
 'receipt-result': 'ApiTests.test_complete_receipt_binds_exact_result_and_permit_expiry',
 'proof-authentication': 'ApiTests.test_proof_reference_needs_authenticated_source',
 'permit-expiry': 'ApiTests.test_complete_receipt_binds_exact_result_and_permit_expiry',
 'absent-state': 'ApiTests.test_request_state_variants',
}

def execute(root, target=None):
    qualified = target if target and target.startswith('test_api_guards.') else 'test_lifecycle_api.' + (target or '')
    arguments = [qualified, '-v'] if target else ['discover', '-p', 'test_*.py', '-v']
    return subprocess.run([sys.executable,'-B','-m','unittest',*arguments],
                          cwd=root/'test/validator-auth-p0',capture_output=True,text=True,timeout=90)

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
                result=execute(root, TARGETS.get(name))
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
