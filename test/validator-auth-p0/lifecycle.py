"""Authenticated lifecycle apply oracle, separate from certificate verification.

The caller supplies an authenticated state/coordinate and four trusted evidence
verifiers. This model does not implement elector contracts or native Merkle proofs.
"""
from copy import deepcopy
import reference as r

ZERO = bytes(32)
MAX_COORDINATE = (1 << 32) - 1
MAX_NONCE = (1 << 64) - 1
MAX_DELAY = 65536


def slot(key):
    return tuple(key[n] for n in ('role', 'suite', 'parameters'))


def ref_slot(ref):
    return ref['role'], ref['key']['suite'], ref['key']['parameters']


def validate_state(state, archive):
    r.encode('identity', state)
    r.require(state['identity'] != ZERO and state['stake_id'] != ZERO, 'identity-allocation')
    for name, get_slot in (('active', ref_slot), ('pending', slot)):
        slots = [get_slot(x) for x in state[name]]
        r.require(slots == sorted(set(slots)) and len(slots) <= 10, 'state-order')
        r.require(all(1 <= x[0] <= 5 and x[1] > 0 and x[2] > 0 for x in slots), 'state-slot')
    all_slots = set(ref_slot(x) for x in state['active']) | set(slot(x) for x in state['pending'])
    r.require(all(sum(x[0] == role for x in all_slots) <= 2 for role in range(1, 6)), 'role-component-bound')
    active = {ref_slot(x): x['key']['key_id'] for x in state['active']}
    for ref in state['active']:
        key = archive.get(ref['key']['key_id'])
        r.require(key is not None and r.keyref(key) == ref['key']
                  and key['identity'] == state['identity'] and key['role'] == ref['role'], 'archive-binding')
    for p in state['pending']:
        r.require(p['operation'] in (1, 2, 3), 'pending-operation')
        r.require(0 <= p['accepted_at'] < p['effective_from'] < MAX_COORDINATE
                  and p['effective_from'] - p['accepted_at'] <= MAX_DELAY, 'pending-coordinate')
        r.require(p['nonce'] < state['next_nonce'] and p['update_id'] != ZERO
                  and p['authorization_id'] != ZERO and p['predecessor'] != ZERO, 'pending-acceptance')
        r.require(active.get(slot(p), ZERO) == p['old_key'], 'pending-old')
        r.require((p['old_key'] == ZERO) == (p['operation'] == 1), 'pending-old')
        r.require((p['new_key'] == ZERO) == (p['operation'] == 3), 'pending-new')
        if p['new_key'] != ZERO:
            key = archive.get(p['new_key'])
            r.require(key is not None and r.object_id('key', key) == p['new_key']
                      and key['identity'] == state['identity'] and slot(key) == slot(p)
                      and key['valid_from'] == p['effective_from'] < key['valid_until'], 'pending-key')


def advance(state, archive, coordinate):
    """Materialize due records before block operations or snapshot construction.

    coordinate and monotonic replay position belong to the authenticated block,
    never an operator timer. Returns a new value; old session snapshots are owned.
    """
    r.require(0 <= coordinate < MAX_COORDINATE, 'coordinate')
    validate_state(state, archive)
    result = deepcopy(state)
    due = [p for p in result['pending'] if p['effective_from'] <= coordinate]
    if due:
        active = {ref_slot(x): x for x in result['active']}
        for p in sorted(due, key=lambda x: (x['effective_from'], slot(x))):
            active.pop(slot(p), None)
            if p['new_key'] != ZERO:
                active[slot(p)] = dict(role=p['role'], key=r.keyref(archive[p['new_key']]))
        result['active'] = [active[k] for k in sorted(active)]
        result['pending'] = [p for p in result['pending'] if p not in due]
        result['previous'] = r.object_id('identity', state)
    return result


def authenticate(update, evidence, state, verifiers, initial=False):
    """Each verifier authenticates its own typed source against current state.

    Owner/PoP/admin/governance are never interchangeable booleans supplied on wire.
    The callbacks are independent trusted integration boundaries, not peer plugins.
    """
    r.encode('authorizations', evidence)
    op = update['operation']; uid = r.object_id('update', update)
    required = {'owner': op in (1, 2), 'possession': op in (1, 2),
                'administration': not initial, 'governance': False}
    for kind, needed in required.items():
        rows = evidence[kind]
        r.require(len(rows) == int(needed), 'authority-shape')
        for proof in rows:
            r.require(proof['update_id'] == uid, 'authority-update')
            if kind == 'owner':
                r.require(all(proof[n] == state[n] for n in ('stake_id', 'owner_workchain', 'owner_address')), 'owner-binding')
            if kind == 'administration':
                r.require(proof['identity'] == state['identity'], 'admin-binding')
            if kind == 'possession':
                r.require(proof['key'] == r.keyref(r.decode('key', update['new_key'])), 'pop-binding')
            r.require(kind in verifiers and verifiers[kind](proof, update, state), 'authority-'+kind)


def apply(state, archive, update, evidence, inclusion, verifiers, admit_key):
    """Apply one identity operation after due materialization, atomically.

    Verifiers check current policy, owner, admin freshness (<=128), native proofs
    and signatures. Allocation/genesis and global governance use separate paths.
    """
    r.encode('update', update)
    current = advance(state, archive, inclusion)
    op = update['operation']
    r.require(op in (1, 2, 3, 7) and update['identity'] == current['identity'], 'operation-target')
    r.require(current['next_nonce'] <= update['nonce'] < MAX_NONCE, 'nonce')
    r.require(update['previous'] == r.object_id('identity', current), 'predecessor')
    r.require(update['new_policy'] == b'', 'unused-field')
    effective = inclusion if op in (3, 7) and update['effective_from'] == 0 else update['effective_from']
    r.require(inclusion <= effective < MAX_COORDINATE and effective - inclusion <= MAX_DELAY, 'effective-coordinate')
    result, keys = deepcopy(current), deepcopy(archive)
    active = {ref_slot(x): x['key']['key_id'] for x in current['active']}
    pending = {slot(x): x for x in current['pending']}
    if op == 7:
        r.require(update['effective_from'] == 0 and update['old_key'] == ZERO and update['new_key'] == b''
                  and len(update['operation_data']) == 32, 'cancel-shape')
        found = [p for p in current['pending'] if r.object_id('transition', p) == update['operation_data']]
        r.require(len(found) == 1, 'cancel-target')
        target = found[0]
        result['pending'].remove(target)
    else:
        r.require(update['operation_data'] == b'', 'unused-field')
        if op in (1, 2):
            key = r.decode('key', update['new_key']); target_slot = slot(key)
            r.require(key['identity'] == current['identity'] and 1 <= key['role'] <= 5, 'new-key-identity')
            r.require(key['valid_from'] == effective < key['valid_until'] <= MAX_COORDINATE, 'new-key-validity')
            epochs = [k['epoch'] for k in archive.values() if k['identity'] == key['identity'] and slot(k) == target_slot]
            r.require(0 < key['epoch'] < MAX_NONCE and key['epoch'] > max(epochs, default=0), 'epoch')
            r.require(admit_key(key), 'key-admission')
            new_id = r.object_id('key', key)
            r.require(new_id not in archive, 'key-history')
            keys[new_id] = key
        else:
            r.require(update['new_key'] == b'', 'unused-field')
            old = archive.get(update['old_key'])
            r.require(old is not None and old['identity'] == current['identity'], 'old-key')
            target_slot = slot(old); new_id = ZERO
        old_id = active.get(target_slot, ZERO)
        r.require(update['old_key'] == old_id and (old_id == ZERO) == (op == 1), 'old-key')
        r.require(target_slot not in pending, 'pending-conflict')
        r.require(len(pending) < 10 and (target_slot in active or len(active) + sum(p['operation'] == 1 for p in pending.values()) < 10), 'pending-bound')
        # All admission-time authorization is bound once. Due execution does not
        # recheck the whole identity predecessor after unrelated role changes.
        target = dict(operation=op, role=target_slot[0], suite=target_slot[1], parameters=target_slot[2],
                      old_key=old_id, new_key=new_id, effective_from=effective, accepted_at=inclusion,
                      nonce=update['nonce'], predecessor=update['previous'], update_id=r.object_id('update', update),
                      authorization_id=r.object_id('authorizations', evidence))
        if effective == inclusion:
            refs = {ref_slot(x): x for x in result['active']}
            refs.pop(target_slot, None)
            if new_id != ZERO:
                refs[target_slot] = dict(role=target_slot[0], key=r.keyref(keys[new_id]))
            result['active'] = [refs[x] for x in sorted(refs)]
        else:
            result['pending'].append(target)
            result['pending'].sort(key=slot)
    initial = not any(k['identity'] == current['identity'] for k in archive.values())
    r.require(not initial or (op == 1 and target_slot[0] == 5), 'initial-register')
    authenticate(update, evidence, current, verifiers, initial)
    result['next_nonce'] = update['nonce'] + 1
    result['previous'] = r.object_id('identity', current)
    validate_state(result, keys)
    return result, keys


def snapshot(state, archive, anchor, required):
    materialized = advance(state, archive, anchor)
    active = {ref_slot(x): x['key']['key_id'] for x in materialized['active']}
    selected = []
    for wanted in required:
        r.require(wanted in active, 'snapshot-missing')
        key = archive[active[wanted]]
        r.require(key['valid_from'] <= anchor < key['valid_until'], 'snapshot-validity')
        selected.append(deepcopy(key))
    return selected
