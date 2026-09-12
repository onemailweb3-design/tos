-- Reference contract, not a running signer or anti-rollback device.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
CREATE TABLE key_versions (
 key_id BLOB PRIMARY KEY CHECK(length(key_id)=32),
 descriptor BLOB NOT NULL CHECK(length(descriptor) BETWEEN 1 AND 32768)
) WITHOUT ROWID;
CREATE TRIGGER immutable_key_update BEFORE UPDATE ON key_versions
BEGIN SELECT RAISE(ABORT, 'immutable key version'); END;
CREATE TRIGGER immutable_key_delete BEFORE DELETE ON key_versions
BEGIN SELECT RAISE(ABORT, 'retain public key history'); END;
CREATE TABLE key_handles (
 key_id BLOB PRIMARY KEY REFERENCES key_versions(key_id),
 handle BLOB NOT NULL CHECK(length(handle)=32),
 state TEXT NOT NULL CHECK(state IN ('PENDING','ACTIVE','RETIRED','DESTROYED'))
) WITHOUT ROWID;
CREATE TABLE admin_nonces (
 identity BLOB PRIMARY KEY CHECK(length(identity)=32),
 next_nonce BLOB NOT NULL CHECK(length(next_nonce)=8)
) WITHOUT ROWID;
CREATE TABLE duties (
 duty_id BLOB PRIMARY KEY CHECK(length(duty_id)=32),
 identity BLOB NOT NULL CHECK(length(identity)=32),
 session BLOB NOT NULL CHECK(length(session)=32),
 workchain INTEGER NOT NULL,
 shard BLOB NOT NULL CHECK(length(shard)=8),
 position BLOB NOT NULL CHECK(length(position)=8),
 role INTEGER NOT NULL CHECK(role BETWEEN 1 AND 5),
 statement_id BLOB NOT NULL CHECK(length(statement_id)=32),
 fence BLOB NOT NULL CHECK(length(fence)=8),
 state TEXT NOT NULL CHECK(state IN ('RESERVED','COMPLETE','BURNED')),
 result BLOB,
 CHECK((state='COMPLETE' AND result IS NOT NULL) OR (state!='COMPLETE' AND result IS NULL)),
 UNIQUE(identity,session,workchain,shard,position,role)
) WITHOUT ROWID;
CREATE TABLE capacity_reservations (
 capacity_domain BLOB NOT NULL CHECK(length(capacity_domain)=32),
 leaf BLOB NOT NULL CHECK(length(leaf)=8),
 duty_id BLOB NOT NULL REFERENCES duties(duty_id),
 PRIMARY KEY(capacity_domain,leaf)
) WITHOUT ROWID;
CREATE TRIGGER immutable_capacity_update BEFORE UPDATE ON capacity_reservations
BEGIN SELECT RAISE(ABORT, 'consumed capacity'); END;
CREATE TRIGGER immutable_capacity_delete BEFORE DELETE ON capacity_reservations
BEGIN SELECT RAISE(ABORT, 'consumed capacity'); END;
CREATE TRIGGER immutable_duty_identity BEFORE UPDATE ON duties
WHEN NEW.duty_id!=OLD.duty_id OR NEW.identity!=OLD.identity OR NEW.session!=OLD.session OR
 NEW.workchain!=OLD.workchain OR NEW.shard!=OLD.shard OR NEW.position!=OLD.position OR
 NEW.role!=OLD.role OR NEW.statement_id!=OLD.statement_id OR NEW.fence!=OLD.fence
BEGIN SELECT RAISE(ABORT, 'immutable duty reservation'); END;
CREATE TRIGGER terminal_duty BEFORE UPDATE ON duties
WHEN OLD.state!='RESERVED' OR NEW.state NOT IN ('COMPLETE','BURNED')
BEGIN SELECT RAISE(ABORT, 'invalid duty transition'); END;
CREATE TRIGGER retain_duty BEFORE DELETE ON duties
BEGIN SELECT RAISE(ABORT, 'retain anti-equivocation history'); END;
