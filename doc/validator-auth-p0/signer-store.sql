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
-- INSERT OR REPLACE removes the conflicting row before inserting, and on a
-- connection with the default recursive_triggers=0 that removal does not run
-- the DELETE trigger above. Guarding the insert closes it without depending on
-- how a caller opened the database, which a one-time PRAGMA cannot guarantee.
CREATE TRIGGER no_key_replacement BEFORE INSERT ON key_versions
WHEN EXISTS(SELECT 1 FROM key_versions WHERE key_id = NEW.key_id)
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
CREATE TRIGGER no_capacity_replacement BEFORE INSERT ON capacity_reservations
WHEN EXISTS(SELECT 1 FROM capacity_reservations
            WHERE capacity_domain = NEW.capacity_domain AND leaf = NEW.leaf)
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
-- Both uniqueness constraints have to be guarded: replacing by duty_id would
-- reopen a settled duty, and replacing by the slot would let a second statement
-- be signed for the same identity, session, shard, position and role, which is
-- the equivocation this table exists to prevent.
CREATE TRIGGER no_duty_replacement BEFORE INSERT ON duties
WHEN EXISTS(SELECT 1 FROM duties WHERE duty_id = NEW.duty_id
            OR (identity = NEW.identity AND session = NEW.session
                AND workchain = NEW.workchain AND shard = NEW.shard
                AND position = NEW.position AND role = NEW.role))
BEGIN SELECT RAISE(ABORT, 'retain anti-equivocation history'); END;
