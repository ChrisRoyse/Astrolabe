//! FSV for multi-record atomic commit framing (issue #23).
//!
//! These tests exercise commits larger than a single WAL record. The source of
//! truth is the bytes on disk: every assertion either reads the persisted
//! segment back through replay and compares the reassembled payload byte-for-
//! byte, or inspects the raw segment bytes / physical record inventory
//! directly. Nothing is trusted from a return value alone.

use super::record;
use super::*;
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

const CHUNK: usize = record::CHUNK_TARGET_BYTES as usize;

/// Deterministic, long-period payload so a mis-ordered or dropped chunk during
/// reassembly changes the bytes (251 is coprime with the 32 MiB chunk size, so
/// the pattern never realigns on a chunk boundary).
fn payload_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn physical_record_count(dir: &PathBuf) -> usize {
    let mut wal = Wal::open(dir, WalOptions::default()).expect("open for inventory");
    let inventory = wal.segment_inventory().expect("inventory");
    inventory.iter().map(|segment| segment.record_count).sum()
}

#[test]
fn oversized_commit_frames_into_group_and_replays_byte_exact() {
    let dir = test_dir("group-roundtrip");
    let mut wal = Wal::open(&dir, WalOptions::default()).expect("open wal");

    // A small standalone commit first, then a commit larger than one chunk.
    let prior = wal.append(b"prior-commit").expect("append prior");
    let big_payload = payload_of(CHUNK + CHUNK / 2); // 1.5 chunks -> 2 members
    let big = wal.append(&big_payload).expect("append oversized commit");
    drop(wal);

    // A group is one logical commit: it consumes exactly one seq (matching the
    // MVCC commit seq), even though it spans multiple physical records.
    assert_eq!(prior.seq, 1);
    assert_eq!(big.seq, 2, "group commit consumes exactly one logical seq");

    // Physically there are three records (1 standalone + 2 group members)...
    assert_eq!(physical_record_count(&dir), 3);

    // ...and the raw segment carries the CXW2 group magic.
    let segment_bytes = fs::read(&big.segment_path).expect("read segment");
    let group_magic = record::MAGIC_GROUP.to_le_bytes();
    assert!(
        segment_bytes
            .windows(group_magic.len())
            .any(|window| window == group_magic),
        "segment must contain a CXW2 group-member record"
    );

    // Logically, replay reassembles the group into ONE record whose payload is
    // byte-exact with what was committed.
    let replay = replay_dir(&dir).expect("replay");
    assert_eq!(replay.torn_tail, None);
    assert_eq!(replay.records.len(), 2, "prior + reassembled group");
    assert_eq!(replay.records[0].seq, 1);
    assert_eq!(replay.records[0].payload, b"prior-commit");
    assert_eq!(replay.records[1].seq, big.seq);
    assert_eq!(
        replay.records[1].payload, big_payload,
        "reassembled group payload must be byte-exact"
    );
    assert_eq!(replay.records[1].start_offset, big.start_offset);
    assert_eq!(replay.records[1].end_offset, big.end_offset);

    // Reopening resumes after the group's single logical seq.
    let mut reopened = Wal::open(&dir, WalOptions::default()).expect("reopen");
    let after = reopened.append(b"after-group").expect("append after group");
    assert_eq!(after.seq, 3);
    drop(reopened);

    cleanup(dir);
}

#[test]
fn three_member_group_replays_byte_exact() {
    let dir = test_dir("group-three-member");
    let mut wal = Wal::open(&dir, WalOptions::default()).expect("open wal");

    // Larger than the 64 MiB per-record cap: proves a commit that the old
    // single-record encoder rejected outright now commits durably.
    let big_payload = payload_of(2 * CHUNK + 1); // 3 members
    let big = wal.append(&big_payload).expect("append 3-member commit");
    drop(wal);

    assert_eq!(big.seq, 1, "single commit -> one logical seq");
    assert_eq!(physical_record_count(&dir), 3);

    let replay = replay_dir(&dir).expect("replay");
    assert_eq!(replay.torn_tail, None);
    assert_eq!(replay.records.len(), 1);
    assert_eq!(replay.records[0].payload, big_payload);
    cleanup(dir);
}

/// Truncates the WAL segment at `truncate_to` bytes, replays, and asserts the
/// partial group is discarded wholesale while the prior standalone commit
/// survives.
fn assert_torn_group_is_all_or_nothing(name: &str, extra_after_group_start: u64) {
    let dir = test_dir(name);
    let mut wal = Wal::open(&dir, WalOptions::default()).expect("open wal");
    let prior = wal.append(b"durable-prior").expect("append prior");
    let big_payload = payload_of(CHUNK + CHUNK / 2); // 2 members
    let big = wal.append(&big_payload).expect("append group");
    drop(wal);

    // The group starts exactly where the prior commit ended (they share one
    // segment at the default 64 MiB rotation threshold).
    let group_start = big.start_offset;
    assert_eq!(group_start, prior.end_offset);

    let truncate_to = group_start + extra_after_group_start;
    let segment = big.segment_path.clone();
    let before_len = fs::metadata(&segment).expect("meta").len();
    assert!(
        truncate_to < before_len,
        "truncation must remove group bytes"
    );
    let file = OpenOptions::new()
        .write(true)
        .open(&segment)
        .expect("open segment for truncation");
    file.set_len(truncate_to).expect("truncate mid-group");
    file.sync_all().expect("fsync truncation");
    drop(file);

    let replay = replay_dir(&dir).expect("replay torn group");
    // The whole partial group is a torn tail...
    let torn = replay.torn_tail.expect("torn tail reported");
    assert_eq!(torn.code, "CALYX_ASTER_TORN_WAL");
    assert_eq!(torn.offset, group_start, "truncate the whole group");
    // ...only the prior commit survives, byte-exact...
    assert_eq!(replay.records.len(), 1);
    assert_eq!(replay.records[0].seq, prior.seq);
    assert_eq!(replay.records[0].payload, b"durable-prior");
    // ...and the segment file is physically truncated back to the group start.
    assert_eq!(
        fs::metadata(&segment).expect("meta after").len(),
        group_start,
        "partial group bytes must be physically removed"
    );

    // The vault can keep committing after recovery, resuming from the prior seq.
    let mut reopened = Wal::open(&dir, WalOptions::default()).expect("reopen after torn");
    let next = reopened
        .append(b"post-recovery")
        .expect("append post recovery");
    assert_eq!(next.seq, prior.seq + 1);
    drop(reopened);

    cleanup(dir);
}

#[test]
fn torn_group_mid_first_member_is_discarded_whole() {
    // Truncate inside the first member's payload.
    assert_torn_group_is_all_or_nothing(
        "torn-mid-first-member",
        record::GROUP_HEADER_LEN as u64 + 16,
    );
}

#[test]
fn torn_group_between_members_is_discarded_whole() {
    // Truncate exactly on the boundary between member 0 and member 1 (member 0
    // is a complete, crc-valid record; member 1 is entirely absent).
    assert_torn_group_is_all_or_nothing(
        "torn-between-members",
        record::GROUP_HEADER_LEN as u64 + CHUNK as u64,
    );
}

#[test]
fn torn_group_mid_last_member_is_discarded_whole() {
    // Member 0 complete, member 1 partial.
    assert_torn_group_is_all_or_nothing(
        "torn-mid-last-member",
        2 * record::GROUP_HEADER_LEN as u64 + CHUNK as u64 + 8,
    );
}

#[test]
fn pre_change_single_record_wal_replays_identically() {
    // A WAL written by the pre-change encoder is exactly a run of standalone
    // CXW1 records. Build such a fixture by hand and prove it replays byte-for-
    // byte with no reframing or migration.
    let dir = test_dir("old-format-compat");
    let seg = dir.join("00000000000000000000.wal");
    let r1 = record::encode(1, b"alpha").expect("encode legacy 1");
    let r2 = record::encode(2, b"bravo").expect("encode legacy 2");
    let mut fixture = Vec::new();
    fixture.extend_from_slice(&r1);
    fixture.extend_from_slice(&r2);
    fs::write(&seg, &fixture).expect("write legacy fixture");

    // The fixture is pure CXW1 (no group magic anywhere).
    assert_eq!(&fixture[0..4], b"CXW1");
    let group_magic = record::MAGIC_GROUP.to_le_bytes();
    assert!(
        !fixture
            .windows(group_magic.len())
            .any(|window| window == group_magic)
    );

    let replay = replay_dir(&dir).expect("replay legacy wal");
    assert_eq!(replay.torn_tail, None);
    assert_eq!(replay.records.len(), 2);
    assert_eq!(replay.records[0].seq, 1);
    assert_eq!(replay.records[0].payload, b"alpha");
    assert_eq!(replay.records[1].seq, 2);
    assert_eq!(replay.records[1].payload, b"bravo");

    // The on-disk bytes were not rewritten by replay.
    assert_eq!(fs::read(&seg).expect("reread"), fixture);

    // A new oversized commit appended after the legacy records still frames as a
    // group and coexists with the legacy standalone records.
    let mut wal = Wal::open(&dir, WalOptions::default()).expect("open over legacy");
    let big_payload = payload_of(CHUNK + 7);
    let big = wal.append(&big_payload).expect("append group after legacy");
    assert_eq!(big.seq, 3, "legacy seqs 1,2 then the group's single seq 3");
    drop(wal);
    let replay = replay_dir(&dir).expect("replay mixed wal");
    assert_eq!(replay.records.len(), 3);
    assert_eq!(replay.records[0].payload, b"alpha");
    assert_eq!(replay.records[1].payload, b"bravo");
    assert_eq!(replay.records[2].payload, big_payload);
    cleanup(dir);
}

#[test]
fn boundary_commit_sizes_frame_correctly() {
    let dir = test_dir("group-boundary");
    let mut wal = Wal::open(&dir, WalOptions::default()).expect("open wal");

    // Empty commit -> one standalone record.
    let empty = wal.append(b"").expect("append empty");
    assert_eq!(empty.seq, 1);

    // Exactly the chunk target -> still a single standalone record (the split
    // only triggers strictly above the target).
    let at_target = payload_of(CHUNK);
    let target = wal.append(&at_target).expect("append at chunk target");
    assert_eq!(target.seq, 2, "at-target commit stays a single record");

    // Exactly the 64 MiB per-record cap -> two members (cap > chunk target),
    // but still one logical seq.
    let at_cap = payload_of(record::MAX_RECORD_BYTES as usize);
    let cap = wal.append(&at_cap).expect("append at record cap");
    assert_eq!(
        cap.seq, 3,
        "cap-sized commit frames into a two-member group"
    );
    drop(wal);

    let replay = replay_dir(&dir).expect("replay boundary wal");
    assert_eq!(replay.torn_tail, None);
    assert_eq!(replay.records.len(), 3);
    assert_eq!(replay.records[0].payload, b"");
    assert_eq!(replay.records[1].payload, at_target);
    assert_eq!(replay.records[2].payload, at_cap);
    assert_eq!(replay.records[2].seq, cap.seq);
    cleanup(dir);
}

fn test_dir(name: &str) -> PathBuf {
    let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("calyx-aster-{name}-{}-{id}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create test dir");
    dir
}

fn cleanup(dir: PathBuf) {
    let _ = fs::remove_dir_all(dir);
}
