//! Arena / bump allocator (PH56 · T01).
//!
//! An [`Arena`] pre-allocates one aligned backing block of `cap` bytes and
//! satisfies every allocation by bumping a cursor — no per-op `malloc`/`free`,
//! no fragmentation. At request/microbatch end [`Arena::reset`] rewinds the
//! cursor to zero in O(1) (no `free` calls); the next request reuses the same
//! memory. Allocations fail closed with [`CALYX_ALLOC_CAP_EXCEEDED`] the instant
//! they would cross the cap — the arena never reallocs or grows (A26).
//!
//! The backing block is over-aligned to [`ARENA_BASE_ALIGN`], so the returned
//! pointers' alignment is a deterministic function of the cursor (not of where
//! the OS happened to place a `Vec`), which keeps the alignment tests exact.

use std::alloc::{self, Layout};
use std::marker::PhantomData;
use std::ptr::NonNull;

use super::{AllocStats, alloc_cap_exceeded};
use crate::Result;

/// Backing-block base alignment. Pointers requested with an alignment `<=` this
/// are aligned deterministically relative to the cursor (the block base is a
/// multiple of every power of two up to this value).
pub const ARENA_BASE_ALIGN: usize = 4096;

/// An owned, [`ARENA_BASE_ALIGN`]-aligned byte block. Frees on drop.
#[derive(Debug)]
struct AlignedBlock {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl AlignedBlock {
    /// Allocates `cap` zeroed, [`ARENA_BASE_ALIGN`]-aligned bytes. `cap > 0`.
    fn new(cap: usize) -> Self {
        debug_assert!(cap > 0, "AlignedBlock::new requires cap > 0");
        let layout = Layout::from_size_align(cap, ARENA_BASE_ALIGN)
            .expect("arena cap + base align is a valid layout");
        // SAFETY: `layout` has non-zero size (cap > 0). `alloc_zeroed` returns a
        // block of `cap` bytes aligned to ARENA_BASE_ALIGN, or null on OOM.
        let raw = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self { ptr, layout }
    }
}

impl Drop for AlignedBlock {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`layout` are exactly what `alloc_zeroed` returned and
        // are freed exactly once (here, on drop).
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

/// A bump allocator over a fixed, pre-allocated, aligned block.
///
/// Not `Sync`/`Send`-shared: an arena is owned by one request/microbatch at a
/// time. Hand allocations out via [`Arena::alloc`] (raw) or [`Arena::alloc_vec`]
/// (typed); rewind everything with [`Arena::reset`].
#[derive(Debug)]
pub struct Arena {
    block: AlignedBlock,
    cursor: usize,
    cap: usize,
    high_water: usize,
    resets: u64,
}

impl Arena {
    /// Builds an arena with a hard cap of `cap` bytes.
    ///
    /// # Errors
    /// [`CALYX_ALLOC_CAP_EXCEEDED`](super::CALYX_ALLOC_CAP_EXCEEDED) if `cap == 0`
    /// — a zero-capacity arena can never satisfy an allocation, so it is rejected
    /// at construction rather than failing every later call.
    pub fn new(cap: usize) -> Result<Self> {
        if cap == 0 {
            return Err(alloc_cap_exceeded("arena cap must be > 0"));
        }
        Ok(Self {
            block: AlignedBlock::new(cap),
            cursor: 0,
            cap,
            high_water: 0,
            resets: 0,
        })
    }

    /// Allocates `size` bytes aligned to `align` (a power of two) by bumping the
    /// cursor past any alignment padding. Returns a pointer into the arena's
    /// block valid until the next [`reset`](Arena::reset) (or arena drop).
    ///
    /// A zero-size request is a no-op: it returns a non-null, correctly aligned
    /// dangling pointer and does **not** advance the cursor.
    ///
    /// # Errors
    /// [`CALYX_ALLOC_CAP_EXCEEDED`](super::CALYX_ALLOC_CAP_EXCEEDED) when the
    /// padded request would cross the cap. The cursor is **not** advanced on
    /// failure (no partial allocation), so the arena stays usable.
    pub fn alloc(&mut self, size: usize, align: usize) -> Result<*mut u8> {
        assert!(align.is_power_of_two(), "alignment must be a power of two");
        if size == 0 {
            // A dangling-but-aligned pointer; consumes nothing.
            return Ok(align as *mut u8);
        }
        // Padding to align the cursor. Because the block base is a multiple of
        // ARENA_BASE_ALIGN, for `align <= ARENA_BASE_ALIGN` this padding is a
        // pure function of the cursor; for larger `align` we still align the
        // real address. Compute against the absolute address to stay correct.
        let base = self.block.ptr.as_ptr() as usize;
        let current = base
            .checked_add(self.cursor)
            .ok_or_else(|| alloc_cap_exceeded("arena cursor address overflow"))?;
        let aligned = current
            .checked_next_multiple_of(align)
            .ok_or_else(|| alloc_cap_exceeded("arena alignment overflow"))?;
        let padding = aligned - current;
        let consumed = padding
            .checked_add(size)
            .ok_or_else(|| alloc_cap_exceeded("arena request size overflow"))?;
        let new_cursor = self
            .cursor
            .checked_add(consumed)
            .ok_or_else(|| alloc_cap_exceeded("arena cursor overflow"))?;
        if new_cursor > self.cap {
            return Err(alloc_cap_exceeded(format!(
                "arena alloc of {size} bytes (align {align}, +{padding} pad) would use \
                 {new_cursor} > cap {} bytes",
                self.cap
            )));
        }
        self.cursor = new_cursor;
        if self.cursor > self.high_water {
            self.high_water = self.cursor;
        }
        Ok(aligned as *mut u8)
    }

    /// Allocates room for up to `capacity` values of `T`, returning an empty
    /// [`ArenaVec`] you push into. The vector borrows the arena for its whole
    /// lifetime (so the arena cannot be reset or re-allocated from while it is
    /// alive — drop it first).
    ///
    /// # Errors
    /// [`CALYX_ALLOC_CAP_EXCEEDED`](super::CALYX_ALLOC_CAP_EXCEEDED) if the
    /// backing bytes do not fit under the cap.
    pub fn alloc_vec<T>(&mut self, capacity: usize) -> Result<ArenaVec<'_, T>> {
        let elem = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>();
        if elem == 0 || capacity == 0 {
            // ZST or zero-capacity: no backing bytes needed.
            return Ok(ArenaVec {
                ptr: NonNull::dangling(),
                len: 0,
                capacity,
                _arena: PhantomData,
            });
        }
        let bytes = elem
            .checked_mul(capacity)
            .ok_or_else(|| alloc_cap_exceeded("arena_vec byte size overflow"))?;
        let raw = self.alloc(bytes, align)?;
        let ptr = NonNull::new(raw.cast::<T>()).expect("arena alloc never returns null");
        Ok(ArenaVec {
            ptr,
            len: 0,
            capacity,
            _arena: PhantomData,
        })
    }

    /// Rewinds the cursor to zero in O(1). No `free` is performed — the backing
    /// block is retained for reuse. Any pointer handed out before the reset is
    /// invalidated (enforced at compile time for [`ArenaVec`] via its borrow).
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.resets += 1;
    }

    /// Bytes currently consumed (including alignment padding) — the live cursor.
    pub fn used(&self) -> usize {
        self.cursor
    }

    /// Hard cap in bytes.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Peak bytes ever consumed between resets (high-water mark).
    pub fn high_water(&self) -> usize {
        self.high_water
    }

    /// Snapshot of allocation metrics for the metrics surface / FSV.
    pub fn stats(&self) -> AllocStats {
        AllocStats {
            arena_high_water_bytes: self.high_water,
            arena_resets: self.resets,
        }
    }
}

/// A typed, fixed-capacity vector backed by arena bytes for the arena's borrow.
///
/// Push initializes elements in place; only initialized elements are ever read,
/// and they are dropped when the `ArenaVec` is dropped (so `T`'s owned resources
/// do not leak even though the arena itself never frees per element).
pub struct ArenaVec<'arena, T> {
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
    _arena: PhantomData<&'arena mut Arena>,
}

impl<T> ArenaVec<'_, T> {
    /// Appends `value`.
    ///
    /// # Errors
    /// [`CALYX_ALLOC_CAP_EXCEEDED`](super::CALYX_ALLOC_CAP_EXCEEDED) if the
    /// vector is already at its reserved capacity (fail closed; never grows).
    pub fn push(&mut self, value: T) -> Result<()> {
        if self.len == self.capacity {
            return Err(alloc_cap_exceeded(format!(
                "arena_vec at capacity {} — cannot push",
                self.capacity
            )));
        }
        // SAFETY: `len < capacity`, so `ptr + len` is within the reserved,
        // correctly aligned region and currently uninitialized; we write once.
        unsafe { self.ptr.as_ptr().add(self.len).write(value) };
        self.len += 1;
        Ok(())
    }

    /// Number of initialized elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no elements have been pushed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reserved element capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The initialized elements as a slice.
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: elements `0..len` are initialized and the region is aligned.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// The initialized elements as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: elements `0..len` are initialized and uniquely borrowed.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> Drop for ArenaVec<'_, T> {
    fn drop(&mut self) {
        // SAFETY: drop the `len` initialized elements in place so `T`'s owned
        // resources are released; the backing bytes belong to the arena.
        unsafe {
            std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(
                self.ptr.as_ptr(),
                self.len,
            ));
        }
    }
}
