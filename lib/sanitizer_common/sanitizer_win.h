//===-- sanitizer_win.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Windows-specific syscall wrappers and classes.
//
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_WIN_H
#define SANITIZER_WIN_H
//// FIXME
#define NULL 0

#include "sanitizer_platform.h"

#if SANITIZER_CAN_USE_WINHEAP_ALLOCATOR

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace __sanitizer {

// These dummy classes are needed because it is needed to emulate external APIs
// of the CombinedAllocator.

// Dummy class.
class WinHeapSizeClassMap {
 public:
  static const uptr kNumClasses = 1;
  static const uptr kMaxSize = 0x10000000; // ??
  static uptr ClassID(uptr size) { return 0; }
};

// Dummy class.
class WinHeapPrimaryAllocator {
 public:
  static bool CanAllocate(uptr size, uptr alignment) { return true; }
};

// Dummy class.
class WinHeapAllocatorCache {};

class WinHeapAllocator
{
 public:
  void InitCommon(bool may_return_null) {
  }

  void InitLinkerInitialized(bool may_return_null) {
  }

  void Init(bool may_return_null) {
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366599(v=vs.85).aspx
    // Use default options. Size is not tested.
    _win_heap = HeapCreate(0, (1ULL << 10), (1ULL << 30) );
    if (!_win_heap) {
      /* volatile DWORD lastError = GetLastError(); */
      __debugbreak();
    }
  }

  void *Allocate(WinHeapAllocatorCache *cache, uptr size, uptr alignment,
                 bool cleared = false, bool check_rss_limit = false) {
    // Copy/pasted code from CombinedAllocator.
    // Returning 0 on malloc(0) may break a lot of code.
    if (size == 0)
      size = 1;
    if (size + alignment < size)
      return ReturnNullOrDie();
    if (check_rss_limit && RssLimitIsExceeded())
      return ReturnNullOrDie();
    if (alignment > 8)
      size = RoundUpTo(size, alignment);
    ////////

    // TODO(wwchrome).
    // Ignored: cache, alignment, cleared, check_rss_limit.
    //
    //
    // Size is 0 does not make sense.
    if (!size) {
      __debugbreak();
    }
    // Check heap is inited.
    if (!_win_heap) {
      __debugbreak();
    }
    // Prefer zero-init the heap.
    // TODO: no alignment guarentee in HeapAlloc, lucky if it fits alignment
    // requirement. If use _aligned_malloc(which is using malloc), will it work?
    uptr res = (uptr)HeapAlloc(_win_heap, HEAP_ZERO_MEMORY, size);
    // If it fails, enter debug.
    // if (!res) { __debugbreak(); }
    // Alignment needs to be checked.
    if (alignment > 8) CHECK_EQ(res & (alignment - 1), 0);

    return (void *)res;
  }

  bool MayReturnNull() const {
    return false;
  }

  void *ReturnNullOrDie() {
    return NULL;
  }

  void SetMayReturnNull(bool may_return_null) {
  }

  bool RssLimitIsExceeded() {
    return false;
  }

  void SetRssLimitIsExceeded(bool rss_limit_is_exceeded) {
  }

  void Deallocate(WinHeapAllocatorCache *cache, void *p) {
    if (!p) return;
    // TODO(wwchrome).
    // No PointerIsMine checking.
    BOOL res = HeapFree(_win_heap, 0, p);
    // 0 for failure.
    if (!res) { __debugbreak(); }
  }

  void *Reallocate(WinHeapAllocatorCache *cache, void *p, uptr new_size,
                   uptr alignment) {
    return NULL;
  }

  bool PointerIsMine(void *p) {
    return false;
  }

  bool FromPrimary(void *p) {
    return false;
  }

  void *GetMetaData(const void *p) {
    return NULL;
  }

  void *GetBlockBegin(const void *p) {
    return NULL;
  }

  // This function does the same as GetBlockBegin, but is much faster.
  // Must be called with the allocator locked.
  void *GetBlockBeginFastLocked(void *p) {
    return NULL;
  }

  uptr GetActuallyAllocatedSize(void *p) {
    return NULL;
  }

  uptr TotalMemoryUsed() {
    return NULL;
  }

  void TestOnlyUnmap() {}

  void InitCache(WinHeapAllocatorCache *cache) {
    /* __debugbreak(); */
  }

  void DestroyCache(WinHeapAllocatorCache *cache) {
  }

  void SwallowCache(WinHeapAllocatorCache *cache) {
  }

  void GetStats(AllocatorStatCounters s) const {
  }

  void PrintStats() {
  }

  // ForceLock() and ForceUnlock() are needed to implement Darwin malloc zone
  // introspection API.
  void ForceLock() {
  }

  void ForceUnlock() {
  }

  // Iterate over all existing chunks.
  // The allocator must be locked when calling this function.
  void ForEachChunk(ForEachChunkCallback callback, void *arg) {
  }

 private:
  HANDLE _win_heap;
  /* PrimaryAllocator primary_; */
  /* SecondaryAllocator secondary_; */
  AllocatorGlobalStats stats_;
  atomic_uint8_t may_return_null_;
  atomic_uint8_t rss_limit_is_exceeded_;
};

} // namespace __sanitizer
#endif  // SANITIZER_CAN_USE_WINHEAP_ALLOCATOR

#endif  // SANITIZER_WIN_H