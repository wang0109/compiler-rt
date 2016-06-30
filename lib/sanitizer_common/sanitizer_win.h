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


#include "sanitizer_platform.h"
#if SANITIZER_CAN_USE_WINHEAP_ALLOCATOR
#include "sanitizer_allocator.h"

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

  void Init(bool may_return_null);

  void *Allocate(WinHeapAllocatorCache *cache, uptr size, uptr alignment,
                 bool cleared = false, bool check_rss_limit = false);

  bool MayReturnNull() const {
    return false;
  }

  void *ReturnNullOrDie() {
    return nullptr;
  }

  void SetMayReturnNull(bool may_return_null) {
  }

  bool RssLimitIsExceeded() {
    return false;
  }

  void SetRssLimitIsExceeded(bool rss_limit_is_exceeded) {
  }

  void Deallocate(WinHeapAllocatorCache *cache, void *p);

  void *Reallocate(WinHeapAllocatorCache *cache, void *p, uptr new_size,
                   uptr alignment) {
    return nullptr;
  }

  bool PointerIsMine(void *p) {
    return false;
  }

  bool FromPrimary(void *p) {
    return false;
  }

  void *GetMetaData(const void *p) {
    return nullptr;
  }

  void *GetBlockBegin(const void *p) {
    return nullptr;
  }

  // This function does the same as GetBlockBegin, but is much faster.
  // Must be called with the allocator locked.
  void *GetBlockBeginFastLocked(void *p) {
    return nullptr;
  }

  uptr GetActuallyAllocatedSize(void *p) {
    return 0;
  }

  uptr TotalMemoryUsed() {
    return 0;
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
  uptr _win_heap;
  /* PrimaryAllocator primary_; */
  /* SecondaryAllocator secondary_; */
  AllocatorGlobalStats stats_;
  atomic_uint8_t may_return_null_;
  atomic_uint8_t rss_limit_is_exceeded_;
};

} // namespace __sanitizer
#endif  // SANITIZER_CAN_USE_WINHEAP_ALLOCATOR

#endif  // SANITIZER_WIN_H