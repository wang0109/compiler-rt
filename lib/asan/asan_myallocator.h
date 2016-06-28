#include "asan_internal.h"

#define NULL 0

#ifndef ASAN_MYALLOCATOR_H
#define ASAN_MYALLOCATOR_H

namespace __sanitizer {

template <class PrimaryAllocator, class AllocatorCache,
          class SecondaryAllocator>  // NOLINT
class MyAllocator
{
 public:
  void InitCommon(bool may_return_null) {
  }

  void InitLinkerInitialized(bool may_return_null) {
  }

  void Init(bool may_return_null) {
  }

  void *Allocate(AllocatorCache *cache, uptr size, uptr alignment,
                 bool cleared = false, bool check_rss_limit = false) {
    return NULL;
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

  void Deallocate(AllocatorCache *cache, void *p) {
  }

  void *Reallocate(AllocatorCache *cache, void *p, uptr new_size,
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

  void InitCache(AllocatorCache *cache) {
  }

  void DestroyCache(AllocatorCache *cache) {
  }

  void SwallowCache(AllocatorCache *cache) {
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

 /* private: */
  /* PrimaryAllocator primary_; */
  /* SecondaryAllocator secondary_; */
  /* AllocatorGlobalStats stats_; */
  /* atomic_uint8_t may_return_null_; */
  /* atomic_uint8_t rss_limit_is_exceeded_; */
};
}
#endif  // ASAN_MYALLOCATOR_H
