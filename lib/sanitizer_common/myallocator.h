#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366599(v=vs.85).aspx
    // Use default options. Size is not tested.
    _win_heap = HeapCreate(0, (1ULL << 10), (1ULL << 40) );
  }

  void *Allocate(AllocatorCache *cache, uptr size, uptr alignment,
                 bool cleared = false, bool check_rss_limit = false) {
    // TODO(wwchrome).
    // Ignored: cache, alignment, cleared, check_rss_limit.
    //
    //
    // Size is 0 does not make sense.
    if (!size) { __debugbreak(); }
    // Check heap is inited.
    if (!_win_heap) { __debugbreak(); }
    // Prefer zero-init the heap.
    uptr res = HeapAlloc(_win_heap, HEAP_ZERO_MEMORY, size );
    // If it fails, enter debug.
    if (!res) { __debugbreak(); }
    // Alignment needs to be checked.
    if (alignment > 8)
      CHECK_EQ(res & (alignment - 1), 0);

    return res;
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
    if (!p) return;
    // TODO(wwchrome).
    // No PointerIsMine checking.
    BOOL res = HeapFree(_win_heap, 0, p);
    // 0 for failure.
    if (!res) { __debugbreak(); }
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

 private:
  HANDLE _win_heap;
  /* PrimaryAllocator primary_; */
  /* SecondaryAllocator secondary_; */
  /* AllocatorGlobalStats stats_; */
  /* atomic_uint8_t may_return_null_; */
  /* atomic_uint8_t rss_limit_is_exceeded_; */
};
}
#endif  // ASAN_MYALLOCATOR_H
