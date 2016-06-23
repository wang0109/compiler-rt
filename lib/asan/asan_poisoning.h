//===-- asan_poisoning.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Shadow memory poisoning by ASan RTL and by user application.
//===----------------------------------------------------------------------===//

#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_mapping.h"
#include "sanitizer_common/sanitizer_flags.h"

namespace __asan {

// Enable/disable memory poisoning.
void SetCanPoisonMemory(bool value);
bool CanPoisonMemory();

// Poisons the shadow memory for "size" bytes starting from "addr".
void PoisonShadow(uptr addr, uptr size, u8 value);

#if SANITIZER_WINDOWS64
__declspec(noinline) static void Debug_memset1(volatile uptr aa,
                                               volatile uptr bb,
                                               volatile u8 cc) {
  volatile char *aax = (char *)aa;
  volatile char *bbx = (char *)bb;
  for (volatile char *ii = aax; ii < bbx; ii++) {
    *ii = cc;
  }
}

static dump_virtualquery() {
  // FIXME(wwchrome).Dump from 0 to 128T.
  uptr addr = 0;
  int limit = 5; //
  Report("Prting for %d regions....\n", limit);
  int i;
  for (i = 0; i < limit; ++i) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery ((LPVOID)addr, &mbi, sizeof(mbi)))
    {
      __debugbreak();
    }
    Report("====================================\n");
    // print one address first.
    Report(
        "baseaddress: %llx\n, allocationbase: %llx \n, allocationprotect %llx, "
        "regionsize: %llx\n, state: %llx\n, protect: %llx\n, type: %llx\n ",
        (uptr)mbi.baseaddress, (uptr)mbi.allocationbase,
        (uptr)mbi.allocationprotect, (uptr)mbi.regionsize, (uptr)mbi.state,
        (uptr)mbi.protect, (uptr)mbi.type );

    addr += (uptr)mbi.regionsize;
  }

}
#endif

// Poisons the shadow memory for "redzone_size" bytes starting from
// "addr + size".
void PoisonShadowPartialRightRedzone(uptr addr,
                                     uptr size,
                                     uptr redzone_size,
                                     u8 value);

// Fast versions of PoisonShadow and PoisonShadowPartialRightRedzone that
// assume that memory addresses are properly aligned. Use in
// performance-critical code with care.
ALWAYS_INLINE void FastPoisonShadow(uptr aligned_beg, uptr aligned_size,
                                    u8 value) {
  DCHECK(CanPoisonMemory());
  volatile uptr shadow_beg = MEM_TO_SHADOW(aligned_beg);
  volatile uptr shadow_end = MEM_TO_SHADOW(
      aligned_beg + aligned_size - SHADOW_GRANULARITY) + 1;
  // FIXME: Page states are different on Windows, so using the same interface
  // for mapping shadow and zeroing out pages doesn't "just work", so we should
  // probably provide higher-level interface for these operations.
  // For now, just memset on Windows.
  if (value ||
      SANITIZER_WINDOWS == 1 ||
      shadow_end - shadow_beg < common_flags()->clear_shadow_mmap_threshold) {
    /* VReport("In %s, aligned_beg: %llx\n", __FILE__, (uptr)aligned_beg); */
    Report("In FastPoisonShadow, aligned_beg: %llx\n", aligned_beg);
    dump_virtualquery();
    // TODO: check with a loop read, just to verify that it was not
    // my stomping's fault
    // FIXME: Remove all these debug things.
    // Disable for now.
    // Debug_memset1(shadow_beg, shadow_end, value);
    // __debugbreak();
    REAL(memset)((void*)shadow_beg, value, shadow_end - shadow_beg);
  } else {
    uptr page_size = GetPageSizeCached();
    uptr page_beg = RoundUpTo(shadow_beg, page_size);
    uptr page_end = RoundDownTo(shadow_end, page_size);

    if (page_beg >= page_end) {
      REAL(memset)((void *)shadow_beg, 0, shadow_end - shadow_beg);
    } else {
      if (page_beg != shadow_beg) {
        REAL(memset)((void *)shadow_beg, 0, page_beg - shadow_beg);
      }
      if (page_end != shadow_end) {
        REAL(memset)((void *)page_end, 0, shadow_end - page_end);
      }
      ReserveShadowMemoryRange(page_beg, page_end - 1, nullptr);
    }
  }
}

ALWAYS_INLINE void FastPoisonShadowPartialRightRedzone(
    uptr aligned_addr, uptr size, uptr redzone_size, u8 value) {
  DCHECK(CanPoisonMemory());
  bool poison_partial = flags()->poison_partial;
  u8 *shadow = (u8*)MEM_TO_SHADOW(aligned_addr);
  for (uptr i = 0; i < redzone_size; i += SHADOW_GRANULARITY, shadow++) {
    if (i + SHADOW_GRANULARITY <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow = (SHADOW_GRANULARITY == 128) ? 0xff : value;  // unaddressable
    } else {
      // first size-i bytes are addressable
      *shadow = poison_partial ? static_cast<u8>(size - i) : 0;
    }
  }
}

// Calls __sanitizer::FlushUnneededShadowMemory() on
// [MemToShadow(p), MemToShadow(p+size)] with proper rounding.
void FlushUnneededASanShadowMemory(uptr p, uptr size);

}  // namespace __asan
