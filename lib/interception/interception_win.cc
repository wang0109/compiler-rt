//===-- interception_linux.cc -----------------------------------*- C++ -*-===//
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
// Windows-specific interception methods.
//===----------------------------------------------------------------------===//

#ifdef _WIN32

#include "interception.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>


namespace __sanitizer {
  void Report(const char* format, ...);
}

namespace __interception {

// FIXME: internal_str* and internal_mem* functions should be moved from the
// ASan sources into interception/.

static void _memset(void *p, int value, size_t sz) {
  for (size_t i = 0; i < sz; ++i)
    ((char*)p)[i] = (char)value;
}

static void _memcpy(void *dst, void *src, size_t sz) {
  char *dst_c = (char*)dst,
       *src_c = (char*)src;
  for (size_t i = 0; i < sz; ++i)
    dst_c[i] = src_c[i];
}

#if SANITIZER_WINDOWS64
static void WriteIndirectJumpInstruction(char *jmp_from, char *indirect_target) {  // NOLINT
  // jmp [rip + XXYYZZWW] = FF 25 WW ZZ YY XX, where
  // XXYYZZWW is an offset from jmp_from.
  // The displacement is still 32-bit in x64, so indirect_target must be located
  // within +/- 2GB range.
 


  int offset = (int)(indirect_target - jmp_from - 6);
  jmp_from[0] = '\xFF';
  jmp_from[1] = '\x25';
  *(int*)(jmp_from + 2) = offset;
}
#else
static void WriteJumpInstruction(char *jmp_from, char *to) {
  // jmp XXYYZZWW = E9 WW ZZ YY XX, where XXYYZZWW is an offset from jmp_from
  // to the next instruction to the destination.
  ptrdiff_t offset = to - jmp_from - 5;
  *jmp_from = '\xE9';
  *(ptrdiff_t*)(jmp_from + 1) = offset;
}
#endif

static void WriteTrampolineJumpInstruction(char *jmp_from, char *to) {
#if SANITIZER_WINDOWS64
  // Emit an indirect jump through immediately following bytes:
  // jmp_from:
  //   jmp [rip + 6]
  //   .quad to
  // Store the address.
  char *indirect_target = jmp_from + 6;
  *(uptr*)indirect_target = (uptr)to;
  // Write the indirect jump.
  WriteIndirectJumpInstruction(jmp_from, indirect_target);
#else
  WriteJumpInstruction(jmp_from, to);
#endif
}

static void WriteInterceptorJumpInstruction(char *jmp_from, char *to) {
#if SANITIZER_WINDOWS64

  static void *pointers_page = 0;
  static uptr pointers_counter = 0;

  static SIZE_T alloc_granularity = 0;
  static SIZE_T page_size = 0;

  if (alloc_granularity == 0) {

    SYSTEM_INFO system_info = {};
    ::GetSystemInfo(&system_info);
    //page_size = system_info.dwPageSize;
    alloc_granularity = system_info.dwAllocationGranularity;
    page_size = system_info.dwPageSize;

    if (!alloc_granularity) {
      //must work.
      __debugbreak();
    }


  }

  static const uptr kLimitRange = (100ULL) << 20; // 10 Meg

  if (pointers_page != 0) {
    Report("Already found pointer page!\n");
  }
  else {
    // Search for one single page after current image.
    // Get current allocation begin.
    MEMORY_BASIC_INFORMATION cur_info;
    if (0 == ::VirtualQuery(jmp_from, &cur_info, sizeof(cur_info))) {

      // jmp_from should be allocated already!
      __debugbreak();

    }

    // find current allocation begin
    uptr alloc_begin = (uptr)cur_info.AllocationBase;
    uptr region_size = (uptr)cur_info.RegionSize;
    uptr next_begin = alloc_begin + region_size;


    Report("Cur page: at %llx, region_size: %llx\n", alloc_begin, region_size);

    switch (cur_info.State) {
    case MEM_FREE:
      Report("State: Free\n");
      break;
    case MEM_RESERVE:
      Report("State: Reserve\n");
      break;
    case MEM_COMMIT:
      Report("State: COmmit\n");
      break;
    default:
      __debugbreak();
    }








    // for loop
    for (uptr curr_addr = next_begin; curr_addr < next_begin + kLimitRange; ) {


      MEMORY_BASIC_INFORMATION info;
      if (0 == ::VirtualQuery((LPCVOID)curr_addr, &info, sizeof(info))) {

        // jmp_from should be allocated already!
        __debugbreak();

      }


      Report("Cur page: at %llx, region_size: %llx\n", info.BaseAddress, info.RegionSize);

      switch (info.State) {
      case MEM_FREE:
        Report("State: Free\n");
        break;
      case MEM_RESERVE:
        Report("State: Reserve\n");
        break;
      case MEM_COMMIT:
        Report("State: COmmit\n");
        break;
      default:
        __debugbreak();
      }


      if (info.State == MEM_FREE) { // 0x10000

                                    // acquire it
        uptr free_begin = (uptr)info.BaseAddress;

        Report("free_begin before roundup: %llx\n", free_begin);

        // check if enough space for one alloc_granularity

        // round up to next alloc_granularity
        uptr next_alloc_begin = ((free_begin - 1) & ~(alloc_granularity - 1)) + alloc_granularity;
        uptr next_alloc_end = next_alloc_begin + alloc_granularity;

        if (free_begin + (uptr)info.RegionSize < next_alloc_end) {
          Report("Not enough size 1, with region_size:%llx, cannot reach: %llx\n", info.RegionSize, next_alloc_end);
        }
        else {


          Report("Trying to reserve at: %llx, for size: %llx, with MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE\n", next_alloc_begin, alloc_granularity);


          LPVOID alloced = ::VirtualAlloc((LPVOID)next_alloc_begin, alloc_granularity, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
          //LPVOID alloced = ::VirtualAlloc((LPVOID)next_alloc_begin, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
          // LPVOID alloced = ::VirtualAlloc((LPVOID)free_begin, alloc_granularity, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

          if (alloced == NULL) {

            uptr error = (uptr)GetLastError();
            Report("Last errro code in decimal: %lld\n", error);
            __debugbreak();
          }
          else {
            Report("Free page allocated at: %llx, free_begin was: %llx\n", (uptr)alloced, free_begin);

            //query back

            MEMORY_BASIC_INFORMATION query;
            if (0 == ::VirtualQuery((LPCVOID)alloced, &query, sizeof(query))) {

              // jmp_from should be allocated already!
              __debugbreak();

            }
            else {
              Report("I was allocated at: %llx, given region_size: %llx\n", (uptr)query.AllocationBase, (uptr)query.RegionSize);
            }


          }





          pointers_page = alloced;

          //found it 
          Report("Found it!!!\n");
          break;
        }
      }


      uptr cur_region_size = info.RegionSize;

      curr_addr += cur_region_size;


      if (curr_addr >= next_begin + kLimitRange) {
        Report("Failed to locate pointer page!\n");
        __debugbreak();
      }

    }

    Report("out of loop..\n");
}








  // Emit an indirect jump through immediately following bytes:
  // jmp_from:
  //   jmp [rip - 8]
  //   .quad to
  // Store the address.
  //char *indirect_target = jmp_from - 8;

char *indirect_target = (char*)pointers_page + (pointers_counter * 8);
pointers_counter++;

if (pointers_counter >= (alloc_granularity >> 3)) {
  __debugbreak();
}

ptrdiff_t distance =  indirect_target - jmp_from;
if (distance > INT32_MAX || distance < INT32_MIN) {
  __debugbreak();
}

   
  *(uptr*)indirect_target = (uptr)to;
  // Write the indirect jump.
  WriteIndirectJumpInstruction(jmp_from, indirect_target);
#else
  WriteJumpInstruction(jmp_from, to);
#endif
}

static char *GetMemoryForTrampoline(size_t size) {
  // Trampolines are allocated from a common pool.
  const int POOL_SIZE = 1024;
  static char *pool = NULL;
  static size_t pool_used = 0;
  if (!pool) {
    pool = (char *)VirtualAlloc(NULL, POOL_SIZE, MEM_RESERVE | MEM_COMMIT,
                                PAGE_EXECUTE_READWRITE);
    // FIXME: Might want to apply PAGE_EXECUTE_READ access after all the
    // interceptors are in place.
    if (!pool)
      return NULL;
    _memset(pool, 0xCC /* int 3 */, POOL_SIZE);
  }

  if (pool_used + size > POOL_SIZE)
    return NULL;

  char *ret = pool + pool_used;
  pool_used += size;
  return ret;
}

// Returns 0 on error.
static size_t RoundUpToInstrBoundary(size_t size, char *code) {
#if SANITIZER_WINDOWS64
  // Win64 RoundUpToInstrBoundary is a work in progress.
  size_t cursor = 0;
  while (cursor < size) {
    switch (code[cursor]) {
      case '\x57':  // 57 : push rdi
        cursor++;
        continue;
      case '\x90':  // 90 : nop
        cursor++;
        continue;
      case '\xb8':  // b8 XX XX XX XX : mov eax, XX XX XX XX
        cursor += 5;
        continue;
    }

    switch (*(u16*)(code + cursor)) {  // NOLINT
      case 0x5540:  // 40 55 : rex push rbp
      case 0x5340:  // 40 53 : rex push rbx
        cursor += 2;
        continue;
    }

    switch (0x00FFFFFF & *(u32*)(code + cursor)) {
      case 0xc18b48:    // 48 8b c1 : mov rax, rcx
      case 0xc48b48:    // 48 8b c4 : mov rax, rsp
      case 0xd9f748:    // 48 f7 d9 : neg rcx
      case 0xd12b48:    // 48 2b d1 : sub rdx, rcx
      case 0x07c1f6:    // f6 c1 07 : test cl, 0x7
      case 0xc0854d:    // 4d 85 c0 : test r8, r8
      case 0xc2b60f:    // 0f b6 c2 : movzx eax, dl
      case 0xc03345:    // 45 33 c0 : xor r8d, r8d
      case 0xd98b4c:    // 4c 8b d9 : mov r11, rcx
      case 0xd28b4c:    // 4c 8b d2 : mov r10, rdx
      case 0xd2b60f:    // 0f b6 d2 : movzx edx, dl
      case 0xca2b48:    // 48 2b ca : sub rcx, rdx
      case 0x10b70f:    // 0f b7 10 : movzx edx, WORD PTR [rax]
      case 0xc00b4d:    // 3d 0b c0 : or r8, r8
      case 0xd18b48:    // 48 8b d1 : mov rdx, rcx
      case 0xdc8b4c:    // 4c 8b dc : mov r11,rsp
      case 0xd18b4c:    // 4c 8b d1 : mov r10, rcx
        cursor += 3;
        continue;

      case 0xec8348:    // 48 83 ec XX : sub rsp, 0xXX
      case 0xf88349:    // 49 83 f8 XX : cmp r8, XX
      case 0x588948:    // 48 89 58 XX : mov QWORD PTR[rax + XX], rbx
        cursor += 4;
        continue;

      case 0x058b48:    // 48 8b 05 XX XX XX XX
                        // = mov rax, QWORD PTR [rip+ 0xXXXXXXXX]
      case 0x25ff48:    // 48 ff 25 XX XX XX XX
                        // = rex.W jmp QWORD PTR [rip + 0xXXXXXXXX]
        cursor += 7;
        continue;
    }

    switch (*(u32*)(code + cursor)) {
      case 0x24448b48:  // 48 8b 44 24 XX : mov rax, qword ptr [rsp + 0xXX]
        cursor += 5;
        continue;
    }

    // Check first 5 bytes.
    switch (0xFFFFFFFFFFull & *(u64*)(code + cursor)) {
      case 0x08245c8948:    // 48 89 5c 24 08 : mov QWORD PTR [rsp+0x8], rbx
      case 0x1024748948:    // 48 89 74 24 10 : mov QWORD PTR [rsp+0x10], rsi
        cursor += 5;
        continue;
    }

    // Check 8 bytes.
    switch (*(u64*)(code + cursor)) {
      case 0x90909090909006EBull:  // JMP +6,  6x NOP
        cursor += 8;
        continue;
    }

    // Unknown instructions!
    __debugbreak();
  }

  return cursor;
#else
  size_t cursor = 0;
  while (cursor < size) {
    switch (code[cursor]) {
      case '\xE8':  // E8 XX XX XX XX = call <func>
      case '\xE9':  // E9 XX XX XX XX = jmp <label>
      case '\xC3':  // C3 = ret
      case '\xEB':  // EB XX = jmp XX (short jump)
      case '\x70':  // 7X YY = jx XX (short conditional jump)
      case '\x71':
      case '\x72':
      case '\x73':
      case '\x74':
      case '\x75':
      case '\x76':
      case '\x77':
      case '\x78':
      case '\x79':
      case '\x7A':
      case '\x7B':
      case '\x7C':
      case '\x7D':
      case '\x7E':
      case '\x7F':
        return 0;

      case '\x50':  // push eax
      case '\x51':  // push ecx
      case '\x52':  // push edx
      case '\x53':  // push ebx
      case '\x54':  // push esp
      case '\x55':  // push ebp
      case '\x56':  // push esi
      case '\x57':  // push edi
      case '\x5D':  // pop ebp
        cursor++;
        continue;
      case '\x6A':  // 6A XX = push XX
        cursor += 2;
        continue;
      case '\xB8':  // B8 XX YY ZZ WW = mov eax, WWZZYYXX
        cursor += 5;
        continue;
    }
    switch (*(u16*)(code + cursor)) {  // NOLINT
      case 0xFF8B:  // 8B FF = mov edi, edi
      case 0xEC8B:  // 8B EC = mov ebp, esp
      case 0xC033:  // 33 C0 = xor eax, eax
      case 0xC933:  // 33 C9 = xor ecx, ecx
        cursor += 2;
        continue;
      case 0x458B:  // 8B 45 XX = mov eax, dword ptr [ebp+XXh]
      case 0x5D8B:  // 8B 5D XX = mov ebx, dword ptr [ebp+XXh]
      case 0x7D8B:  // 8B 7D XX = mov edi, dword ptr [ebp+XXh]
      case 0xEC83:  // 83 EC XX = sub esp, XX
      case 0x75FF:  // FF 75 XX = push dword ptr [ebp+XXh]
        cursor += 3;
        continue;
      case 0xC1F7:  // F7 C1 XX YY ZZ WW = test ecx, WWZZYYXX
      case 0x25FF:  // FF 25 XX YY ZZ WW = jmp dword ptr ds:[WWZZYYXX]
        cursor += 6;
        continue;
      case 0x3D83:  // 83 3D XX YY ZZ WW TT = cmp TT, WWZZYYXX
        cursor += 7;
        continue;
      case 0x7D83:  // 83 7D XX YY = cmp dword ptr [ebp+XXh], YY
        cursor += 4;
        continue;
    }
    switch (0x00FFFFFF & *(u32*)(code + cursor)) {
      case 0x24448A:  // 8A 44 24 XX = mov eal, dword ptr [esp+XXh]
      case 0x24448B:  // 8B 44 24 XX = mov eax, dword ptr [esp+XXh]
      case 0x244C8B:  // 8B 4C 24 XX = mov ecx, dword ptr [esp+XXh]
      case 0x24548B:  // 8B 54 24 XX = mov edx, dword ptr [esp+XXh]
      case 0x24748B:  // 8B 74 24 XX = mov esi, dword ptr [esp+XXh]
      case 0x247C8B:  // 8B 7C 24 XX = mov edi, dword ptr [esp+XXh]
        cursor += 4;
        continue;
    }
    switch (*(u32*)(code + cursor)) {
      case 0x2444B60F:  // 0F B6 44 24 XX = movzx eax, byte ptr [esp+XXh]
        cursor += 5;
        continue;
    }

    // Unknown instruction!
    // FIXME: Unknown instruction failures might happen when we add a new
    // interceptor or a new compiler version. In either case, they should result
    // in visible and readable error messages. However, merely calling abort()
    // leads to an infinite recursion in CheckFailed.
    // Do we have a good way to abort with an error message here?
    __debugbreak();
    return 0;
  }

  return cursor;
#endif
}

bool OverrideFunction(uptr old_func, uptr new_func, uptr *orig_old_func) {
  static int counter = 0;
  counter++;
  //break at 27th
  if (counter == 27) {
    __debugbreak();
  }
  __sanitizer::Report("counteter: %d, overriding old_func at addr: %llx\n", counter,
                      (old_func));
  // Function overriding works basically like this:
  // On Win32, We write "jmp <new_func>" (5 bytes) at the beginning of
  // the 'old_func' to override it.
  // On Win64, We write "jmp [rip -8]" (6 bytes) at the beginning of
  // the 'old_func' to override it, and use 8 bytes of data to store
  // the full 64-bit address for new_func.
  // We might want to be able to execute the original 'old_func' from the
  // wrapper, in this case we need to keep the leading 5+ (6+ on Win64)
  // bytes ('head') of the original code somewhere with a "jmp <old_func+head>".
  // We call these 'head'+5/6 bytes of instructions a "trampoline".
  char *old_bytes = (char *)old_func;

#if SANITIZER_WINDOWS64
  size_t kHeadMin = 6;  // The minimum size of the head to contain the 'jmp'.
  size_t kTrampolineJumpSize = 14;  // The total bytes used at the end of
                                    // trampoline for jumping back to the
                                    // remains of original function.
  size_t kExtraPrevBytes = 8;  // The extra bytes we need to mark READWRITE for
                               // page access, that is preceeding the begin
                               // of function.
#else
  size_t kHeadMin = 5;
  size_t kTrampolineJumpSize = 5;
  size_t kExtraPrevBytes = 0;
#endif
  size_t head = kHeadMin;
  if (orig_old_func) {
    // Find out the number of bytes of the instructions we need to copy
    // to the trampoline and store it in 'head'.
    head = RoundUpToInstrBoundary(kHeadMin, old_bytes);
    if (!head)
      return false;

    // Put the needed instructions into the trampoline bytes.
    char *trampoline = GetMemoryForTrampoline(head + kTrampolineJumpSize);
    if (!trampoline)
      return false;
    _memcpy(trampoline, old_bytes, head);
    WriteTrampolineJumpInstruction(trampoline + head, old_bytes + head);
    *orig_old_func = (uptr)trampoline;
  }

  // Now put the "jmp <new_func>" instruction at the original code location.
  // We should preserve the EXECUTE flag as some of our own code might be
  // located in the same page (sic!).  FIXME: might consider putting the
  // __interception code into a separate section or something?
  DWORD old_prot, unused_prot;
  // TODO(wwchrome): Properly handle access violations when finding a safe
  // region to store the indirect jump target address.
  // Need to mark extra 8 bytes for Win64 because jmp [rip -8]
  if (!VirtualProtect((void *)(old_bytes - kExtraPrevBytes),
                      head + kExtraPrevBytes, PAGE_EXECUTE_READWRITE,
                      &old_prot))
    return false;

  WriteInterceptorJumpInstruction(old_bytes, (char *)new_func);
  _memset(old_bytes + kHeadMin, 0xCC /* int 3 */, head - kHeadMin);

  // Restore the original permissions.
  if (!VirtualProtect((void *)(old_bytes - kExtraPrevBytes),
                      head + kExtraPrevBytes, old_prot, &unused_prot))
    return false;  // not clear if this failure bothers us.

  return true;
}

static void **InterestingDLLsAvailable() {
  static const char *InterestingDLLs[] = {
      "kernel32.dll",
      "msvcr110.dll",      // VS2012
      "msvcr120.dll",      // VS2013
      "vcruntime140.dll",  // VS2015
      "ucrtbase.dll",      // Universal CRT
      // NTDLL should go last as it exports some functions that we should
      // override in the CRT [presumably only used internally].
      "ntdll.dll", NULL};
  static void *result[ARRAY_SIZE(InterestingDLLs)] = { 0 };
  if (!result[0]) {
    for (size_t i = 0, j = 0; InterestingDLLs[i]; ++i) {
      if (HMODULE h = GetModuleHandleA(InterestingDLLs[i]))
        result[j++] = (void *)h;
    }
  }
  return &result[0];
}

namespace {
// Utility for reading loaded PE images.
template <typename T> class RVAPtr {
 public:
  RVAPtr(void *module, uptr rva)
      : ptr_(reinterpret_cast<T *>(reinterpret_cast<char *>(module) + rva)) {}
  operator T *() { return ptr_; }
  T *operator->() { return ptr_; }
  T *operator++() { return ++ptr_; }

 private:
  T *ptr_;
};
} // namespace

// Internal implementation of GetProcAddress. At least since Windows 8,
// GetProcAddress appears to initialize DLLs before returning function pointers
// into them. This is problematic for the sanitizers, because they typically
// want to intercept malloc *before* MSVCRT initializes. Our internal
// implementation walks the export list manually without doing initialization.
uptr InternalGetProcAddress(void *module, const char *func_name) {
  // Check that the module header is full and present.
  RVAPtr<IMAGE_DOS_HEADER> dos_stub(module, 0);
  RVAPtr<IMAGE_NT_HEADERS> headers(module, dos_stub->e_lfanew);
  if (!module || dos_stub->e_magic != IMAGE_DOS_SIGNATURE || // "MZ"
      headers->Signature != IMAGE_NT_SIGNATURE ||           // "PE\0\0"
      headers->FileHeader.SizeOfOptionalHeader <
          sizeof(IMAGE_OPTIONAL_HEADER)) {
    return 0;
  }

  IMAGE_DATA_DIRECTORY *export_directory =
      &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  RVAPtr<IMAGE_EXPORT_DIRECTORY> exports(module,
                                         export_directory->VirtualAddress);
  RVAPtr<DWORD> functions(module, exports->AddressOfFunctions);
  RVAPtr<DWORD> names(module, exports->AddressOfNames);
  RVAPtr<WORD> ordinals(module, exports->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exports->NumberOfNames; i++) {
    RVAPtr<char> name(module, names[i]);
    if (!strcmp(func_name, name)) {
      DWORD index = ordinals[i];
      RVAPtr<char> func(module, functions[index]);
      return (uptr)(char *)func;
    }
  }

  return 0;
}

static bool GetFunctionAddressInDLLs(const char *func_name, uptr *func_addr) {
  *func_addr = 0;
  void **DLLs = InterestingDLLsAvailable();
  for (size_t i = 0; *func_addr == 0 && DLLs[i]; ++i)
    *func_addr = InternalGetProcAddress(DLLs[i], func_name);
  return (*func_addr != 0);
}

bool OverrideFunction(const char *name, uptr new_func, uptr *orig_old_func) {
  uptr orig_func;
  if (!GetFunctionAddressInDLLs(name, &orig_func))
    return false;
  return OverrideFunction(orig_func, new_func, orig_old_func);
}

bool OverrideImportedFunction(const char *module_to_patch,
                              const char *imported_module,
                              const char *function_name, uptr new_function,
                              uptr *orig_old_func) {
  HMODULE module = GetModuleHandleA(module_to_patch);
  if (!module)
    return false;

  // Check that the module header is full and present.
  RVAPtr<IMAGE_DOS_HEADER> dos_stub(module, 0);
  RVAPtr<IMAGE_NT_HEADERS> headers(module, dos_stub->e_lfanew);
  if (!module || dos_stub->e_magic != IMAGE_DOS_SIGNATURE || // "MZ"
      headers->Signature != IMAGE_NT_SIGNATURE ||           // "PE\0\0"
      headers->FileHeader.SizeOfOptionalHeader <
          sizeof(IMAGE_OPTIONAL_HEADER)) {
    return false;
  }

  IMAGE_DATA_DIRECTORY *import_directory =
      &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  // Iterate the list of imported DLLs. FirstThunk will be null for the last
  // entry.
  RVAPtr<IMAGE_IMPORT_DESCRIPTOR> imports(module,
                                          import_directory->VirtualAddress);
  for (; imports->FirstThunk != 0; ++imports) {
    RVAPtr<const char> modname(module, imports->Name);
    if (_stricmp(&*modname, imported_module) == 0)
      break;
  }
  if (imports->FirstThunk == 0)
    return false;

  // We have two parallel arrays: the import address table (IAT) and the table
  // of names. They start out containing the same data, but the loader rewrites
  // the IAT to hold imported addresses and leaves the name table in
  // OriginalFirstThunk alone.
  RVAPtr<IMAGE_THUNK_DATA> name_table(module, imports->OriginalFirstThunk);
  RVAPtr<IMAGE_THUNK_DATA> iat(module, imports->FirstThunk);
  for (; name_table->u1.Ordinal != 0; ++name_table, ++iat) {
    if (!IMAGE_SNAP_BY_ORDINAL(name_table->u1.Ordinal)) {
      RVAPtr<IMAGE_IMPORT_BY_NAME> import_by_name(
          module, name_table->u1.ForwarderString);
      const char *funcname = &import_by_name->Name[0];
      if (strcmp(funcname, function_name) == 0)
        break;
    }
  }
  if (name_table->u1.Ordinal == 0)
    return false;

  // Now we have the correct IAT entry. Do the swap. We have to make the page
  // read/write first.
  if (orig_old_func)
    *orig_old_func = iat->u1.AddressOfData;
  DWORD old_prot, unused_prot;
  if (!VirtualProtect(&iat->u1.AddressOfData, 4, PAGE_EXECUTE_READWRITE,
                      &old_prot))
    return false;
  iat->u1.AddressOfData = new_function;
  if (!VirtualProtect(&iat->u1.AddressOfData, 4, old_prot, &unused_prot))
    return false;  // Not clear if this failure bothers us.
  return true;
}

}  // namespace __interception

#endif  // _WIN32
