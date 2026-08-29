#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "MinHook.h"
#include "NativeGameTypes.hpp"

namespace
{
constexpr std::uint32_t kMagic = 0x44465348; // HSFD
constexpr std::uint32_t kVersion = 3;
constexpr std::size_t kMaxCreators = 16;
constexpr std::uint32_t kProtectedPoolCapacity = 512U * 512U;
constexpr std::uint32_t kProtectedPoolSafeUsed = kProtectedPoolCapacity - 62144U;
constexpr LONG kMaxExtraCreatorsPerSecond = 800;

enum RuntimeStatus : std::uint32_t
{
    STATUS_WAITING = 0,
    STATUS_RESOLVING = 1,
    STATUS_READY = 2,
    STATUS_ERROR = 3,
    STATUS_UNLOADING = 4,
};

#pragma pack(push, 8)
struct SharedState
{
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t size;
    volatile LONG status;
    volatile LONG enabled;
    volatile LONG shutdown;
    volatile LONG lastError;
    volatile LONG protectedPoolUsed;
    alignas(8) double multiplier;
    std::uint64_t depthAddress;
    std::uint64_t layerAddress;
    std::uint32_t creatorCount;
    std::int32_t creatorIndices[kMaxCreators];
    volatile LONG capacitySkips;
    volatile LONG64 hostHeartbeat;
    volatile LONG64 depthCalls;
    volatile LONG64 layerCalls;
    volatile LONG64 creatorMatches;
    volatile LONG64 extraCreators;
    volatile LONG64 hookGeneration;
    char message[256];
};
#pragma pack(pop)

static_assert(offsetof(SharedState, multiplier) == 32);
static_assert(offsetof(SharedState, hostHeartbeat) == 128);
static_assert(offsetof(SharedState, message) == 176);
static_assert(sizeof(SharedState) == 432);

struct MemoryRegion
{
    const std::uint8_t* base;
    std::size_t size;
};

HMODULE gSelf = nullptr;
HANDLE gMapping = nullptr;
SharedState* gState = nullptr;
YYGMLRoutine gOriginalDepth = nullptr;
YYGMLRoutine gOriginalLayer = nullptr;
using RealRValueFn = double (*)(const RValue*);
using FreeRValueFn = void (*)(RValue*);
RealRValueFn gRealRValue = nullptr;
FreeRValueFn gFreeRValue = nullptr;
std::array<int, kMaxCreators> gCreators{};
std::size_t gCreatorCount = 0;
std::atomic<std::uint64_t> gFractionSequence{0};
thread_local bool gInsideDensityCopy = false;
const std::uint8_t* gProtectedPoolEntries = nullptr;
LONG gPoolScanCountdown = 0;
ULONGLONG gRateWindowStart = 0;
LONG gRateWindowCopies = 0;

constexpr std::array<const char*, 7> kCreatorNames{
    "Enemy_Creator_Ambush_obj",
    "Enemy_Creator_Ancient_obj",
    "Enemy_Creator_Champion_obj",
    "Enemy_Creator_Colossal_Chest_obj",
    "Enemy_Creator_Legion_obj",
    "Enemy_Creator_Miniboss_obj",
    "Enemy_Creator_obj",
};

void SetMessage(const char* message)
{
    if (!gState) return;
    strncpy_s(gState->message, message ? message : "", _TRUNCATE);
}

void Fail(DWORD code, const char* message)
{
    if (!gState) return;
    InterlockedExchange(&gState->lastError, static_cast<LONG>(code));
    SetMessage(message);
    InterlockedExchange(&gState->status, STATUS_ERROR);
}

bool IsReadableProtection(DWORD protection)
{
    if (protection & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    const DWORD base = protection & 0xFF;
    return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
           base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

bool IsExecutableAddress(std::uintptr_t address)
{
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info))) return false;
    if (info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    const DWORD base = info.Protect & 0xFF;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool SafeEqual(const void* left, const void* right, std::size_t size);

bool InitializeProtectedPoolGuard()
{
    const HMODULE module = GetModuleHandleW(L"ac_dll_gm.dll");
    if (!module) return false;
    const auto* base = reinterpret_cast<const std::uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.TimeDateStamp != 0x6A844148U ||
        nt->OptionalHeader.SizeOfImage != 0x00A0A000U)
        return false;
    constexpr std::array<std::uint8_t, 26> setSignature{
        0x48, 0x8B, 0x03,
        0x4C, 0x8D, 0x4C, 0x24, 0x20,
        0x66, 0x48, 0x0F, 0x7E, 0xF1,
        0x41, 0xB8, 0x02, 0x00, 0x00, 0x00,
        0x48, 0x33, 0x4B, 0x18,
        0x48, 0x89, 0x08
    };
    if (!SafeEqual(base + 0x140D, setSignature.data(), setSignature.size())) return false;
    gProtectedPoolEntries = base + 0x5688;
    return true;
}

LONG CountProtectedPoolUsed()
{
    if (!gProtectedPoolEntries) return 0;
    LONG used = 0;
    __try {
        for (std::uint32_t page = 0; page < 512U; ++page) {
            const auto* entries = gProtectedPoolEntries + page * 0x5008U;
            for (std::uint32_t entry = 0; entry < 512U; ++entry) {
                if (*(entries + entry * 0x28U + 0x10U) != 0) ++used;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        gProtectedPoolEntries = nullptr;
        return 0;
    }
    if (gState) InterlockedExchange(&gState->protectedPoolUsed, used);
    return used;
}

bool ReserveDensityCapacity()
{
    const ULONGLONG now = GetTickCount64();
    if (!gRateWindowStart || now - gRateWindowStart >= 1000ULL) {
        gRateWindowStart = now;
        gRateWindowCopies = 0;
    }
    if (gRateWindowCopies >= kMaxExtraCreatorsPerSecond) return false;

    if (gProtectedPoolEntries) {
        if (gPoolScanCountdown <= 0) {
            const LONG used = CountProtectedPoolUsed();
            gPoolScanCountdown = 8;
            if (used >= static_cast<LONG>(kProtectedPoolSafeUsed)) return false;
        }
        --gPoolScanCountdown;
    }
    ++gRateWindowCopies;
    return true;
}

// GameMaker allocates and releases runner heaps from other threads while the
// catalog is being inspected. VirtualQuery can therefore be true immediately
// before a page disappears. Keep raw reads in tiny SEH-only helpers so a stale
// region is skipped instead of taking down the game process.
bool SafeFindByte(
    const std::uint8_t* base,
    std::size_t size,
    unsigned char target,
    const std::uint8_t** found)
{
    __try {
        *found = static_cast<const std::uint8_t*>(std::memchr(base, target, size));
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *found = nullptr;
        return false;
    }
}

bool SafeEqual(const void* left, const void* right, std::size_t size)
{
    __try {
        return std::memcmp(left, right, size) == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SafeReadPointer(std::uintptr_t address, std::uintptr_t* value)
{
    __try {
        *value = *reinterpret_cast<const std::uintptr_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *value = 0;
        return false;
    }
}

bool SafeReadInt32(std::uintptr_t address, std::int32_t* value)
{
    __try {
        *value = *reinterpret_cast<const std::int32_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *value = 0;
        return false;
    }
}

std::vector<MemoryRegion> PrivateReadableRegions()
{
    std::vector<MemoryRegion> regions;
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto cursor = reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info))) break;
        const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE &&
            IsReadableProtection(info.Protect) && info.RegionSize > 0 &&
            info.RegionSize <= 64ULL * 1024ULL * 1024ULL) {
            regions.push_back({reinterpret_cast<const std::uint8_t*>(base), info.RegionSize});
        }
        const auto next = base + info.RegionSize;
        if (next <= cursor) break;
        cursor = next;
    }
    return regions;
}

std::vector<std::uintptr_t> FindExactInRange(
    const std::uint8_t* base, std::size_t size, const char* text)
{
    std::vector<std::uintptr_t> hits;
    const std::size_t length = std::strlen(text) + 1;
    if (!base || size < length) return hits;
    const auto* cursor = base;
    const auto* end = base + size - length + 1;
    while (cursor < end) {
        const std::uint8_t* next = nullptr;
        if (!SafeFindByte(cursor, end - cursor, static_cast<unsigned char>(text[0]), &next) || !next)
            break;
        cursor = next;
        if (SafeEqual(cursor, text, length))
            hits.push_back(reinterpret_cast<std::uintptr_t>(cursor));
        ++cursor;
    }
    return hits;
}

std::vector<std::uintptr_t> FindExactInRegions(
    const std::vector<MemoryRegion>& regions, const char* text)
{
    std::vector<std::uintptr_t> hits;
    for (const auto& region : regions) {
        auto found = FindExactInRange(region.base, region.size, text);
        hits.insert(hits.end(), found.begin(), found.end());
    }
    return hits;
}

std::vector<std::uintptr_t> FindPointerHits(
    const std::vector<MemoryRegion>& regions,
    const std::vector<std::uintptr_t>& needles)
{
    std::vector<std::uintptr_t> hits;
    if (needles.empty()) return hits;
    for (const auto& region : regions) {
        const auto start = (reinterpret_cast<std::uintptr_t>(region.base) + 7ULL) & ~7ULL;
        const auto end = reinterpret_cast<std::uintptr_t>(region.base) + region.size;
        for (auto cursor = start; cursor + sizeof(std::uintptr_t) <= end; cursor += 8) {
            const auto value = *reinterpret_cast<const std::uintptr_t*>(cursor);
            if (std::find(needles.begin(), needles.end(), value) != needles.end())
                hits.push_back(cursor);
        }
    }
    return hits;
}

std::vector<std::pair<std::uintptr_t, std::uintptr_t>> FindPointerPairs(
    const std::vector<MemoryRegion>& regions,
    std::vector<std::uintptr_t> needles)
{
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> hits;
    if (needles.empty()) return hits;
    std::sort(needles.begin(), needles.end());
    needles.erase(std::unique(needles.begin(), needles.end()), needles.end());
    for (const auto& region : regions) {
        const auto start = (reinterpret_cast<std::uintptr_t>(region.base) + 7ULL) & ~7ULL;
        const auto end = reinterpret_cast<std::uintptr_t>(region.base) + region.size;
        for (auto cursor = start; cursor + sizeof(std::uintptr_t) <= end; cursor += 8) {
            std::uintptr_t value = 0;
            if (!SafeReadPointer(cursor, &value)) break;
            if (std::binary_search(needles.begin(), needles.end(), value))
                hits.emplace_back(cursor, value);
        }
    }
    return hits;
}

bool ModuleRange(HMODULE module, const std::uint8_t*& base, std::size_t& size)
{
    if (!module) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const std::uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    base = reinterpret_cast<const std::uint8_t*>(module);
    size = nt->OptionalHeader.SizeOfImage;
    return size > 0;
}

std::uintptr_t ResolveRealRValue(const std::uint8_t* moduleBase, std::size_t moduleSize)
{
    // GameMaker's REAL_RValue fast path is emitted twice next to each other:
    // one runner helper followed 0xC0 bytes later by the public converter used
    // by RValue::ToDouble. A third copy can exist in generated game code, so a
    // single byte-pattern hit is deliberately not accepted. This relationship
    // is stable across the verified S10 runner builds and avoids a fixed RVA.
    constexpr std::array<std::uint8_t, 14> signature{
        0xF7, 0x41, 0x0C, 0xFF, 0xFF, 0xFF, 0x00,
        0x75, 0x05, 0xF2, 0x0F, 0x10, 0x01, 0xC3,
    };
    std::vector<std::uintptr_t> hits;
    const auto* end = moduleBase + moduleSize;
    for (const auto* cursor = moduleBase; cursor + signature.size() <= end;) {
        const auto* hit = std::search(cursor, end, signature.begin(), signature.end());
        if (hit == end) break;
        hits.push_back(reinterpret_cast<std::uintptr_t>(hit));
        cursor = hit + 1;
    }
    std::vector<std::uintptr_t> candidates;
    for (const auto hit : hits) {
        if (std::find(hits.begin(), hits.end(), hit - 0xC0ULL) != hits.end())
            candidates.push_back(hit);
    }
    if (candidates.size() != 1 || !IsExecutableAddress(candidates.front())) return 0;
    return candidates.front();
}

std::uintptr_t ResolveFreeRValue(const std::uint8_t* moduleBase, std::size_t moduleSize)
{
    // FREE_RValue has one stable runner implementation. The relative CALL in
    // the middle changes per build, so match the invariant prefix/suffix and
    // deliberately skip its four-byte displacement.
    constexpr std::array<std::uint8_t, 31> prefix{
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B,
        0xD9, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x8B, 0x49,
        0x0C, 0x83, 0xE1, 0x1F, 0xD3, 0xE2, 0xF6, 0xC2,
        0x46, 0x74, 0x08, 0x48, 0x8B, 0xCB, 0xE8,
    };
    constexpr std::array<std::uint8_t, 21> suffix{
        0x33, 0xC0, 0xC7, 0x43, 0x0C, 0x05, 0x00, 0x00,
        0x00, 0x48, 0x89, 0x03, 0x89, 0x43, 0x08, 0x48,
        0x83, 0xC4, 0x20, 0x5B, 0xC3,
    };
    std::vector<std::uintptr_t> candidates;
    const auto* end = moduleBase + moduleSize;
    const auto required = prefix.size() + 4 + suffix.size();
    for (const auto* cursor = moduleBase; cursor + required <= end;) {
        const auto* hit = std::search(cursor, end, prefix.begin(), prefix.end());
        if (hit == end || hit + required > end) break;
        if (std::equal(suffix.begin(), suffix.end(), hit + prefix.size() + 4))
            candidates.push_back(reinterpret_cast<std::uintptr_t>(hit));
        cursor = hit + 1;
    }
    if (candidates.size() != 1 || !IsExecutableAddress(candidates.front())) return 0;
    return candidates.front();
}

std::uintptr_t ResolveBuiltin(
    const std::uint8_t* moduleBase,
    std::size_t moduleSize,
    const std::vector<MemoryRegion>& regions,
    const char* name)
{
    const auto strings = FindExactInRange(moduleBase, moduleSize, name);
    for (const auto address : strings) {
        if (address + 72 <= reinterpret_cast<std::uintptr_t>(moduleBase) + moduleSize) {
            const auto routine = *reinterpret_cast<const std::uintptr_t*>(address + 64);
            if (IsExecutableAddress(routine)) return routine;
        }
    }
    const auto refs = FindPointerHits(regions, strings);
    for (const auto row : refs) {
        const auto routine = *reinterpret_cast<const std::uintptr_t*>(row + 8);
        if (IsExecutableAddress(routine)) return routine;
    }
    return 0;
}

bool ResolveCreatorIndices(const std::vector<MemoryRegion>& regions)
{
    std::vector<std::uintptr_t> nameAddresses;
    for (const char* name : kCreatorNames) {
        const auto hits = FindExactInRegions(regions, name);
        nameAddresses.insert(nameAddresses.end(), hits.begin(), hits.end());
    }
    if (nameAddresses.size() < kCreatorNames.size()) return false;

    const auto resourceFields = FindPointerHits(regions, nameAddresses);
    if (resourceFields.empty()) return false;
    const auto resourceRefs = FindPointerHits(regions, resourceFields);
    for (const auto reference : resourceRefs) {
        if (reference < 0x18) continue;
        const auto objectIndex = *reinterpret_cast<const std::int32_t*>(reference - 8);
        const auto nextNode = *reinterpret_cast<const std::uintptr_t*>(reference - 16);
        // The runner table itself can produce small scalar false positives
        // (observed 0 and 1) when a name pointer is referenced by bookkeeping
        // data. Hero Siege enemy resources live well above the built-in range.
        if (objectIndex < 100 || objectIndex >= 100000) continue;
        if (nextNode != 0 && (nextNode < 0x10000 || nextNode >= 0x0000800000000000ULL)) continue;
        if (std::find(gCreators.begin(), gCreators.begin() + gCreatorCount, objectIndex) !=
            gCreators.begin() + gCreatorCount)
            continue;
        if (gCreatorCount < gCreators.size()) gCreators[gCreatorCount++] = objectIndex;
    }
    std::sort(gCreators.begin(), gCreators.begin() + gCreatorCount);
    return gCreatorCount >= kCreatorNames.size();
}

bool ResolveRuntime(
    const std::uint8_t* moduleBase,
    std::size_t moduleSize,
    const std::vector<MemoryRegion>& regions,
    std::uintptr_t& depth,
    std::uintptr_t& layer)
{
    const auto realRValue = ResolveRealRValue(moduleBase, moduleSize);
    const auto freeRValue = ResolveFreeRValue(moduleBase, moduleSize);
    if (!realRValue || !freeRValue) return false;
    gRealRValue = reinterpret_cast<RealRValueFn>(realRValue);
    gFreeRValue = reinterpret_cast<FreeRValueFn>(freeRValue);

    // Search each memory family once. The first implementation rescanned the
    // entire GameMaker heap once per name and took over 30 seconds on large
    // sessions. This combined catalog pass stays adaptive without that delay.
    std::array<std::vector<std::uintptr_t>, 2> builtinStrings;
    const std::array<const char*, 2> builtinNames{
        "instance_create_depth", "instance_create_layer"};
    const auto* moduleEnd = moduleBase + moduleSize;
    for (const auto* cursor = moduleBase; cursor < moduleEnd;) {
        const std::uint8_t* next = nullptr;
        if (!SafeFindByte(cursor, moduleEnd - cursor, 'i', &next) || !next) break;
        cursor = next;
        for (std::size_t index = 0; index < builtinNames.size(); ++index) {
            const auto length = std::strlen(builtinNames[index]) + 1;
            if (cursor + length <= moduleEnd &&
                SafeEqual(cursor, builtinNames[index], length))
                builtinStrings[index].push_back(reinterpret_cast<std::uintptr_t>(cursor));
        }
        ++cursor;
    }

    std::vector<std::uintptr_t> creatorNameAddresses;
    for (const auto& region : regions) {
        const auto* regionEnd = region.base + region.size;
        for (const auto* cursor = region.base; cursor < regionEnd;) {
            const std::uint8_t* next = nullptr;
            if (!SafeFindByte(cursor, regionEnd - cursor, 'E', &next) || !next) break;
            cursor = next;
            for (const char* name : kCreatorNames) {
                const auto length = std::strlen(name) + 1;
                if (cursor + length <= regionEnd && SafeEqual(cursor, name, length)) {
                    creatorNameAddresses.push_back(reinterpret_cast<std::uintptr_t>(cursor));
                    break;
                }
            }
            ++cursor;
        }
    }
    if (creatorNameAddresses.size() < kCreatorNames.size()) return false;

    // Some runner builds keep an inline 80-byte builtin row.
    for (std::size_t index = 0; index < builtinStrings.size(); ++index) {
        for (const auto address : builtinStrings[index]) {
            if (address + 72 > reinterpret_cast<std::uintptr_t>(moduleEnd)) continue;
            std::uintptr_t routine = 0;
            if (!SafeReadPointer(address + 64, &routine)) continue;
            if (!IsExecutableAddress(routine)) continue;
            if (index == 0) depth = routine;
            else layer = routine;
            break;
        }
    }

    std::vector<std::uintptr_t> allNameAddresses = creatorNameAddresses;
    for (const auto& strings : builtinStrings)
        allNameAddresses.insert(allNameAddresses.end(), strings.begin(), strings.end());
    const auto nameRefs = FindPointerPairs(regions, allNameAddresses);
    std::vector<std::uintptr_t> resourceFields;
    for (const auto& [reference, value] : nameRefs) {
        if (!depth && std::find(builtinStrings[0].begin(), builtinStrings[0].end(), value) !=
                          builtinStrings[0].end()) {
            std::uintptr_t routine = 0;
            if (!SafeReadPointer(reference + 8, &routine)) continue;
            if (IsExecutableAddress(routine)) depth = routine;
            continue;
        }
        if (!layer && std::find(builtinStrings[1].begin(), builtinStrings[1].end(), value) !=
                          builtinStrings[1].end()) {
            std::uintptr_t routine = 0;
            if (!SafeReadPointer(reference + 8, &routine)) continue;
            if (IsExecutableAddress(routine)) layer = routine;
            continue;
        }
        if (std::find(creatorNameAddresses.begin(), creatorNameAddresses.end(), value) !=
            creatorNameAddresses.end())
            resourceFields.push_back(reference);
    }
    if (!depth || !layer || resourceFields.empty()) return false;

    const auto resourceRefs = FindPointerPairs(regions, resourceFields);
    std::vector<int> candidateIndices;
    for (const auto& [reference, _value] : resourceRefs) {
        if (reference < 0x18) continue;
        std::int32_t objectIndex = 0;
        std::uintptr_t nextNode = 0;
        if (!SafeReadInt32(reference - 8, &objectIndex) ||
            !SafeReadPointer(reference - 16, &nextNode))
            continue;
        if (objectIndex < 100 || objectIndex >= 100000) continue;
        if (nextNode != 0 && (nextNode < 0x10000 || nextNode >= 0x0000800000000000ULL)) continue;
        candidateIndices.push_back(objectIndex);
    }
    std::sort(candidateIndices.begin(), candidateIndices.end());
    candidateIndices.erase(
        std::unique(candidateIndices.begin(), candidateIndices.end()), candidateIndices.end());

    // The seven known Enemy_Creator resources form one contiguous block in
    // GameMaker's alphabetically-built object table. Scalar/table bookkeeping
    // references also look like resource nodes, but do not form this complete
    // block. Require exactly one seven-ID run so an ambiguous future layout is
    // blocked instead of multiplying an unrelated object.
    std::vector<std::array<int, 7>> blocks;
    for (std::size_t start = 0; start + kCreatorNames.size() <= candidateIndices.size(); ++start) {
        bool contiguous = true;
        for (std::size_t offset = 1; offset < kCreatorNames.size(); ++offset) {
            if (candidateIndices[start + offset] != candidateIndices[start] + static_cast<int>(offset)) {
                contiguous = false;
                break;
            }
        }
        if (!contiguous) continue;
        std::array<int, 7> block{};
        std::copy_n(candidateIndices.begin() + start, block.size(), block.begin());
        blocks.push_back(block);
    }
    if (blocks.size() != 1) return false;
    gCreatorCount = blocks.front().size();
    std::copy(blocks.front().begin(), blocks.front().end(), gCreators.begin());
    return true;
}

bool ResolveRuntimeHint(
    const std::uint8_t* moduleBase,
    std::size_t moduleSize,
    std::uintptr_t depth,
    std::uintptr_t layer)
{
    if (!gState || gState->creatorCount != kCreatorNames.size()) return false;
    const auto moduleStart = reinterpret_cast<std::uintptr_t>(moduleBase);
    const auto moduleEnd = moduleStart + moduleSize;
    if (depth < moduleStart || depth >= moduleEnd || layer < moduleStart || layer >= moduleEnd)
        return false;
    if (!IsExecutableAddress(depth) || !IsExecutableAddress(layer)) return false;

    std::array<int, kMaxCreators> hinted{};
    for (std::size_t index = 0; index < kCreatorNames.size(); ++index) {
        const int objectIndex = gState->creatorIndices[index];
        if (objectIndex < 100 || objectIndex >= 100000) return false;
        if (index && objectIndex != hinted[index - 1] + 1) return false;
        hinted[index] = objectIndex;
    }

    const auto realRValue = ResolveRealRValue(moduleBase, moduleSize);
    const auto freeRValue = ResolveFreeRValue(moduleBase, moduleSize);
    if (!realRValue || !freeRValue) return false;
    gRealRValue = reinterpret_cast<RealRValueFn>(realRValue);
    gFreeRValue = reinterpret_cast<FreeRValueFn>(freeRValue);
    gCreatorCount = kCreatorNames.size();
    std::copy_n(hinted.begin(), gCreatorCount, gCreators.begin());
    return true;
}

bool IsCreator(int objectIndex)
{
    const std::size_t count = (std::min)(gCreatorCount, gCreators.size());
    for (std::size_t index = 0; index < count; ++index)
        if (gCreators[index] == objectIndex) return true;
    return false;
}

int ObjectIndex(const RValue& value)
{
    const auto kind = static_cast<RValueType>(
        static_cast<std::uint32_t>(value.kind) & 0x0FFFFFFFU);
    switch (kind) {
    case VALUE_REAL: return static_cast<int>(value.value.real);
    case VALUE_INT32:
    case VALUE_BOOL: return value.value.i32;
    case VALUE_INT64: return static_cast<int>(value.value.i64);
    default:
        return gRealRValue ? static_cast<int>(gRealRValue(&value)) : -1;
    }
}

double Number(const RValue& value)
{
    const auto kind = static_cast<RValueType>(
        static_cast<std::uint32_t>(value.kind) & 0x0FFFFFFFU);
    switch (kind) {
    case VALUE_REAL: return value.value.real;
    case VALUE_INT32:
    case VALUE_BOOL: return static_cast<double>(value.value.i32);
    case VALUE_INT64: return static_cast<double>(value.value.i64);
    default: return gRealRValue ? gRealRValue(&value) : 0.0;
    }
}

void SetReal(RValue& value, double number)
{
    value.value.real = number;
    value.flags = 0;
    value.kind = VALUE_REAL;
}

double ReadMultiplier()
{
    if (!gState || InterlockedCompareExchange(&gState->enabled, 0, 0) == 0) return 1.0;
    LONG64 bits = InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&gState->multiplier), 0, 0);
    double value = 1.0;
    std::memcpy(&value, &bits, sizeof(value));
    if (!std::isfinite(value)) return 1.0;
    value = std::clamp(value, 1.0, 5.0);
    return std::round(value * 2.0) / 2.0;
}

int CopyCount(double multiplier)
{
    const double extras = std::max(0.0, multiplier - 1.0);
    int copies = static_cast<int>(std::floor(extras));
    if (extras - copies >= 0.499999) {
        const auto sequence = gFractionSequence.fetch_add(1, std::memory_order_relaxed);
        if ((sequence & 1ULL) != 0) ++copies;
    }
    return copies;
}

void CallWithDensity(
    YYGMLRoutine original,
    RValue& result,
    CInstance* self,
    CInstance* other,
    int argumentCount,
    RValue arguments[],
    volatile LONG64* callCounter)
{
    if (!original) return;
    if (gState) InterlockedIncrement64(callCounter);
    if (gInsideDensityCopy || argumentCount < 4 || !arguments) {
        original(result, self, other, argumentCount, arguments);
        return;
    }
    const int objectIndex = ObjectIndex(arguments[3]);
    if (!IsCreator(objectIndex)) {
        original(result, self, other, argumentCount, arguments);
        return;
    }
    if (gState) InterlockedIncrement64(&gState->creatorMatches);
    const int copies = CopyCount(ReadMultiplier());
    gInsideDensityCopy = true;
    if (copies > 0 && argumentCount <= 32) {
        const double baseX = Number(arguments[0]);
        const double baseY = Number(arguments[1]);
        for (int copy = 1; copy <= copies; ++copy) {
            if (!ReserveDensityCapacity()) {
                if (gState) InterlockedExchangeAdd(
                    &gState->capacitySkips, static_cast<LONG>(copies - copy + 1));
                break;
            }
            RValue spread[32]{};
            std::memcpy(spread, arguments, static_cast<std::size_t>(argumentCount) * sizeof(RValue));
            SetReal(spread[0], baseX + static_cast<double>(((copy % 5) - 2) * 28));
            SetReal(spread[1], baseY + static_cast<double>(((copy / 5) - 2) * 28));
            RValue discarded{};
            original(discarded, self, other, argumentCount, spread);
            gFreeRValue(&discarded);
            if (gState) InterlockedIncrement64(&gState->extraCreators);
        }
    }
    original(result, self, other, argumentCount, arguments);
    gInsideDensityCopy = false;
}

void HookDepth(RValue& result, CInstance* self, CInstance* other, int count, RValue arguments[])
{
    CallWithDensity(gOriginalDepth, result, self, other, count, arguments,
                    gState ? &gState->depthCalls : nullptr);
}

void HookLayer(RValue& result, CInstance* self, CInstance* other, int count, RValue arguments[])
{
    CallWithDensity(gOriginalLayer, result, self, other, count, arguments,
                    gState ? &gState->layerCalls : nullptr);
}

bool InstallHooks(std::uintptr_t depth, std::uintptr_t layer)
{
    if (MH_Initialize() != MH_OK) return false;
    if (MH_CreateHook(reinterpret_cast<void*>(depth), reinterpret_cast<void*>(&HookDepth),
                      reinterpret_cast<void**>(&gOriginalDepth)) != MH_OK)
        return false;
    if (MH_CreateHook(reinterpret_cast<void*>(layer), reinterpret_cast<void*>(&HookLayer),
                      reinterpret_cast<void**>(&gOriginalLayer)) != MH_OK)
        return false;
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) return false;
    return true;
}

void RemoveHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_RemoveHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    gOriginalDepth = nullptr;
    gOriginalLayer = nullptr;
}

DWORD WINAPI Worker(void*)
{
    wchar_t mappingName[96]{};
    swprintf_s(mappingName, L"Local\\HSStatForgeDensity_%lu", GetCurrentProcessId());
    for (int attempt = 0; attempt < 100 && !gMapping; ++attempt) {
        gMapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName);
        if (!gMapping) Sleep(25);
    }
    if (!gMapping) FreeLibraryAndExitThread(gSelf, 1);
    gState = static_cast<SharedState*>(MapViewOfFile(gMapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
    if (!gState) {
        CloseHandle(gMapping);
        gMapping = nullptr;
        FreeLibraryAndExitThread(gSelf, 2);
    }
    if (gState->magic != kMagic || gState->version != kVersion ||
        gState->size != sizeof(SharedState)) {
        Fail(ERROR_REVISION_MISMATCH, "StatForge density IPC version mismatch");
        Sleep(1000);
        UnmapViewOfFile(gState);
        CloseHandle(gMapping);
        FreeLibraryAndExitThread(gSelf, 3);
    }

    InterlockedExchange(&gState->status, STATUS_RESOLVING);
    SetMessage("Resolving native GameMaker routes");
    const std::uint8_t* moduleBase = nullptr;
    std::size_t moduleSize = 0;
    const HMODULE game = GetModuleHandleW(nullptr);
    if (!ModuleRange(game, moduleBase, moduleSize)) {
        Fail(ERROR_BAD_EXE_FORMAT, "Hero_Siege.exe module layout is invalid");
        goto unload;
    }
    {
        InitializeProtectedPoolGuard();
        CountProtectedPoolUsed();
        std::uintptr_t depth = static_cast<std::uintptr_t>(gState->depthAddress);
        std::uintptr_t layer = static_cast<std::uintptr_t>(gState->layerAddress);
        const bool hinted = ResolveRuntimeHint(moduleBase, moduleSize, depth, layer);
        if (!hinted) {
            SetMessage("Scanning adaptive GameMaker catalog");
            gCreatorCount = 0;
            gCreators.fill(0);
            depth = 0;
            layer = 0;
            const auto regions = PrivateReadableRegions();
            if (!ResolveRuntime(moduleBase, moduleSize, regions, depth, layer)) {
                Fail(ERROR_NOT_FOUND, "GameMaker create routes or enemy creator catalog were not resolved");
                goto unload;
            }
        }
        if (!depth || !layer || gCreatorCount < kCreatorNames.size()) {
            Fail(ERROR_NOT_FOUND, "GameMaker create routes or enemy creator catalog were not resolved");
            goto unload;
        }
        gState->depthAddress = depth;
        gState->layerAddress = layer;
        gState->creatorCount = static_cast<std::uint32_t>(gCreatorCount);
        for (std::size_t index = 0; index < gCreatorCount; ++index)
            gState->creatorIndices[index] = gCreators[index];
        if (InterlockedCompareExchange(&gState->shutdown, 0, 0) != 0)
            goto unload;
        if (!InstallHooks(depth, layer)) {
            Fail(ERROR_INVALID_HOOK_HANDLE, "Native create hook installation failed");
            goto unload;
        }
    }

    InterlockedIncrement64(&gState->hookGeneration);
    SetMessage("Standalone density hooks ready");
    InterlockedExchange(&gState->status, STATUS_READY);
    while (InterlockedCompareExchange(&gState->shutdown, 0, 0) == 0) {
        const auto heartbeat = static_cast<ULONGLONG>(
            InterlockedCompareExchange64(&gState->hostHeartbeat, 0, 0));
        const auto now = GetTickCount64();
        if (heartbeat && now > heartbeat + 10000ULL) break;
        Sleep(50);
    }

unload:
    InterlockedExchange(&gState->enabled, 0);
    InterlockedExchange(&gState->status, STATUS_UNLOADING);
    RemoveHooks();
    UnmapViewOfFile(gState);
    gState = nullptr;
    CloseHandle(gMapping);
    gMapping = nullptr;
    FreeLibraryAndExitThread(gSelf, 0);
}
} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        gSelf = instance;
        DisableThreadLibraryCalls(instance);
        const HANDLE thread = CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr);
        if (!thread) return FALSE;
        CloseHandle(thread);
    }
    return TRUE;
}
