#pragma once

#include <cstdint>

struct CInstance;

enum RValueType : std::uint32_t
{
    VALUE_REAL = 0,
    VALUE_STRING = 1,
    VALUE_ARRAY = 2,
    VALUE_PTR = 3,
    VALUE_VEC3 = 4,
    VALUE_UNDEFINED = 5,
    VALUE_OBJECT = 6,
    VALUE_INT32 = 7,
    VALUE_VEC4 = 8,
    VALUE_VEC44 = 9,
    VALUE_INT64 = 10,
    VALUE_ACCESSOR = 11,
    VALUE_NULL = 12,
    VALUE_BOOL = 13,
    VALUE_ITERATOR = 14,
    VALUE_REF = 15,
};

#pragma pack(push, 4)
struct RValue
{
    union
    {
        std::int32_t i32;
        std::int64_t i64;
        double real;
        void* pointer;
    } value{};
    std::uint32_t flags = 0;
    RValueType kind = VALUE_UNDEFINED;
};
#pragma pack(pop)

static_assert(sizeof(RValue) == 16, "Season 10 RValue ABI must remain 16 bytes");

using YYGMLRoutine = void (*)(
    RValue& result,
    CInstance* self,
    CInstance* other,
    int argumentCount,
    RValue arguments[]);
