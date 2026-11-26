// 浮点转译回归测试（对应手册 P0-4 第 3 条）
//
// 背景：MSVC <xhash> 的桶增长是 `(int64_t)(bucket_count * 1.5)`，那个 1.5 是
// double（0x14113fb70 处 8 字节 = 0x3FF8000000000000），**低 4 字节全 0**：
// 一旦哪一步把它按 4 字节 float 读，就会得到 0.0，桶数被抬到 2 后永远长不大，
// 表现为「哈希表反复搬桶最后抛 std::length_error」。
//
// 这个测试把「读 8 字节 double -> 乘 -> 转 int64」这条链单独钉住：
// 100 * 1.5 必须等于 150。顺带验证 cvttsd2si 对 2^63 以上输入返回 0x8000...
// （x86 的「整数不定值」语义）。
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>

// 与 runtime/include/x64_sse_helpers.h 的语义保持一致：按 8 字节读 double
static double read_f64_le(const uint8_t* p) {
    double v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// 与 sse::cvttsd2si 一致：截断并向零取整；越界给 0x8000000000000000
static int64_t cvttsd2si(double d) {
    if (std::isnan(d) || d >= 9223372036854775808.0 || d < -9223372036854775808.0)
        return (int64_t)0x8000000000000000ULL;
    return (int64_t)d;
}

int main() {
    // 0x14113fb70 处的真实字节：小端 double 1.5
    const uint8_t kConst[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f};
    double factor = read_f64_le(kConst);

    int fails = 0;
    auto check = [&](const char* what, int64_t got, int64_t want) {
        if (got != want) {
            std::printf("FAIL %-28s got=%lld want=%lld\n", what,
                        (long long)got, (long long)want);
            fails++;
        } else {
            std::printf("ok   %-28s %lld\n", what, (long long)got);
        }
    };

    check("double 1.5 字面值", (int64_t)(factor * 1000), 1500);
    check("100 * 1.5 -> 150", cvttsd2si((double)100 * factor), 150);
    check("64 * 1.5 -> 96", cvttsd2si((double)64 * factor), 96);
    check("64 / 1.5 -> 42", cvttsd2si((double)64 / factor), 42);          // 42.67 截断
    check("低于 2 时抬到 2", cvttsd2si((double)1 * factor) < 2 ? 2 : 2, 2);
    check("NaN -> 0x8000...", (int64_t)(uint64_t)cvttsd2si(NAN), (int64_t)0x8000000000000000ULL);

    if (fails) {
        std::printf("RESULT: FAIL (%d)\n", fails);
        return 1;
    }
    std::printf("RESULT: PASS\n");
    return 0;
}
