// Bionic pthread (40B mutex) -> Darwin pthread（64B）的安全间接层
// 关键点：不能把 Bionic 的 40 字节块直接当 Darwin 的 64 字节对象用，否则会踩爆相邻 24 字节。
// 做法：在调用方给的那 40 字节里放 {magic, real_ptr}，真对象 malloc 在堆上。
#include "bionic_shim.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdio.h>
#include <errno.h>   // ETIMEDOUT 在 Darwin 的 <errno.h> 里，pthread.h 不保证带进来

#define KIND_MUTEX 0x4D58u   // 'MX'
#define KIND_COND  0x4344u   // 'CD'
#define KIND_RW    0x5257u   // 'RW'
#define MAGIC(k)   (0x4D45570000000000ULL | (uint64_t)(k))

typedef struct {
    uint64_t magic;
    void*    real;     // 指向堆上的 Darwin pthread_*_t
} bionic_slot;

static pthread_mutex_t g_guard = PTHREAD_MUTEX_INITIALIZER;

static void* slot_ensure(void* bionic_obj, unsigned kind, size_t real_size, int* created) {
    bionic_slot* s = (bionic_slot*)bionic_obj;
    const uint64_t want = MAGIC(kind);
    if (__builtin_expect(s->magic == want && s->real != NULL, 1)) {
        if (created) *created = 0;
        return s->real;
    }
    pthread_mutex_lock(&g_guard);
    if (s->magic != want || s->real == NULL) {
        void* real = calloc(1, real_size);
        __atomic_store_n(&s->real, real, __ATOMIC_RELEASE);
        __atomic_store_n(&s->magic, want, __ATOMIC_RELEASE);
        if (created) *created = 1;
    } else if (created) {
        *created = 0;
    }
    pthread_mutex_unlock(&g_guard);
    return s->real;
}

static void slot_destroy(void* bionic_obj, unsigned kind) {
    bionic_slot* s = (bionic_slot*)bionic_obj;
    if (s->magic == MAGIC(kind) && s->real) {
        free(s->real);
        s->real = NULL;
        s->magic = 0;
    }
}

// ---------------- mutex ----------------
int bionic_pthread_mutex_init(void* m, const void* attr) {
    (void)attr;
    if (!m) return 22;
    memset(m, 0, BIONIC_MUTEX_SIZE);
    int created = 0;
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), &created);
    if (!real) return 12;
    if (created) {
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        // Bionic 静态初始化常见递归语义，统一给递归锁最安全
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(real, &a);
        pthread_mutexattr_destroy(&a);
    }
    return 0;
}
int bionic_pthread_mutex_lock(void* m) {
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!real) return 22;
    return pthread_mutex_lock(real) == 0 ? 0 : 22;
}
int bionic_pthread_mutex_trylock(void* m) {
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!real) return 22;
    return pthread_mutex_trylock(real) == 0 ? 0 : 11;   // EBUSY(bionic 16)->EAGAIN? 这里给 bionic EBUSY=16
}
int bionic_pthread_mutex_unlock(void* m) {
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!real) return 22;
    return pthread_mutex_unlock(real) == 0 ? 0 : 22;
}
int bionic_pthread_mutex_destroy(void* m) {
    if (!m) return 22;
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (real) pthread_mutex_destroy(real);
    slot_destroy(m, KIND_MUTEX);
    return 0;
}

// ---------------- cond ----------------
int bionic_pthread_cond_init(void* c, const void* attr) {
    (void)attr;
    if (!c) return 22;
    memset(c, 0, BIONIC_COND_SIZE);
    int created = 0;
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), &created);
    if (!real) return 12;
    if (created) pthread_cond_init(real, NULL);
    return 0;
}
int bionic_pthread_cond_destroy(void* c) {
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    if (real) pthread_cond_destroy(real);
    slot_destroy(c, KIND_COND);
    return 0;
}
int bionic_pthread_cond_signal(void* c) {
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    return real ? pthread_cond_signal(real) : 22;
}
int bionic_pthread_cond_broadcast(void* c) {
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    return real ? pthread_cond_broadcast(real) : 22;
}
int bionic_pthread_cond_wait(void* c, void* m) {
    pthread_cond_t* rc = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    pthread_mutex_t* rm = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!rc || !rm) return 22;
    return pthread_cond_wait(rc, rm) == 0 ? 0 : 22;
}
int bionic_pthread_cond_timedwait(void* c, void* m, const struct timespec* abstime) {
    pthread_cond_t* rc = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    pthread_mutex_t* rm = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!rc || !rm) return 22;
    // 注意：Linux 的 CLOCK_MONOTONIC 与 Darwin 的 CLOCK_REALTIME 不同，这里直接透传，P2 再校时基
    int r = pthread_cond_timedwait(rc, rm, abstime);
    return r == 0 ? 0 : (r == ETIMEDOUT ? 110 : 22);
}

// ---------------- rwlock ----------------
int bionic_pthread_rwlock_rdlock(void* l) {
    pthread_rwlock_t* real = (pthread_rwlock_t*)slot_ensure(l, KIND_RW, sizeof(pthread_rwlock_t), NULL);
    return real ? pthread_rwlock_rdlock(real) : 22;
}
int bionic_pthread_rwlock_wrlock(void* l) {
    pthread_rwlock_t* real = (pthread_rwlock_t*)slot_ensure(l, KIND_RW, sizeof(pthread_rwlock_t), NULL);
    return real ? pthread_rwlock_wrlock(real) : 22;
}
int bionic_pthread_rwlock_unlock(void* l) {
    pthread_rwlock_t* real = (pthread_rwlock_t*)slot_ensure(l, KIND_RW, sizeof(pthread_rwlock_t), NULL);
    return real ? pthread_rwlock_unlock(real) : 22;
}

// ---------------- 直接透传的那些（签名/AArch64 约定一致） ----------------
int bionic_pthread_join(pthread_t t, void** r) { return pthread_join(t, r); }
int bionic_pthread_detach(pthread_t t) { return pthread_detach(t); }
void bionic_pthread_exit(void* r) { pthread_exit(r); }
pthread_t bionic_pthread_self(void) { return pthread_self(); }
// pthread_once_t：bionic 是 4 字节 int，Darwin 是 8 字节 long。直接转指针会让
// Darwin 读满 8 字节（越过 guest 的 4 字节对象）。自己实现，只要求那 4 字节可写。
int bionic_pthread_once(void* once, void (*fn)(void)) {
    int* p = (int*)once;
    if (__atomic_load_n(p, __ATOMIC_ACQUIRE) == 2) return 0;
    static pthread_mutex_t om = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&om);
    if (__atomic_load_n(p, __ATOMIC_RELAXED) != 2) {
        fn();
        __atomic_store_n(p, 2, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&om);
    return 0;
}

// pthread_key_t：bionic 是 4 字节 unsigned，Darwin 是 8 字节 unsigned long。
// 直接透传会写穿 guest 的 4 字节槽，所以用一张小表做索引。
#define MEW_MAX_KEYS 1024
static pthread_key_t g_keys[MEW_MAX_KEYS];
static unsigned char g_key_used[MEW_MAX_KEYS];
static pthread_mutex_t g_key_lock = PTHREAD_MUTEX_INITIALIZER;

int bionic_pthread_key_create(unsigned* k, void (*dtor)(void*)) {
    if (!k) return 22;
    pthread_mutex_lock(&g_key_lock);
    for (unsigned i = 1; i < MEW_MAX_KEYS; i++) {
        if (g_key_used[i]) continue;
        pthread_key_t dk;
        int r = pthread_key_create(&dk, dtor);
        if (r != 0) { pthread_mutex_unlock(&g_key_lock); return 11; }
        g_keys[i] = dk;
        g_key_used[i] = 1;
        *k = i;
        pthread_mutex_unlock(&g_key_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_key_lock);
    return 11;
}
int bionic_pthread_key_delete(unsigned k) {
    if (k == 0 || k >= MEW_MAX_KEYS) return 22;
    pthread_mutex_lock(&g_key_lock);
    if (!g_key_used[k]) { pthread_mutex_unlock(&g_key_lock); return 22; }
    pthread_key_delete(g_keys[k]);
    g_key_used[k] = 0;
    pthread_mutex_unlock(&g_key_lock);
    return 0;
}
void* bionic_pthread_getspecific(unsigned k) {
    if (k == 0 || k >= MEW_MAX_KEYS || !g_key_used[k]) return NULL;
    return pthread_getspecific(g_keys[k]);
}
int bionic_pthread_setspecific(unsigned k, const void* v) {
    if (k == 0 || k >= MEW_MAX_KEYS || !g_key_used[k]) return 22;
    return pthread_setspecific(g_keys[k], v) == 0 ? 0 : 22;
}

// pthread_attr_t：Bionic 56B / Darwin 64B，直接透传会写穿 8 字节栈内存。
// 做法：在自己的 56B 结构里只存 detachstate + stacksize，pthread_create 时临时构造 Darwin attr。
typedef struct {
    uint32_t detachstate;   // 0 = joinable, 1 = detached
    uint32_t _pad;
    uint64_t stacksize;
} bionic_attr;

int bionic_pthread_attr_init(void* a) {
    memset(a, 0, BIONIC_ATTR_SIZE);
    return 0;
}
int bionic_pthread_attr_destroy(void* a) { (void)a; return 0; }
int bionic_pthread_attr_setdetachstate(void* a, int s) {
    ((bionic_attr*)a)->detachstate = (uint32_t)s;
    return 0;
}
int bionic_pthread_attr_setstacksize(void* a, size_t s) {
    ((bionic_attr*)a)->stacksize = (uint64_t)s;
    return 0;
}
int bionic_pthread_create(pthread_t* t, const void* attr, void* (*fn)(void*), void* arg) {
    if (!attr) return pthread_create(t, NULL, fn, arg) == 0 ? 0 : 11;
    const bionic_attr* ba = (const bionic_attr*)attr;
    pthread_attr_t da;
    pthread_attr_init(&da);
    if (ba->stacksize) pthread_attr_setstacksize(&da, (size_t)ba->stacksize);
    pthread_attr_setdetachstate(&da, ba->detachstate ? PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE);
    int r = pthread_create(t, &da, fn, arg);
    pthread_attr_destroy(&da);
    return r == 0 ? 0 : 11;
}

int bionic_pthread_mutexattr_init(void* a) { memset(a, 0, 8); return 0; }
int bionic_pthread_mutexattr_destroy(void* a) { (void)a; return 0; }
int bionic_pthread_mutexattr_settype(void* a, int t) {
    *(int*)a = t;   // 先记住，mutex_init 时再翻译成 Darwin 类型
    return 0;
}
