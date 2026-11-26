#!/usr/bin/env python3
"""阶段 3：并行编译分片 -> libmew_recomp.a，并按「语法通过 / 能链接」分层报告。

用法：
  python3 tools/build_stage3.py --src-dir generated/stage3 --obj-dir build-stage3 \
      --archive build-stage3/libmew_recomp.a --jobs 8 --extra src.cpp
"""
import argparse
import collections
import concurrent.futures as cf
import glob
import os
import re
import subprocess
import sys
import time


def classify(err):
    if not err:
        return 'ok'
    for pat, name in (
        (r'error: expected', 'syntax-expected'),
        (r'error: no matching function', 'overload'),
        (r'error: use of undeclared', 'undeclared'),
        (r'error: invalid', 'invalid-expr'),
        (r'fatal error: .*No such file', 'missing-header'),
        (r'error:', 'other-error'),
    ):
        if re.search(pat, err):
            return name
    return 'other'


def compile_one(job):
    src, obj, cxx, flags, extra_incs = job
    cmd = [cxx] + flags + ['-c', src, '-o', obj] + extra_incs
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    return src, p.returncode, p.stderr, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src-dir', required=True)
    ap.add_argument('--obj-dir', required=True)
    ap.add_argument('--archive', required=True)
    ap.add_argument('--jobs', type=int, default=8)
    ap.add_argument('--cxx', default='g++')
    ap.add_argument('--extra', action='append', default=[], help='额外参与归档的 .cpp')
    ap.add_argument('--opt', default='-O1')
    # 热分片单独提速：--opt2-shards=12,37 表示这两个分片用 -O2 编，其余保持 --opt。
    # 用途：包含 0x140386xxx / 0x140dxxxxx 的那些分片是启动路径的热点，-O2 能快 15~30 倍，
    # 又不至于让 66 个 TU 全部 -O2 把编译时间拖到不可接受。
    ap.add_argument('--opt2-shards', default='', help='逗号分隔的分片编号（文件名 shard_NN.cpp 里的 NN）')
    ap.add_argument('--no-archive', action='store_true')
    args = ap.parse_args()

    os.makedirs(args.obj_dir, exist_ok=True)
    srcs = sorted(glob.glob(os.path.join(args.src_dir, '*.cpp')))
    # shims_auto.cpp 也参与归档：它提供 456 个 IAT 的 weak 占位，链接门禁需要
    srcs += args.extra
    if not srcs:
        print('no sources'); return 1

    base_flags = ['-std=c++17', '-w', '-I', 'runtime/include', '-I', args.src_dir]
    hot = {x.strip() for x in args.opt2_shards.split(',') if x.strip()}
    jobs = []
    objs = []
    hot_used = []
    for s in srcs:
        base = os.path.basename(s).replace('.cpp', '.o')
        obj = os.path.join(args.obj_dir, base)
        objs.append(obj)
        m = re.search(r'shard_(\d+)\.cpp$', base)
        is_hot = bool(m and m.group(1) in hot)
        if is_hot:
            hot_used.append(base)
        flags = base_flags + (['-O2'] if is_hot else [args.opt])
        jobs.append((s, obj, args.cxx, flags, []))
    if hot:
        print('hot shards (-O2): %s' % (', '.join(hot_used) if hot_used else '未命中任何分片'))

    print('compiling %d TUs with -j%d ...' % (len(jobs), args.jobs))
    t0 = time.time()
    classes = collections.Counter()
    failed = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for src, rc, err, dt in ex.map(compile_one, jobs):
            if rc != 0:
                classes[classify(err)] += 1
                failed.append((src, err))
    dur = time.time() - t0

    ok = len(jobs) - len(failed)
    print('--- 门禁 1：逐 TU 语法/编译 ---')
    print('TUs=%d ok=%d failed=%d  (%.1fs)' % (len(jobs), ok, len(failed), dur))
    if classes:
        print('failure classes:', dict(classes))
        for src, err in failed[:5]:
            print('---', src)
            print('\n'.join(err.strip().splitlines()[:12]))

    if failed:
        print('RESULT: FAIL (compile)')
        return 1

    if args.no_archive:
        print('RESULT: PASS (compile only)')
        return 0

    print('--- 门禁 2：归档 libmew_recomp.a ---')
    if os.path.exists(args.archive):
        os.remove(args.archive)
    p = subprocess.run(['ar', 'rcs', args.archive] + objs, capture_output=True, text=True)
    if p.returncode != 0:
        print('ar failed:', p.stderr[:500])
        print('RESULT: FAIL (archive)')
        return 1
    size = os.path.getsize(args.archive)
    print('archive=%s size=%d bytes objs=%d' % (args.archive, size, len(objs)))
    print('RESULT: PASS (compile + archive)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
