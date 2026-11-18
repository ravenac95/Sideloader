#!/usr/bin/env python3
"""Copy Homebrew libraries into a folder so a macOS build runs without Homebrew.

Sideloader dlopens libimobiledevice, libusbmuxd, libplist and OpenSSL by name and
looks in @executable_path/lib first. This copies the named libraries from Homebrew
into <lib dir>, follows their dependencies recursively, copies every dependency
that lives outside the system (/usr/lib, /System), rewrites all references between
them to @loader_path/<name> (siblings in the same folder), ad-hoc signs every copy
(Apple Silicon refuses modified, unsigned code) and fails if anything still points
outside the folder or the system.

Usage: bundle-macos-libs.py <lib dir> <homebrew prefix> <library> [<library>...]
       A library is a file name searched in <prefix>/lib and <prefix>/opt/*/lib,
       or a glob such as 'libplist-2.0.[0-9]*.dylib'.
"""

import glob
import os
import shutil
import subprocess
import sys

lib_dir, brew_prefix, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
os.makedirs(lib_dir, exist_ok=True)
search_dirs = [os.path.join(brew_prefix, "lib")] + sorted(glob.glob(os.path.join(brew_prefix, "opt", "*", "lib")))


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def find(pattern):
    for d in search_dirs:
        matches = sorted(glob.glob(os.path.join(d, pattern)))
        # Prefer the shortest name (the soname link, e.g. libfoo.1.dylib over libfoo.1.2.3.dylib).
        matches.sort(key=len)
        if matches:
            return matches[0]
    return None


def dependencies(path):
    lines = run("otool", "-L", path).splitlines()[1:]
    deps = [line.strip().split(" (compatibility")[0] for line in lines if line.strip()]
    own = run("otool", "-D", path).splitlines()
    own_id = own[1].strip() if len(own) > 1 else None
    return [d for d in deps if d != own_id]


def is_system(dep):
    return dep.startswith(("/usr/lib/", "/System/"))


def copy_in(source, name):
    target = os.path.join(lib_dir, name)
    if not os.path.exists(target):
        shutil.copy2(os.path.realpath(source), target)
        os.chmod(target, 0o755)
        run("install_name_tool", "-id", f"@loader_path/{name}", target)
        print(f"copied   {name} (from {os.path.realpath(source)})")
    return target


for pattern in wanted:
    source = find(pattern)
    if source is None:
        sys.exit(f"{pattern} not found in Homebrew ({brew_prefix})")
    copy_in(source, os.path.basename(source))

changed = True
while changed:
    changed = False
    for name in sorted(os.listdir(lib_dir)):
        path = os.path.join(lib_dir, name)
        for dep in dependencies(path):
            if is_system(dep):
                continue
            dep_name = os.path.basename(dep)
            if dep == f"@loader_path/{dep_name}" and os.path.exists(os.path.join(lib_dir, dep_name)):
                continue
            source = dep if os.path.isabs(dep) and os.path.exists(dep) else find(dep_name)
            if source is None:
                sys.exit(f"{name} needs {dep}, which is not in Homebrew")
            copy_in(source, dep_name)
            run("install_name_tool", "-change", dep, f"@loader_path/{dep_name}", path)
            print(f"relinked {name}: {dep} -> @loader_path/{dep_name}")
            changed = True

problems = []
for name in sorted(os.listdir(lib_dir)):
    path = os.path.join(lib_dir, name)
    run("codesign", "--force", "--sign", "-", path)
    for dep in dependencies(path):
        if not is_system(dep) and not (dep.startswith("@loader_path/") and os.path.exists(os.path.join(lib_dir, os.path.basename(dep)))):
            problems.append(f"{name} -> {dep}")
if problems:
    sys.exit("Still pointing outside the bundle:\n  " + "\n  ".join(problems))
print(f"{len(os.listdir(lib_dir))} libraries bundled in {lib_dir}, all signed and self-contained.")
