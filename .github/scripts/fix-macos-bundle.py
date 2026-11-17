#!/usr/bin/env python3
"""Make a macdeployqt'ed .app bundle self-contained.

macdeployqt copies Qt and its Homebrew dependencies into Contents/Frameworks, but
leaves some dependencies' own references untouched. For example, Homebrew's
libbrotlidec refers to @loader_path/../lib/libbrotlicommon.1.dylib, which does not
exist inside the bundle, so Qt's cocoa platform plugin fails to load.

For every Mach-O file in the bundle, every dependency that is a Homebrew path or
that does not resolve inside the bundle is copied into Contents/Frameworks (if it
isn't there yet) and rewritten to @executable_path/../Frameworks/<name>. This
repeats until nothing changes. Afterwards the bundle must be signed again.

Usage: fix-macos-bundle.py <path/to/App.app> <homebrew prefix>
"""

import os
import shutil
import subprocess
import sys

app, brew_prefix = sys.argv[1], sys.argv[2]
contents = os.path.join(app, "Contents")
frameworks = os.path.join(contents, "Frameworks")
executable_dir = os.path.join(contents, "MacOS")
homebrew_roots = ("/opt/homebrew/", "/usr/local/")
search_dirs = [os.path.join(brew_prefix, "lib"), os.path.join(brew_prefix, "opt")]


def is_macho(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    return magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf")


def macho_files():
    for root, _, files in os.walk(contents):
        for name in files:
            path = os.path.join(root, name)
            if not os.path.islink(path) and is_macho(path):
                yield path


def dependencies(path):
    out = subprocess.run(["otool", "-L", path], capture_output=True, text=True, check=True).stdout
    deps = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line:
            deps.append(line.split(" (compatibility")[0])
    return deps


def own_id(path):
    out = subprocess.run(["otool", "-D", path], capture_output=True, text=True, check=True).stdout.splitlines()
    return out[1].strip() if len(out) > 1 else None


def resolves_in_bundle(dep, path):
    if dep.startswith("@executable_path/"):
        return os.path.exists(os.path.join(executable_dir, dep[len("@executable_path/"):]))
    if dep.startswith("@loader_path/"):
        return os.path.exists(os.path.join(os.path.dirname(path), dep[len("@loader_path/"):]))
    if dep.startswith("@rpath/"):
        return os.path.exists(os.path.join(frameworks, dep[len("@rpath/"):]))
    return False


def find_in_homebrew(name):
    candidates = [os.path.join(d, name) for d in search_dirs[:1]]
    for root in search_dirs[1:]:
        if os.path.isdir(root):
            candidates += [os.path.join(root, opt, "lib", name) for opt in os.listdir(root)]
    for candidate in candidates:
        if os.path.exists(candidate):
            return os.path.realpath(candidate)
    return None


changed = True
rounds = 0
while changed:
    changed = False
    rounds += 1
    if rounds > 20:
        sys.exit("Giving up: dependencies keep changing")
    for path in list(macho_files()):
        self_id = own_id(path)
        for dep in dependencies(path):
            if dep == self_id or dep.startswith(("/usr/lib/", "/System/")):
                continue
            if ".framework/" in dep and resolves_in_bundle(dep, path):
                continue
            is_homebrew = dep.startswith(homebrew_roots)
            if not is_homebrew and (not dep.startswith("@") or resolves_in_bundle(dep, path)):
                continue
            if ".framework/" in dep:
                # e.g. /opt/homebrew/opt/qt@5/lib/QtCore.framework/Versions/5/QtCore
                inside = dep[dep.rindex("/", 0, dep.index(".framework/")) + 1:]
                if not os.path.exists(os.path.join(frameworks, inside)):
                    sys.exit(f"{os.path.relpath(path, app)} needs framework {dep}, which is not in the bundle")
                new = f"@executable_path/../Frameworks/{inside}"
                subprocess.run(["install_name_tool", "-change", dep, new, path], check=True, capture_output=True)
                print(f"relinked {os.path.relpath(path, app)}: {dep} -> {new}")
                changed = True
                continue
            name = os.path.basename(dep)
            target = os.path.join(frameworks, name)
            if not os.path.exists(target):
                source = dep if is_homebrew and os.path.exists(dep) else find_in_homebrew(name)
                if source is None:
                    sys.exit(f"{os.path.relpath(path, app)} needs {dep}, which is not in the bundle or Homebrew")
                shutil.copy2(source, target)
                os.chmod(target, 0o755)
                subprocess.run(["install_name_tool", "-id", f"@executable_path/../Frameworks/{name}", target],
                               check=True, capture_output=True)
                print(f"copied   {name} (from {source})")
            new = f"@executable_path/../Frameworks/{name}"
            subprocess.run(["install_name_tool", "-change", dep, new, path], check=True, capture_output=True)
            print(f"relinked {os.path.relpath(path, app)}: {dep} -> {new}")
            changed = True

print(f"Bundle is self-contained after {rounds} pass(es).")
