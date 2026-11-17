/++
 + Finds libplist under names the plist-d bindings don't know about.
 +
 + plist-d only looks for libplist-2.0.3/2.0.4 (.dylib / .so). libplist 2.8 and
 + newer install libplist-2.0.12 instead (its libtool age was reset to 0), and that
 + is what Homebrew ships on Apple Silicon. On macOS, dlopen also doesn't search
 + Homebrew's prefixes (/opt/homebrew/lib, /usr/local/lib) by default.
 +
 + plist-d resolves every function lazily from `LibImport.libraryHandle!libplist`
 + once `LibImport.loaded!libplist` is set, so it's enough to open the library
 + ourselves, before the first plist call, and hand the handle over. Provision's
 + plist usage goes through the same binding and benefits too.
 +
 + libplist 2.8's ABI changes don't affect the calls plist-d makes: functions that
 + went from `void` to returning `plist_err_t` have their result ignored, and the
 + now-opaque iterators are still `malloc`ed, so plist-d freeing them with `free()`
 + remains correct. Every function plist-d binds still exists in 2.8, and the
 + plist_type values are unchanged.
 +/
module libplistloader;

import core.atomic;

import dynamicloader;
import plist.c: libplist;

version (OSX) {
    /// Copies bundled next to the executable (lib/) are tried before anything else,
    /// so the bundled libimobiledevice and Sideloader share one libplist.
    private immutable string[] bundledLibplistNames = [
        "@executable_path/lib/libplist-2.0.12.dylib",
        "@executable_path/lib/libplist-2.0.4.dylib",
    ];
    private immutable string[] extraLibplistNames = [
        "libplist-2.0.12.dylib",
        "/opt/homebrew/lib/libplist-2.0.12.dylib",
        "/opt/homebrew/lib/libplist-2.0.4.dylib",
        "/usr/local/lib/libplist-2.0.12.dylib",
        "/usr/local/lib/libplist-2.0.4.dylib",
    ];
} else version (Posix) {
    private immutable string[] bundledLibplistNames = [];
    private immutable string[] extraLibplistNames = [
        "libplist-2.0.so.12",
    ];
} else {
    private immutable string[] bundledLibplistNames = [];
    private immutable string[] extraLibplistNames = [];
}

shared static this() {
    ensureLibplistLoaded();
}

/// Loads libplist if possible. Returns false if no known name could be loaded,
/// in which case the first plist call reports plist-d's usual error.
bool ensureLibplistLoaded() nothrow {
    if (atomicLoad(LibImport.loaded!libplist)) {
        return true;
    }

    version (Posix) {
        import core.sys.posix.dlfcn: dlopen, RTLD_LAZY;
        import std.string: toStringz;

        bool tryNames(const(string)[] names) {
            foreach (name; names) {
                auto handle = dlopen(name.toStringz(), RTLD_LAZY);
                if (handle) {
                    LibImport.libraryHandle!libplist = handle;
                    atomicStore(LibImport.loaded!libplist, true);
                    return true;
                }
            }
            return false;
        }

        if (tryNames(bundledLibplistNames)) {
            return true;
        }
    }

    if (LibImport.tryLoad!libplist()) {
        return true;
    }

    version (Posix) {
        if (tryNames(extraLibplistNames)) {
            return true;
        }
    }
    return false;
}
