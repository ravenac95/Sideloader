# libplist-d (vendored)

Copy of https://github.com/Dadoum/libplist-d at commit
6fdaa60d62bbf7c55044069e8f03cbe74401c444 (Boost licence, see LICENSE).

Local change: `source/plist/c.d` also looks for `libplist-2.0.12.dylib` (macOS) and
`libplist-2.0.so.12` (Linux), the names libplist 2.8 and newer install. Homebrew on
Apple Silicon ships libplist 2.8, which the original bindings could not find.
