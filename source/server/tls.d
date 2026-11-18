/++
 + Verified TLS for every connection Sideloader makes.
 +
 + dlang-requests' built-in TLS either skips verification entirely (which is how
 + Sideloader used to call it) or checks the certificate chain without checking
 + that the certificate belongs to the host being contacted. Either way, anyone
 + able to intercept the connection could read the Apple ID session tokens or
 + replace the native libraries Sideloader downloads and executes.
 +
 + This module plugs into requests' `socketFactory` hook and opens its own
 + OpenSSL connection that:
 +  - only trusts the root certificates Apple's servers actually chain to
 +    (Apple Root CA for gsa.apple.com, DigiCert Global Root G2 for the
 +    developer portal and the CDN), not the system trust store;
 +  - checks the certificate's hostname (`SSL_set1_host`);
 +  - requires TLS 1.2 or newer;
 +  - refuses plain HTTP and any host outside Apple's domains.
 +/
module server.tls;

import core.stdc.errno;
import core.time;

import std.algorithm.searching;
import std.conv;
import std.exception;
import std.format;
import std.process;
import std.socket;
import std.string;
import std.uni;

import requests;

import slf4d;

/// Root certificates (DER) that Apple's servers chain to.
/// Apple Root CA: SHA-256 B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24
private static immutable ubyte[] appleRootCA = cast(immutable(ubyte)[]) import("AppleIncRootCertificate.cer");
/// DigiCert Global Root G2: SHA-256 CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F
private static immutable ubyte[] digiCertGlobalRootG2 = cast(immutable(ubyte)[]) import("DigiCertGlobalRootG2.cer");

/// A `Request` whose HTTPS connections are all verified and pinned.
/// `timeout` applies to connecting and sending, like `Request.timeout` normally does
/// (requests doesn't pass its own timeout to streams made by a `socketFactory`).
Request secureRequest(Duration timeout = 30.seconds) {
    Request request = Request();
    request.timeout = timeout;
    request.socketFactory = (string scheme, string host, ushort port) =>
        openVerifiedConnection(scheme, host, port, timeout);
    return request;
}

/// Hosts Sideloader is allowed to talk to.
bool isAllowedHost(string host) {
    host = host.toLower();
    return host == "apple.com" || host.endsWith(".apple.com") || host.endsWith(".mzstatic.com");
}

/// gsa.apple.com chains to Apple's private root only; the other Apple hosts
/// (developer portal, CDN) chain to DigiCert Global Root G2.
private bool trustsAppleRootOnly(string host) {
    return host.toLower() == "gsa.apple.com";
}

class TlsVerificationException: Exception {
    this(string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
    }
}

NetworkStream openVerifiedConnection(string scheme, string host, ushort port, Duration timeout = 30.seconds) {
    if (scheme != "https") {
        throw new TlsVerificationException(format!"Refusing to connect to %s://%s: only HTTPS is allowed."(scheme, host));
    }
    if (!isAllowedHost(host)) {
        throw new TlsVerificationException(format!"Refusing to connect to %s: not an Apple server."(host));
    }

    auto stream = new VerifiedTlsStream();
    stream.connect(host, port, timeout);
    return stream;
}

/// An HTTPS proxy from the environment, as dlang-requests itself would pick it.
private string environmentProxy() {
    foreach (name; ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]) {
        auto value = environment.get(name);
        if (value.length) {
            return value;
        }
    }
    return null;
}

private bool bypassesProxy(string host) {
    auto noProxy = environment.get("no_proxy", environment.get("NO_PROXY"));
    if (!noProxy.length) {
        return false;
    }
    host = host.toLower();
    foreach (entry; noProxy.split(",")) {
        entry = entry.strip().toLower();
        if (!entry.length) continue;
        if (entry == "*") return true;
        if (entry.startsWith("*.")) entry = entry[1..$];
        if (host == entry || (entry.startsWith(".") && host.endsWith(entry)) || host.endsWith("." ~ entry)) {
            return true;
        }
    }
    return false;
}

final class VerifiedTlsStream: NetworkStream {
    private Socket socket;
    private SSL* ssl;
    private SSL_CTX* ownedCtx; // only for tests that override the roots
    private bool connected;
    // Set after a fatal TLS or socket error: SSL_shutdown must not be called then.
    private bool fatal;
    private immutable(ubyte)[][] rootsOverride;

    this() {}

    /// For tests only: trust these roots (DER) instead of the pinned ones.
    this(immutable(ubyte)[][] trustedRoots) {
        rootsOverride = trustedRoots;
    }

    @property bool isConnected() const { return socket !is null && connected; }
    @property bool isOpen() const { return socket !is null; }
    Socket so() { return socket; }

    NetworkStream connect(string host, ushort port, Duration timeout = 30.seconds) {
        auto log = getLogger();
        scope(failure) close();

        string proxy = bypassesProxy(host) ? null : environmentProxy();
        if (proxy) {
            auto proxyUri = URI(proxy);
            openSocket(proxyUri.host, proxyUri.port, timeout);
            connectThroughProxy(proxyUri, host, port);
        } else {
            openSocket(host, port, timeout);
        }

        handshake(host);
        connected = true;
        log.debugF!"Verified TLS connection to %s:%d."(host, port);
        return this;
    }

    private void openSocket(string host, ushort port, Duration timeout) {
        Address[] addresses;
        try {
            addresses = getAddress(host, port);
        } catch (Exception e) {
            throw new ConnectError(format!"Can't resolve %s: %s"(host, e.msg));
        }

        foreach (address; addresses) {
            auto candidate = new Socket(address.addressFamily, SocketType.STREAM, ProtocolType.TCP);
            try {
                candidate.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, timeout);
                candidate.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout);
                candidate.setOption(SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1);
                version (OSX) {
                    // Writing to a reset connection must fail, not kill the process.
                    enum SO_NOSIGPIPE = 0x1022;
                    candidate.setOption(SocketOptionLevel.SOCKET, cast(SocketOption) SO_NOSIGPIPE, 1);
                }
                candidate.connect(address);
                socket = candidate;
                return;
            } catch (SocketException e) {
                candidate.close();
            }
        }
        throw new ConnectError(format!"Can't connect to %s:%d"(host, port));
    }

    private void connectThroughProxy(URI proxyUri, string host, ushort port) {
        import std.base64;

        string connectRequest = format!"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"(host, port, host, port);
        if (proxyUri.username.length) {
            string credentials = Base64.encode(cast(ubyte[]) (proxyUri.username ~ ":" ~ proxyUri.password)).idup;
            connectRequest ~= "Proxy-Authorization: Basic " ~ credentials ~ "\r\n";
        }
        connectRequest ~= "\r\n";
        rawSend(connectRequest);

        // Read the proxy's answer byte by byte so nothing past the headers is consumed.
        char[] response;
        ubyte[1] b;
        while (!response.endsWith("\r\n\r\n")) {
            auto received = socket.receive(b[]);
            if (received <= 0 || response.length > 16 * 1024) {
                throw new ConnectError("The proxy closed the connection during CONNECT.");
            }
            response ~= cast(char) b[0];
        }
        auto statusLine = response[0..response.indexOf("\r\n")];
        auto parts = statusLine.split(" ");
        if (parts.length < 2 || parts[1] != "200") {
            throw new ConnectError(format!"The proxy refused CONNECT to %s:%d: %s"(host, port, statusLine));
        }
    }

    private void rawSend(const(char)[] data) {
        while (data.length) {
            auto sent = socket.send(data);
            if (sent <= 0) {
                throw new NetworkException("Sending data to the proxy failed.");
            }
            data = data[sent..$];
        }
    }

    private void handshake(string host) {
        auto lib = OpenSSLLib.get();

        SSL_CTX* ctx;
        if (rootsOverride.length) {
            ctx = ownedCtx = lib.buildContext(rootsOverride);
        } else {
            ctx = trustsAppleRootOnly(host) ? lib.appleRootContext : lib.appleHostsContext;
        }

        ssl = lib.SSL_new(ctx);
        enforce!TlsVerificationException(ssl, "Cannot create a TLS session: " ~ lib.lastError());
        enforce!TlsVerificationException(lib.SSL_set_fd(ssl, cast(int) socket.handle) == 1, "Cannot attach the TLS session: " ~ lib.lastError());

        auto hostz = host.toStringz();
        // SNI
        enforce!TlsVerificationException(
            lib.SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, cast(void*) hostz) == 1,
            "Cannot set the TLS server name: " ~ lib.lastError()
        );
        // The certificate must be valid for this exact host.
        enforce!TlsVerificationException(lib.SSL_set1_host(ssl, hostz) == 1, "Cannot set the expected host name: " ~ lib.lastError());

        if (lib.SSL_connect(ssl) != 1) {
            auto verifyResult = lib.SSL_get_verify_result(ssl);
            if (verifyResult != X509_V_OK) {
                throw new TlsVerificationException(format!"The certificate presented by %s is not trusted (%s). Someone may be intercepting your connection."(
                    host, fromStringz(lib.X509_verify_cert_error_string(verifyResult))
                ));
            }
            throw new TlsVerificationException(format!"TLS handshake with %s failed: %s"(host, lib.lastError()));
        }

        // Belt and braces: never use a session whose verification did not pass.
        auto verifyResult = lib.SSL_get_verify_result(ssl);
        if (verifyResult != X509_V_OK) {
            throw new TlsVerificationException(format!"The certificate presented by %s is not trusted (%s)."(
                host, fromStringz(lib.X509_verify_cert_error_string(verifyResult))
            ));
        }
    }

    ptrdiff_t send(const(void)[] buff) {
        enforce!NetworkException(isConnected, "Not connected.");
        auto lib = OpenSSLLib.get();
        while (true) {
            auto written = lib.SSL_write(ssl, buff.ptr, cast(int) buff.length);
            auto e = errno;
            if (written > 0) {
                return written;
            }
            auto err = lib.SSL_get_error(ssl, written);
            if (err == SSL_ERROR_SYSCALL && e == core.stdc.errno.EINTR) continue;
            fatal = true;
            close();
            throw new NetworkException("Sending data failed: " ~ lib.lastError());
        }
    }

    ptrdiff_t receive(void[] buff) {
        if (!isConnected) {
            return 0;
        }
        auto lib = OpenSSLLib.get();
        while (true) {
            auto read = lib.SSL_read(ssl, buff.ptr, cast(int) buff.length);
            auto e = errno;
            if (read > 0) {
                return read;
            }
            auto err = lib.SSL_get_error(ssl, read);
            if (err == SSL_ERROR_ZERO_RETURN) {
                // Clean close (close_notify received).
                return 0;
            }
            if (err == SSL_ERROR_SYSCALL && read == 0 && e == 0) {
                // EOF without close_notify (OpenSSL 1.1 / LibreSSL; OpenSSL 3 reports it
                // as SSL_ERROR_SSL). A body delimited by Content-Length or chunked
                // encoding is still checked by requests; anything else may be truncated.
                getLogger().warn("TLS connection closed without close_notify; the response may be truncated.");
                fatal = true;
                return 0;
            }
            if (err == SSL_ERROR_SYSCALL && e == core.stdc.errno.EINTR) continue;
            fatal = true;
            close();
            if (err == SSL_ERROR_WANT_READ || (err == SSL_ERROR_SYSCALL && (e == core.stdc.errno.EAGAIN || e == core.stdc.errno.EWOULDBLOCK))) {
                throw new TimeoutException("Timeout receiving data");
            }
            throw new NetworkException("Receiving data failed: " ~ lib.lastError());
        }
    }

    void close() @trusted {
        auto wasConnected = connected;
        connected = false;
        if (ssl !is null) {
            auto lib = OpenSSLLib.get();
            // Never send close_notify after a fatal error (OpenSSL forbids it) or
            // on a connection whose handshake didn't complete.
            if (wasConnected && !fatal) {
                lib.SSL_shutdown(ssl);
            }
            lib.SSL_free(ssl);
            ssl = null;
        }
        if (ownedCtx !is null) {
            OpenSSLLib.get().SSL_CTX_free(ownedCtx);
            ownedCtx = null;
        }
        if (socket !is null) {
            socket.close();
            socket = null;
        }
    }

    @property void readTimeout(Duration timeout) {
        if (socket !is null) {
            socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout);
        }
    }

    NetworkStream accept() { assert(false, "Not supported."); }
    @property void reuseAddr(bool) { assert(false, "Not supported."); }
    void bind(string) { assert(false, "Not supported."); }
    void bind(Address) { assert(false, "Not supported."); }
    void listen(int) { assert(false, "Not supported."); }
}

// --- Minimal OpenSSL binding (OpenSSL >= 1.1.0 or LibreSSL >= 2.7) ---

import core.stdc.config: c_long, c_ulong;

private struct SSL;
private struct SSL_CTX;
private struct SSL_METHOD;
private struct X509;
private struct X509_STORE;

private enum SSL_VERIFY_PEER = 1;
private enum SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
private enum TLSEXT_NAMETYPE_host_name = 0;
private enum SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
private enum TLS1_2_VERSION = 0x0303;
private enum X509_V_OK = 0;
private enum SSL_ERROR_WANT_READ = 2;
private enum SSL_ERROR_SYSCALL = 5;
private enum SSL_ERROR_ZERO_RETURN = 6;

private final class OpenSSLLib {
    extern(C) nothrow @nogc {
        const(SSL_METHOD)* function() TLS_client_method;
        SSL_CTX* function(const(SSL_METHOD)*) SSL_CTX_new;
        void function(SSL_CTX*) SSL_CTX_free;
        c_long function(SSL_CTX*, int, c_long, void*) SSL_CTX_ctrl;
        X509_STORE* function(const(SSL_CTX)*) SSL_CTX_get_cert_store;
        void function(SSL_CTX*, int, void*) SSL_CTX_set_verify;
        SSL* function(SSL_CTX*) SSL_new;
        void function(SSL*) SSL_free;
        int function(SSL*, int) SSL_set_fd;
        c_long function(SSL*, int, c_long, void*) SSL_ctrl;
        int function(SSL*, const(char)*) SSL_set1_host;
        int function(SSL*) SSL_connect;
        c_long function(const(SSL)*) SSL_get_verify_result;
        int function(SSL*, void*, int) SSL_read;
        int function(SSL*, const(void)*, int) SSL_write;
        int function(SSL*) SSL_shutdown;
        int function(const(SSL)*, int) SSL_get_error;

        X509* function(X509**, const(ubyte)**, c_long) d2i_X509;
        void function(X509*) X509_free;
        int function(X509_STORE*, X509*) X509_STORE_add_cert;
        const(char)* function(c_long) X509_verify_cert_error_string;
        c_ulong function() ERR_get_error;
        void function(c_ulong, char*, size_t) ERR_error_string_n;
    }

    /// Shared, read-only after construction: one context per pinned root set.
    /// SSL_CTX is safe to use from several threads for SSL_new.
    SSL_CTX* appleRootContext;
    SSL_CTX* appleHostsContext;

    private __gshared OpenSSLLib instance;

    /// Thread-safe: initOnce publishes the fully constructed instance (and its
    /// function pointers) to every thread, which a plain double-checked lock on
    /// arm64's weak memory model would not guarantee.
    static OpenSSLLib get() {
        import std.concurrency: initOnce;
        return initOnce!instance(new OpenSSLLib());
    }

    /// A client context that requires TLS 1.2+, verifies the peer, and trusts only
    /// `roots` (DER). The system trust store is never loaded.
    SSL_CTX* buildContext(const(immutable(ubyte)[])[] roots) {
        auto ctx = SSL_CTX_new(TLS_client_method());
        enforce!TlsVerificationException(ctx, "Cannot create a TLS context: " ~ lastError());
        scope(failure) SSL_CTX_free(ctx);

        enforce!TlsVerificationException(
            SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, null) == 1,
            "Cannot require TLS 1.2: " ~ lastError()
        );

        auto store = SSL_CTX_get_cert_store(ctx);
        foreach (der; roots) {
            const(ubyte)* p = der.ptr;
            auto cert = d2i_X509(null, &p, cast(c_long) der.length);
            enforce!TlsVerificationException(cert, "Cannot parse a pinned root certificate: " ~ lastError());
            scope(exit) X509_free(cert);
            enforce!TlsVerificationException(X509_STORE_add_cert(store, cert) == 1, "Cannot load a pinned root certificate: " ~ lastError());
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null);
        return ctx;
    }

    string lastError() nothrow {
        auto code = ERR_get_error();
        if (!code) {
            return "unknown error";
        }
        char[256] buffer = 0;
        ERR_error_string_n(code, buffer.ptr, buffer.length);
        try {
            return fromStringz(buffer.ptr).idup;
        } catch (Exception) {
            return "unknown error";
        }
    }

    private this() {
        version (OSX) {
            // Prefer Homebrew's OpenSSL 3, then the versioned LibreSSL macOS ships.
            // (The unversioned /usr/lib/libssl.dylib aborts the process when loaded.)
            enum string[2][] candidates = [
                ["/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib", "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"],
                ["/usr/local/opt/openssl@3/lib/libssl.3.dylib", "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"],
                ["libssl.3.dylib", "libcrypto.3.dylib"],
                ["libssl.48.dylib", "libcrypto.46.dylib"],
                ["libssl.46.dylib", "libcrypto.44.dylib"],
                ["libssl.44.dylib", "libcrypto.42.dylib"],
                ["libssl.43.dylib", "libcrypto.41.dylib"],
            ];
        } else version (Windows) {
            enum string[2][] candidates = [
                ["libssl-3-x64.dll", "libcrypto-3-x64.dll"],
                ["libssl-3.dll", "libcrypto-3.dll"],
                ["libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll"],
                ["libssl-1_1.dll", "libcrypto-1_1.dll"],
            ];
        } else {
            enum string[2][] candidates = [
                ["libssl.so.3", "libcrypto.so.3"],
                ["libssl.so.1.1", "libcrypto.so.1.1"],
                ["libssl.so", "libcrypto.so"],
            ];
        }

        void* ssl, crypto;
        string chosen;
        foreach (candidate; candidates) {
            ssl = openLibrary(candidate[0]);
            if (!ssl) continue;
            crypto = openLibrary(candidate[1]);
            if (crypto) { chosen = candidate[0]; break; }
            ssl = null;
        }
        if (!ssl || !crypto) {
            throw new TlsVerificationException("OpenSSL (1.1 or newer) could not be found. It is needed for secure connections.");
        }
        getLogger().debugF!"Using OpenSSL library: %s"(chosen);

        static foreach (member; [
            "TLS_client_method", "SSL_CTX_new", "SSL_CTX_free", "SSL_CTX_ctrl", "SSL_CTX_get_cert_store",
            "SSL_CTX_set_verify", "SSL_new", "SSL_free", "SSL_set_fd", "SSL_ctrl", "SSL_set1_host",
            "SSL_connect", "SSL_get_verify_result", "SSL_read", "SSL_write", "SSL_shutdown", "SSL_get_error",
        ]) {
            mixin(member) = cast(typeof(mixin(member))) loadSymbol(ssl, member);
        }
        static foreach (member; [
            "d2i_X509", "X509_free", "X509_STORE_add_cert", "X509_verify_cert_error_string",
            "ERR_get_error", "ERR_error_string_n",
        ]) {
            mixin(member) = cast(typeof(mixin(member))) loadSymbol(crypto, member);
        }

        appleRootContext = buildContext([appleRootCA]);
        appleHostsContext = buildContext([appleRootCA, digiCertGlobalRootG2]);

        version (Posix) {
            // On Linux, OpenSSL writes with write(), not send(MSG_NOSIGNAL), so a
            // reset connection would raise SIGPIPE and kill the process. Ignore it,
            // unless the application already installed its own handler.
            import core.sys.posix.signal: sigaction, sigaction_t, SIGPIPE, SIG_DFL, SIG_IGN;
            sigaction_t current;
            if (sigaction(SIGPIPE, null, &current) == 0 && current.sa_handler == SIG_DFL) {
                sigaction_t ignore;
                ignore.sa_handler = SIG_IGN;
                sigaction(SIGPIPE, &ignore, null);
            }
        }
    }

    private static void* openLibrary(string name) {
        version (Windows) {
            import core.sys.windows.winbase: LoadLibraryW;
            import std.utf: toUTF16z;
            return cast(void*) LoadLibraryW(name.toUTF16z());
        } else {
            import core.sys.posix.dlfcn: dlopen, RTLD_LAZY;
            return dlopen(name.toStringz(), RTLD_LAZY);
        }
    }

    private static void* loadSymbol(void* library, string name) {
        version (Windows) {
            import core.sys.windows.winbase: GetProcAddress;
            import core.sys.windows.windef: HMODULE;
            auto symbol = cast(void*) GetProcAddress(cast(HMODULE) library, name.toStringz());
        } else {
            import core.sys.posix.dlfcn: dlsym;
            auto symbol = dlsym(library, name.toStringz());
        }
        if (!symbol) {
            throw new TlsVerificationException(format!"The installed OpenSSL is too old: %s is missing (OpenSSL 1.1 or newer is needed)."(name));
        }
        return symbol;
    }
}
