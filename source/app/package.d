module app;

import file = std.file;
import std.math;
import std.path;
import std.zip;

import slf4d;

import requests;

import plist;

import provision;

import constants;
import libplistloader;
import server.tls;
import utils;

struct ProvisioningData {
    Device device;
    ADI adi;
}

bool downloadAndInstallDeps(string configurationPath, bool delegate(float progress) downloadCallback) {
    auto log = getLogger();

    log.info("Downloading APK...");
    Request request = secureRequest();
    request.useStreaming = true;

    auto response = request.get(nativesUrl);
    auto responseStream = response.receiveAsRange();

    auto size = cast(float) response.contentLength;
    size = size ? size : 150_000_000.0 /+ Rough estimate if we don't know the exact size. +/;

    ubyte[] apkData;
    while(!responseStream.empty) {
        if (downloadCallback(cast(float) response.contentReceived / size))
            return false;
        apkData ~= responseStream.front;
        responseStream.popFront();
    }
    downloadCallback(1.);

    auto apk = new ZipArchive(apkData);
    auto dir = apk.directory();

    string libPath = configurationPath.buildPath("lib");
    if (!file.exists(libPath)) {
        file.mkdirRecurse(libPath);
    }

    version (X86_64) {
        enum string architectureIdentifier = "x86_64";
    } else version (X86) {
        enum string architectureIdentifier = "x86";
    } else version (AArch64) {
        enum string architectureIdentifier = "arm64-v8a";
    } else version (ARM) {
        enum string architectureIdentifier = "armeabi-v7a";
    } else {
        static assert(false, "Architecture not supported :(");
    }
    file.write(libPath.buildPath("libCoreADI.so"), apk.expand(dir["lib/" ~ architectureIdentifier ~ "/libCoreADI.so"]));
    file.write(libPath.buildPath("libstoreservicescore.so"), apk.expand(dir["lib/" ~ architectureIdentifier ~ "/libstoreservicescore.so"]));
    log.info("Extracted successfully!");
    return true;
}

ProvisioningData initializeADI(string configurationPath) {
    auto log = getLogger();
    if (!ensureLibplistLoaded()) {
        log.warn("libplist could not be found; install it (on macOS: brew install libplist).");
    }
    auto device = new Device(configurationPath.buildPath("device.json"));

    if (!device.initialized) {
        log.info("Creating device...");

        import std.digest;
        import std.random;
        import std.range;
        import std.uni;
        import std.uuid;
        device.serverFriendlyDescription = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        device.uniqueDeviceIdentifier = randomUUID().toString().toUpper();
        device.adiIdentifier = (cast(ubyte[]) rndGen.take(2).array()).toHexString().toLower();
        device.localUserUUID = (cast(ubyte[]) rndGen.take(8).array()).toHexString().toUpper();
        log.info("Device created successfully.");
    }
    log.debug_("Device OK.");

    auto adi = new ADI(configurationPath.buildPath("lib"));
    adi.provisioningPath = configurationPath;
    adi.identifier = device.adiIdentifier;

    if (!adi.isMachineProvisioned(-2)) {
        log.info("Provisioning device...");

        provisionDevice(adi, device, -2);
        log.info("Device provisioned successfully.");
    }
    log.debug_("Provisioning OK.");

    return ProvisioningData(device, adi);
}

/++
 + Registers this machine's anisette identity with Apple.
 +
 + This is Provision's `ProvisioningSession.provision`, reimplemented here because
 + that class always disables certificate verification on its private HTTP client.
 + Here every request goes through `secureRequest()`, which verifies and pins TLS.
 +/
void provisionDevice(ADI adi, Device device, ulong dsId) {
    import std.base64;
    import std.datetime.systime;
    import std.format;

    Request request = secureRequest();
    request.addHeaders([
        "User-Agent": "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0",

        // they are somehow not using the plist content-type in AuthKit
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",

        "X-Mme-Device-Id": device.uniqueDeviceIdentifier,
        "X-MMe-Client-Info": device.serverFriendlyDescription,
        "X-Apple-I-MD-LU": device.localUserUUID,
        "X-Apple-Client-App-Name": "Setup",
    ]);

    string[string] urlBag;
    {
        auto lookup = Plist.fromXml(request.get("https://gsa.apple.com/grandslam/GsService2/lookup").responseBody.data!string())["urls"].dict().native();
        foreach (key, url; lookup) {
            urlBag[key] = url.str().native();
        }
    }

    enum plistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Header</key>
	<dict/>
	<key>Request</key>
`;

    request.addHeaders(["X-Apple-I-Client-Time": Clock.currTime().stripMilliseconds().toISOExtString()]);
    string startProvisioningPlist = request.post(
        urlBag["midStartProvisioning"],
        plistHeader ~ "\t<dict/>\n</dict>\n</plist>"
    ).responseBody.data!string();

    ubyte[] spim = Base64.decode(Plist.fromXml(startProvisioningPlist)["Response"].dict()["spim"].str().native());

    auto cpim = adi.startProvisioning(dsId, spim);
    scope (failure) try { adi.destroyProvisioning(cpim.session); } catch (Throwable) {}

    request.addHeaders(["X-Apple-I-Client-Time": Clock.currTime().stripMilliseconds().toISOExtString()]);
    string endProvisioningPlist = request.post(
        urlBag["midFinishProvisioning"],
        plistHeader ~ format!"\t<dict>\n\t\t<key>cpim</key>\n\t\t<string>%s</string>\n\t</dict>\n</dict>\n</plist>"(
            Base64.encode(cpim.clientProvisioningIntermediateMetadata)
        )
    ).responseBody.data!string();

    auto response = Plist.fromXml(endProvisioningPlist)["Response"].dict();
    ubyte[] persistentTokenMetadata = Base64.decode(response["ptm"].str().native());
    ubyte[] trustKey = Base64.decode(response["tk"].str().native());

    adi.endProvisioning(cpim.session, persistentTokenMetadata, trustKey);
}
