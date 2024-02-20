//
//  kern_start.cpp
//  TeraScaleFixup.kext
//
//  Copyright ©2024 Jazzzny. All rights reserved.
//

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>
#include <Headers/kern_devinfo.hpp>

#define MODULE_SHORT "TeraScaleFixup"

static mach_vm_address_t orig_cs_validate {};
static mach_vm_address_t orig_authenticate_root_hash {};

// Patch for 10.7
static UInt8 findLion[] =    { 0x48, 0x0F, 0xA3, 0xD8, 0x0F, 0x83, 0x24, 0xFF, 0xFF, 0xFF, 0xBF, 0x58 };
static UInt8 replaceLion[] = { 0x48, 0x0F, 0xA3, 0xD8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xBF, 0x58 };

// Patch for 10.8
static UInt8 findMountainLion[] =    { 0x0F, 0xA3, 0xCA, 0x0F, 0x83, 0xAE, 0x01, 0x00, 0x00, 0xBF, 0xC8, 0x05 };
static UInt8 replaceMountainLion[] = { 0x0F, 0xA3, 0xCA, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xBF, 0xC8, 0x05 };

// Patch for 10.9
static UInt8 findMavericks[] =    { 0x48, 0x0F, 0xA3, 0xC1, 0x0F, 0x83, 0x94, 0x01, 0x00, 0x00, 0xBF, 0x10 };
static UInt8 replaceMavericks[] = { 0x48, 0x0F, 0xA3, 0xC1, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xBF, 0x10 };

// Patch for 10.10
static UInt8 findYosemite[] =    { 0x04, 0x48, 0x0F, 0xA3, 0xCA, 0x0F, 0x83, 0x9B, 0x01, 0x00, 0x00, 0xBF };
static UInt8 replaceYosemite[] = { 0x04, 0x48, 0x0F, 0xA3, 0xCA, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xBF };

// Patch for 10.11
static UInt8 findElCapitan[] =    { 0xFF, 0x83, 0xF9, 0x1A, 0x0F, 0x87, 0x98, 0x01, 0x00, 0x00, 0xBA, 0x45, 0x44, 0x00, 0x04, 0x0F, 0xA3, 0xCA, 0x0F, 0x83, 0x8A, 0x01, 0x00, 0x00 };
static UInt8 replaceElCapitan[] = { 0xFF, 0x83, 0xF9, 0x3A, 0x0F, 0x87, 0x98, 0x01, 0x00, 0x00, 0xBA, 0x45, 0x44, 0x00, 0x04, 0x0F, 0xA3, 0xCA, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

// Patch for 10.12
static UInt8 findSierra[] =    { 0x00, 0x01, 0x48, 0x0F, 0xA3, 0xCA, 0x0F, 0x83, 0xA2, 0x00, 0x00, 0x00 };
static UInt8 replaceSierra[] = { 0x00, 0x01, 0x48, 0x0F, 0xA3, 0xCA, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };


// Patch for 10.13 (and above)
static UInt8 findHighSierra[] =    { 0x0F, 0xA3, 0xCA, 0x0F, 0x83, 0xC3, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x06 };
static UInt8 replaceHighSierra[] = { 0x0F, 0xA3, 0xCA, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xBF, 0x00, 0x06 };

static const char *kextX2000[] {
	"/System/Library/Extensions/ATIRadeonX2000.kext/Contents/MacOS/ATIRadeonX2000"
};

static KernelPatcher::KextInfo kextList[] {
	{"com.apple.ATIRadeonX2000", kextX2000, arrsize(kextX2000), {true}, {}, KernelPatcher::KextInfo::Unloaded },
};


#pragma mark - Kernel patching code

static void processKext(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
	// Check ATIRadeonX2000 is loaded
	if (index != kextList[0].loadIndex) {
		return;
	}

	const KernelPatcher::LookupPatch patchLion = {
		&kextList[0],
		findLion,
		replaceLion,
		sizeof(findLion),
		1
	};
    
    const KernelPatcher::LookupPatch patchMountainLion = {
        &kextList[0],
        findMountainLion,
        replaceMountainLion,
        sizeof(findMountainLion),
        1
    };
    
    const KernelPatcher::LookupPatch patchMavericks = {
        &kextList[0],
        findMavericks,
        replaceMavericks,
        sizeof(findMavericks),
        1
    };
    
    const KernelPatcher::LookupPatch patchYosemite = {
        &kextList[0],
        findYosemite,
        replaceYosemite,
        sizeof(findYosemite),
        1
    };
    
    const KernelPatcher::LookupPatch patchElCapitan = {
        &kextList[0],
        findElCapitan,
        replaceElCapitan,
        sizeof(findElCapitan),
        1
    };
    
    const KernelPatcher::LookupPatch patchSierra = {
        &kextList[0],
        findSierra,
        replaceSierra,
        sizeof(findSierra),
        1
    };
    
    const KernelPatcher::LookupPatch patchHighSierra = {
        &kextList[0],
        findHighSierra,
        replaceHighSierra,
        sizeof(findHighSierra),
        1
    };
    
    switch (getKernelVersion()) {
        case KernelVersion::Lion:
            patcher.applyLookupPatch(&patchLion);
            break;
        case KernelVersion::MountainLion:
            patcher.applyLookupPatch(&patchMountainLion);
            break;
        case KernelVersion::Mavericks:
            patcher.applyLookupPatch(&patchMavericks);
            break;
        case KernelVersion::Yosemite:
            patcher.applyLookupPatch(&patchYosemite);
            break;
        case KernelVersion::ElCapitan:
            patcher.applyLookupPatch(&patchElCapitan);
            break;
        case KernelVersion::Sierra:
            patcher.applyLookupPatch(&patchSierra);
            break;
        case KernelVersion::HighSierra:
            patcher.applyLookupPatch(&patchHighSierra);
            break;
        default: // Assume kexts are installed and functional - no harm is done if they are not present.
            patcher.applyLookupPatch(&patchHighSierra);
    }
    
	if (patcher.getError() != KernelPatcher::Error::NoError) {
		SYSLOG(MODULE_SHORT, "Failed to apply ATIRadeonX2000 patch");
		patcher.clearError();
	}
    else {
        SYSLOG(MODULE_SHORT, "ATIRadeonX2000 patch applied");
    }
}


#pragma mark - Patches on start/stop

static void pluginStart() {
	DBGLOG(MODULE_SHORT, "start");

	// Kernel Space Patcher
    lilu.onKextLoadForce(kextList, arrsize(kextList),
							[](void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
		processKext(patcher, index, address, size);
	}, nullptr);
}

// Boot args.
static const char *bootargOff[] {
	"-terascaleoff"
};
static const char *bootargDebug[] {
	"-terascaledbg"
};
static const char *bootargBeta[] {
	"-terascalebeta"
};

// Plugin configuration.
PluginConfiguration ADDPR(config) {
	xStringify(PRODUCT_NAME),
	parseModuleVersion(xStringify(MODULE_VERSION)),
	LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery | LiluAPI::AllowSafeMode,
	bootargOff,
	arrsize(bootargOff),
	bootargDebug,
	arrsize(bootargDebug),
	bootargBeta,
	arrsize(bootargBeta),
	KernelVersion::Lion,
	KernelVersion::Sonoma,
	pluginStart
};
