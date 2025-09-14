# Frida Fruity Debug Logging

This document describes the conditional debug logging implementation for the Frida Fruity components.

## Overview

I have implemented conditional debug logging for the Frida Fruity iOS device communication subsystem. The debug logging is controlled by the `FRIDA_FRUITY_DEBUG` environment variable.

## Usage

### Enable Debug Logs
```bash
export FRIDA_FRUITY_DEBUG=1
frida-ls-devices  # or any other frida command that uses iOS devices
```

### Disable Debug Logs
```bash
unset FRIDA_FRUITY_DEBUG
# or simply don't set the variable
frida-ls-devices  # logs will be suppressed
```

## Implementation Details

### Shared Debug Module
Created `src/fruity/debug.vala` with a shared debug logging function:

```vala
[CCode (lower_case_cprefix = "frida_fruity_debug_", cheader_filename = "fruity-debug.h")]
namespace Frida.Fruity.Debug {
    private static bool debug_enabled = false;
    private static bool debug_checked = false;

    public static void log (string format, ...) {
        if (!debug_checked) {
            debug_enabled = Environment.get_variable ("FRIDA_FRUITY_DEBUG") != null;
            debug_checked = true;
        }
        if (debug_enabled) {
            var args = va_list ();
            stderr.vprintf (format, args);
        }
    }
}
```

### Debug Statement Replacement

All existing debug statements in the following files have been changed from:
```vala
stderr.printf ("[FRIDA-*] Some debug message\n");
```

To:
```vala
Debug.log ("[FRIDA-*] Some debug message\n");
```

### Affected Files

The following files now use conditional debug logging:
- `src/fruity/device-monitor.vala` - Device discovery and management
- `src/fruity/lockdown.vala` - iOS lockdown daemon communication
- `src/fruity/dtx.vala` - Device info and app listing services
- `src/fruity/injector.vala` - Code injection functionality
- `src/fruity/plist-service.vala` - Property list service communication
- `src/fruity/usb.vala` - USB device handling
- `src/fruity/usbmux.vala` - USB multiplexer communication
- `src/fruity/fruity-host-session.vala` - Host session management

### Debug Output Categories

The debug logs cover several key areas:

- **Device Monitor**: Device attachment/detachment, transport management
- **Lockdown**: iOS lockdown service connections and authentication
- **DTX**: Device info queries and application listing
- **Injector**: Code injection and gadget deployment
- **USB/USBMux**: Low-level USB communication and multiplexing
- **Host Sessions**: Session creation and lifecycle management

### Performance Impact

- **When disabled** (default): Zero performance impact - environment variable is checked only once per process
- **When enabled**: Minimal impact - only adds formatted string output to stderr

## Benefits

1. **Clean logs by default**: No debug spam in normal operation
2. **Easy debugging**: Set one environment variable to see detailed iOS communication flow
3. **Selective debugging**: Only Fruity subsystem logs are affected, other Frida logs unchanged
4. **Zero runtime cost when disabled**: Environment variable checked only once per process
5. **Maintainable**: Centralized debug logic, easy to modify behavior

## Example Debug Output

When `FRIDA_FRUITY_DEBUG=1` is set, you'll see output like:

```
[FRIDA-DEVICE-MONITOR] Starting device monitor with 2 backends
[FRIDA-DEVICE-MONITOR] Starting backend: FridaFruityUsbmuxBackend
[FRIDA-USBMUX-BACKEND] Starting USB mux backend
[FRIDA-DEVICE-MONITOR] Device attached: iPhone (UDID: 1234567890abcdef)
[FRIDA-LOCKDOWN] Opening lockdown client for device: 1234567890abcdef
[FRIDA-LOCKDOWN] Creating lockdown client
[FRIDA-DTX] Opening DeviceInfoService
[FRIDA-DTX] DeviceInfoService opened successfully
```


---

Based on my analysis of the Frida project structure, here's what you need to know about building and modifying
  the Frida gadget for iOS:

  Key Frida Gadget Files and Structure

  Main Subproject: `subprojects/frida-core` - This contains the primary gadget code.

  Core Gadget Files (in `subprojects/frida-core/lib/gadget/`):

  1. Main Implementation:
    - `gadget.vala:1-2210` - Core gadget logic, configuration, and controllers
    - `gadget-glue.c` - C glue code connecting Vala to C APIs
    - `gadget-darwin.m:1-54` - iOS/macOS-specific code for bundle detection
  2. Build Configuration:
    - `meson.build:1-122` - Build system configuration for gadget compilation
    - `frida-gadget.symbols` - Exported symbols list
    - `frida-gadget.def` - Windows module definition
    - `frida-gadget.version` - Linux version script
  3. iOS-Specific: Each subproject has `releng/modules/frida-gadget-ios/` for iOS build configuration.

  Key Components for Listen Port and Main Functionality:

  1. Listen Port Configuration (`gadget.vala`):
    - SocketInteraction class (lines 239-259): Base class defining address and port properties
    - ListenInteraction class (lines 261-288): Handles listen mode configuration
    - Port conflict behavior defined at lines 262-266
    - Listen port logic at lines 652-659
  2. Main Gadget Entry Points:
    - load() function (lines 455-556): Main gadget initialization
    - ControlServer class (lines 1456+): Handles incoming connections for listen mode
    - Configuration parsing at lines 717-775
  3. iOS-Specific Code:
    - Bundle ID detection: `gadget-darwin.m:8-15`
    - Documents directory detection: `gadget-darwin.m:28-40`
    - Framework resource directory handling: `gadget.vala:2066-2083`

  Files to Modify for Changes:

  1. Port Configuration: Modify `gadget.vala:245-248` (port property in SocketInteraction)
  2. Listen Behavior: Modify `gadget.vala:261-288` (ListenInteraction class)
  3. iOS Bundle Handling: Modify `gadget-darwin.m:8-40`
  4. Build for iOS: Use `meson.build:89-102` for iOS-specific build configuration
  5. Main Initialization: Modify `gadget.vala:455-556` (load() function)

  Building Process:

  The gadget builds as:
  1. Raw library (libfrida-gadget-raw)
  2. Modulated library (constructor/destructor reordering)
  3. Final processed library (FridaGadget.dylib for iOS)

  For iOS, the gadget identity is set to `@executable_path/Frameworks/FridaGadget.dylib` (line 92).

  This structure allows you to modify listen port behavior, main gadget functionality, and iOS-specific features
  by editing the appropriate files in the frida-core/lib/gadget/ directory.


  --- Just notes - ignore this --

  Here are the common and advanced techniques used to detect Frida hooking in iOS
  apps:

  Process-Based Detection

  1. Process Name Detection
  - Check for frida-server process using sysctl or /proc
  - Scan running processes for Frida-related names

  2. Port Scanning
  - Default Frida port 27042 detection
  - TCP port enumeration for listening services

  3. Library Loading Detection
  - Check for FridaGadget.dylib in loaded libraries
  - Monitor dlopen() calls for suspicious libraries
  - Inspect /proc/self/maps for injected libraries

  Memory-Based Detection

  4. Memory Pattern Scanning
  - Search heap/stack for Frida signatures
  - Look for JavaScript engine artifacts (V8/Duktape strings)
  - Scan for Frida's internal data structures

  5. Code Integrity Checks
  - Calculate checksums of critical functions
  - Detect inline hooking modifications
  - Monitor unexpected RWX memory regions

  6. Exception Handler Manipulation
  - Detect changes to signal handlers
  - Monitor mach_msg modifications used by Frida

  Runtime Detection

  7. Function Hook Detection
  - Compare function pointers against expected addresses
  - Detect trampolines and jump instructions
  - Monitor GOT/PLT table modifications

  8. Anti-Debugging Techniques
  - ptrace(PT_DENY_ATTACH) to prevent attachment
  - sysctl checks for debugger presence
  - Exception-based debugger detection

  9. Dynamic Analysis Detection
  - Monitor suspicious API call patterns
  - Detect rapid function calls (automation signatures)
  - Check for artificial delays or timing anomalies

  iOS-Specific Detection

  10. Jailbreak Detection
  - Check for common jailbreak files/paths
  - Verify code signing and sandbox integrity
  - Test filesystem permissions outside sandbox

  11. Substrate/Substitute Detection
  - Look for MobileSubstrate.dylib
  - Check for substrate-related processes
  - Monitor Cydia installation artifacts

  12. App Store vs. Side-loading Detection
  - Verify provisioning profile authenticity
  - Check bundle signature integrity
  - Detect enterprise certificate abuse

  Advanced RASP Techniques

  13. Machine Learning Behavioral Detection
  - Pattern recognition for hooking behaviors
  - Anomaly detection in function call graphs
  - Statistical analysis of execution patterns

  14. Kernel-Level Protection
  - Custom kernel extensions (kexts) for monitoring
  - Hardware security features (TrustZone)
  - Hypervisor-based protection

  15. Network-Based Detection
  - Monitor for Frida's network communications
  - Detect USB forwarding tools (usbmuxd)
  - Analyze traffic patterns to Frida servers

  Evasion-Resistant Methods

  16. White-box Cryptography
  - Hide detection logic in obfuscated crypto
  - Tamper-evident key derivation
  - Remote attestation protocols

  17. Control Flow Integrity
  - Hardware-assisted CFI (ARM Pointer Authentication)
  - Shadow stack implementations
  - Indirect call validation

  18. Environmental Validation
  - Device fingerprinting consistency checks
  - Hardware feature validation
  - Secure enclave attestation

  Implementation Considerations

  Most commercial RASP solutions combine multiple techniques:
  - Layered approach: Multiple detection vectors
  - Time-based checks: Periodic validation
  - Obfuscation: Hide detection mechanisms
  - Server-side validation: Remote verification
  - Gradual degradation: Subtle functionality reduction vs. immediate crash

  The most effective solutions use a combination of runtime checks, static analysis
  integration, and behavioral monitoring rather than relying on single detection
  methods.
