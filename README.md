# ZydisDriverDemo
using Zydis via git submodule and msvc

# Zydis Kernel Module Library

```bash
mkdir deps
git submodule add 'https://github.com/zyantific/zydis.git' deps/zydis
git submodule update --init --recursive
```

# Zydis include

../deps/zydis/dependencies/zycore/include

../deps/zydis/include

# Zydis Preprocessor

ZYAN_NO_LIBC

ZYDIS_NO_LIBC

ZYCORE_STATIC_BUILD

ZYDIS_STATIC_BUILD

# Zydis library

## x86 Debug

../deps/zydis/msvc/bin/DebugX86Kernel

## x86 Release

../deps/zydis/msvc/bin/ReleaseX86Kernel

## x64 Debug

../deps/zydis/msvc/bin/DebugX64Kernel

## x64 Release

../deps/zydis/msvc/bin/ReleaseX64Kernel
