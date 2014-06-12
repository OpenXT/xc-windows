BUILDDIR=build
TARGETPATH=$(TOPDIR)\$(BUILDDIR)
!if defined(USERSPACE)
INCLUDES=$(TOPDIR)\inc
!else
INCLUDES=$(DDK_INC_PATH);$(TOPDIR)\inc
!endif

# Sigh... If _BUILDARCH is x86, the DDK build scripts put binaries in
# BUILDDIR\i386.  Otherwise, they go in BUILDDIR\_BUILDARCH.
# Because, you know, it's obviously impossible to decide on a single
# name for a processor.
!if "$(_BUILDARCH)" == "x86"
BUILDDIR_ARCH=$(BUILDDIR)\i386
!else
BUILDDIR_ARCH=$(BUILDDIR)\amd64
!endif
TARGETPATH_ARCH=$(TOPDIR)\$(BUILDDIR_ARCH)

# Warning 4127 is ``conditional expression is constant'', and is
# triggered by do {} while (0).  This is by far the most convenient
# way of writing multi-statement macros, and so the warning should be
# disabled.
MSC_WARNING_LEVEL=/W4 /WX /wd4127
# We need the library version of ntstrsafe.h, since we need to work
# on Windows 2000.
C_DEFINES=-DNTSTRSAFE_LIB

# Userspace stuff needs to be built for windows 2000 or it won't run
# (you get ``... is not a valid Win32 application.'' popups, and
# access denied errors from CreateProcess).
!if defined(USERSPACE)
_NT_TARGET_VERSION=$(_NT_TARGET_VERSION_WIN2K)
!endif
