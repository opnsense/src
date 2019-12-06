# $FreeBSD$

.include <bsd.init.mk>

LIB=		clang_rt.cfi-${CRTARCH}

SRCS+=		interception/interception_linux.cc
SRCS+=		interception/interception_mac.cc
SRCS+=		interception/interception_type_test.cc
SRCS+=		interception/interception_win.cc
SRCS+=		cfi/cfi.cc
SRCS+=		sanitizer_common/sanitizer_allocator.cc
SRCS+=		sanitizer_common/sanitizer_common.cc
SRCS+=		sanitizer_common/sanitizer_common_nolibc.cc
SRCS+=		sanitizer_common/sanitizer_deadlock_detector1.cc
SRCS+=		sanitizer_common/sanitizer_deadlock_detector2.cc
SRCS+=		sanitizer_common/sanitizer_errno.cc
SRCS+=		sanitizer_common/sanitizer_file.cc
SRCS+=		sanitizer_common/sanitizer_flag_parser.cc
SRCS+=		sanitizer_common/sanitizer_flags.cc
SRCS+=		sanitizer_common/sanitizer_libc.cc
SRCS+=		sanitizer_common/sanitizer_libignore.cc
SRCS+=		sanitizer_common/sanitizer_linux.cc
SRCS+=		sanitizer_common/sanitizer_mac.cc
SRCS+=		sanitizer_common/sanitizer_persistent_allocator.cc
SRCS+=		sanitizer_common/sanitizer_platform_limits_linux.cc
SRCS+=		sanitizer_common/sanitizer_platform_limits_posix.cc
SRCS+=		sanitizer_common/sanitizer_posix.cc
SRCS+=		sanitizer_common/sanitizer_printf.cc
SRCS+=		sanitizer_common/sanitizer_procmaps_bsd.cc
SRCS+=		sanitizer_common/sanitizer_procmaps_common.cc
SRCS+=		sanitizer_common/sanitizer_procmaps_linux.cc
SRCS+=		sanitizer_common/sanitizer_procmaps_mac.cc
SRCS+=		sanitizer_common/sanitizer_stackdepot.cc
SRCS+=		sanitizer_common/sanitizer_stacktrace.cc
SRCS+=		sanitizer_common/sanitizer_stacktrace_printer.cc
SRCS+=		sanitizer_common/sanitizer_suppressions.cc
SRCS+=		sanitizer_common/sanitizer_symbolizer.cc
SRCS+=		sanitizer_common/sanitizer_symbolizer_libbacktrace.cc
SRCS+=		sanitizer_common/sanitizer_symbolizer_mac.cc
SRCS+=		sanitizer_common/sanitizer_symbolizer_win.cc
SRCS+=		sanitizer_common/sanitizer_termination.cc
SRCS+=		sanitizer_common/sanitizer_thread_registry.cc
SRCS+=		sanitizer_common/sanitizer_tls_get_addr.cc
SRCS+=		sanitizer_common/sanitizer_win.cc

.if ${MK_LLD_IS_LD} != "no" && ${MK_CLANG_IS_CC} != "no" # && ${MK_CROSS_DSO_CFI} == "no"
CFLAGS+=	-flto
CXXFLAGS+=	-flto
LDFLAGS+=	-flto
.endif

.include <bsd.lib.mk>
