/*-
 * Copyright (c) 1998 Robert Nordier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are freely
 * permitted provided that the above copyright notice and this
 * paragraph and the following disclaimer are duplicated in all
 * such forms.
 *
 * This software is provided "AS IS" and without any express or
 * implied warranties, including, without limitation, the implied
 * warranties of merchantability and fitness for a particular
 * purpose.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/disklabel.h>
#include <sys/diskmbr.h>
#include <sys/dirent.h>
#include <sys/reboot.h>

#include <machine/bootinfo.h>
#include <machine/elf.h>

#include <stdarg.h>

#include <a.out.h>

#include <btxv86.h>

#include "boot2.h"
#include "lib.h"

#define IO_KEYBOARD	1
#define IO_SERIAL	2

#define SECOND		18	/* Circa that many ticks in a second. */

#define RBX_ASKNAME	0x0	/* -a */
#define RBX_SINGLE	0x1	/* -s */
/* 0x2 is reserved for log2(RB_NOSYNC). */
/* 0x3 is reserved for log2(RB_HALT). */
/* 0x4 is reserved for log2(RB_INITNAME). */
#define RBX_DFLTROOT	0x5	/* -r */
#define RBX_KDB 	0x6	/* -d */
/* 0x7 is reserved for log2(RB_RDONLY). */
/* 0x8 is reserved for log2(RB_DUMP). */
/* 0x9 is reserved for log2(RB_MINIROOT). */
#define RBX_CONFIG	0xa	/* -c */
#define RBX_VERBOSE	0xb	/* -v */
#define RBX_SERIAL	0xc	/* -h */
#define RBX_CDROM	0xd	/* -C */
/* 0xe is reserved for log2(RB_POWEROFF). */
#define RBX_GDB 	0xf	/* -g */
#define RBX_MUTE	0x10	/* -m */
/* 0x11 is reserved for log2(RB_SELFTEST). */
/* 0x12 is reserved for boot programs. */
/* 0x13 is reserved for boot programs. */
#define RBX_PAUSE	0x14	/* -p */
#define RBX_QUIET	0x15	/* -q */
#define RBX_NOINTR	0x1c	/* -n */
/* 0x1d is reserved for log2(RB_MULTIPLE) and is just misnamed here. */
#define RBX_DUAL	0x1d	/* -D */
/* 0x1f is reserved for log2(RB_BOOTINFO). */

/* pass: -a, -s, -r, -d, -c, -v, -h, -C, -g, -m, -p, -D */
#define RBX_MASK	(OPT_SET(RBX_ASKNAME) | OPT_SET(RBX_SINGLE) | \
			OPT_SET(RBX_DFLTROOT) | OPT_SET(RBX_KDB ) | \
			OPT_SET(RBX_CONFIG) | OPT_SET(RBX_VERBOSE) | \
			OPT_SET(RBX_SERIAL) | OPT_SET(RBX_CDROM) | \
			OPT_SET(RBX_GDB ) | OPT_SET(RBX_MUTE) | \
			OPT_SET(RBX_PAUSE) | OPT_SET(RBX_DUAL))

#define PATH_DOTCONFIG	"/boot.config"
#define PATH_CONFIG	"/boot/config"
#define PATH_BOOT3	"/boot/loader"
#define PATH_KERNEL	"/boot/kernel/kernel"

#define ARGS		0x900
#define NOPT		14
#define NDEV		3
#define MEM_BASE	0x12
#define MEM_EXT 	0x15

#define DRV_HARD	0x80
#define DRV_MASK	0x7f

#define TYPE_AD		0
#define TYPE_DA		1
#define TYPE_MAXHARD	TYPE_DA
#define TYPE_FD		2

#define OPT_SET(opt)	(1 << (opt))
#define OPT_CHECK(opt)	((opts) & OPT_SET(opt))

extern uint32_t _end;

static const char optstr[NOPT] = "DhaCcdgmnpqrsv"; /* Also 'P', 'S' */
static const unsigned char flags[NOPT] = {
    RBX_DUAL,
    RBX_SERIAL,
    RBX_ASKNAME,
    RBX_CDROM,
    RBX_CONFIG,
    RBX_KDB,
    RBX_GDB,
    RBX_MUTE,
    RBX_NOINTR,
    RBX_PAUSE,
    RBX_QUIET,
    RBX_DFLTROOT,
    RBX_SINGLE,
    RBX_VERBOSE
};

static const char *const dev_nm[NDEV] = {"ad", "da", "fd"};
static const unsigned char dev_maj[NDEV] = {30, 4, 2};

static struct dsk {
    unsigned drive;
    unsigned type;
    unsigned unit;
    uint8_t slice;
    uint8_t part;
    unsigned start;
    int init;
} dsk;
static char cmd[512], cmddup[512], knamebuf[1024];
static const char *kname;
static uint32_t opts;
static int comspeed = SIOSPD;
static struct bootinfo bootinfo;
static uint8_t ioctrl = IO_KEYBOARD;

void exit(int);
static void load(void);
static int parse(void);
static int dskread(void *, unsigned, unsigned);
static void printf(const char *,...);
static void putchar(int);
static int drvread(void *, unsigned, unsigned);
static int keyhit(unsigned);
static int xputc(int);
static int xgetc(int);
static inline int getc(int);

static void memcpy(void *, const void *, int);
static void
memcpy(void *dst, const void *src, int len)
{
    const char *s = src;
    char *d = dst;

    while (len--)
        *d++ = *s++;
}

static inline int
strcmp(const char *s1, const char *s2)
{
    for (; *s1 == *s2 && *s1; s1++, s2++);
    return (unsigned char)*s1 - (unsigned char)*s2;
}

#define	UFS_SMALL_CGBASE
#include "ufsread.c"

static inline int
xfsread(ufs_ino_t inode, void *buf, size_t nbyte)
{
    if ((size_t)fsread(inode, buf, nbyte) != nbyte) {
	printf("Invalid %s\n", "format");
	return -1;
    }
    return 0;
}

static inline void
getstr(void)
{
    char *s;
    int c;

    s = cmd;
    for (;;) {
	switch (c = xgetc(0)) {
	case 0:
	    break;
	case '\177':
	case '\b':
	    if (s > cmd) {
		s--;
		printf("\b \b");
	    }
	    break;
	case '\n':
	case '\r':
	    *s = 0;
	    return;
	default:
	    if (s - cmd < sizeof(cmd) - 1)
		*s++ = c;
	    putchar(c);
	}
    }
}

static inline void
putc(int c)
{
    v86.addr = 0x10;
    v86.eax = 0xe00 | (c & 0xff);
    v86.ebx = 0x7;
    v86int();
}

int
main(void)
{
    uint8_t autoboot;
    ufs_ino_t ino;
    size_t nbyte;

    dmadat = (void *)(roundup2(__base + (int32_t)&_end, 0x10000) - __base);
    v86.ctl = V86_FLAGS;
    v86.efl = PSL_RESERVED_DEFAULT | PSL_I;
    dsk.drive = *(uint8_t *)PTOV(ARGS);
    dsk.type = dsk.drive & DRV_HARD ? TYPE_AD : TYPE_FD;
    dsk.unit = dsk.drive & DRV_MASK;
    dsk.slice = *(uint8_t *)PTOV(ARGS + 1) + 1;
    bootinfo.bi_version = BOOTINFO_VERSION;
    bootinfo.bi_size = sizeof(bootinfo);

    /* Process configuration file */

    autoboot = 1;

    if ((ino = lookup(PATH_CONFIG)) ||
        (ino = lookup(PATH_DOTCONFIG))) {
	nbyte = fsread(ino, cmd, sizeof(cmd) - 1);
	cmd[nbyte] = '\0';
    }

    if (*cmd) {
	memcpy(cmddup, cmd, sizeof(cmd));
	if (parse())
	    autoboot = 0;
	if (!OPT_CHECK(RBX_QUIET))
	    printf("%s: %s", PATH_CONFIG, cmddup);
	/* Do not process this command twice */
	*cmd = 0;
    }

    /*
     * Try to exec stage 3 boot loader. If interrupted by a keypress,
     * or in case of failure, try to load a kernel directly instead.
     */

    if (!kname) {
	kname = PATH_BOOT3;
	if (autoboot && !keyhit(3*SECOND)) {
	    load();
	    kname = PATH_KERNEL;
	}
    }

    /* Present the user with the boot2 prompt. */

    for (;;) {
	if (!autoboot || !OPT_CHECK(RBX_QUIET))
	    printf("\nOPNsense/x86 boot\n"
		   "Default: %u:%s(%u,%c)%s\n"
		   "boot: ",
		   dsk.drive & DRV_MASK, dev_nm[dsk.type], dsk.unit,
		   'a' + dsk.part, kname);
	if (ioctrl & IO_SERIAL)
	    sio_flush();
	if (!autoboot || keyhit(3*SECOND))
	    getstr();
	else if (!autoboot || !OPT_CHECK(RBX_QUIET))
	    putchar('\n');
	autoboot = 0;
	if (parse())
	    putchar('\a');
	else
	    load();
    }
}

/* XXX - Needed for btxld to link the boot2 binary; do not remove. */
void
exit(int x)
{
}

static void
load(void)
{
    union {
	struct exec ex;
	Elf32_Ehdr eh;
    } hdr;
    static Elf32_Phdr ep[2];
    static Elf32_Shdr es[2];
    caddr_t p;
    ufs_ino_t ino;
    uint32_t addr;
    int i, j;

    if (!(ino = lookup(kname))) {
	if (!ls)
	    printf("No %s\n", kname);
	return;
    }
    if (xfsread(ino, &hdr, sizeof(hdr)))
	return;

    if (N_GETMAGIC(hdr.ex) == ZMAGIC) {
	addr = hdr.ex.a_entry & 0xffffff;
	p = PTOV(addr);
	fs_off = PAGE_SIZE;
	if (xfsread(ino, p, hdr.ex.a_text))
	    return;
	p += roundup2(hdr.ex.a_text, PAGE_SIZE);
	if (xfsread(ino, p, hdr.ex.a_data))
	    return;
    } else if (IS_ELF(hdr.eh)) {
	fs_off = hdr.eh.e_phoff;
	for (j = i = 0; i < hdr.eh.e_phnum && j < 2; i++) {
	    if (xfsread(ino, ep + j, sizeof(ep[0])))
		return;
	    if (ep[j].p_type == PT_LOAD)
		j++;
	}
	for (i = 0; i < 2; i++) {
	    p = PTOV(ep[i].p_paddr & 0xffffff);
	    fs_off = ep[i].p_offset;
	    if (xfsread(ino, p, ep[i].p_filesz))
		return;
	}
	p += roundup2(ep[1].p_memsz, PAGE_SIZE);
	bootinfo.bi_symtab = VTOP(p);
	if (hdr.eh.e_shnum == hdr.eh.e_shstrndx + 3) {
	    fs_off = hdr.eh.e_shoff + sizeof(es[0]) *
		(hdr.eh.e_shstrndx + 1);
	    if (xfsread(ino, &es, sizeof(es)))
		return;
	    for (i = 0; i < 2; i++) {
		*(Elf32_Word *)p = es[i].sh_size;
		p += sizeof(es[i].sh_size);
		fs_off = es[i].sh_offset;
		if (xfsread(ino, p, es[i].sh_size))
		    return;
		p += es[i].sh_size;
	    }
	}
	addr = hdr.eh.e_entry & 0xffffff;
	bootinfo.bi_esymtab = VTOP(p);
    } else {
	printf("Invalid %s\n", "format");
	return;
    }

    bootinfo.bi_kernelname = VTOP(kname);
    bootinfo.bi_bios_dev = dsk.drive;
    __exec((caddr_t)addr, RB_BOOTINFO | (opts & RBX_MASK),
	   MAKEBOOTDEV(dev_maj[dsk.type], dsk.slice, dsk.unit, dsk.part),
	   0, 0, 0, VTOP(&bootinfo));
}

static int
parse()
{
    char *arg = cmd;
    char *ep, *p, *q;
    const char *cp;
    unsigned int drv;
    int c, i, j;

    while ((c = *arg++)) {
	if (c == ' ' || c == '\t' || c == '\n')
	    continue;
	for (p = arg; *p && *p != '\n' && *p != ' ' && *p != '\t'; p++);
	ep = p;
	if (*p)
	    *p++ = 0;
	if (c == '-') {
	    while ((c = *arg++)) {
		if (c == 'P') {
		    if (*(uint8_t *)PTOV(0x496) & 0x10) {
			cp = "yes";
		    } else {
			opts |= OPT_SET(RBX_DUAL) | OPT_SET(RBX_SERIAL);
			cp = "no";
		    }
		    printf("Keyboard: %s\n", cp);
		    continue;
		} else if (c == 'S') {
		    j = 0;
		    while ((unsigned int)(i = *arg++ - '0') <= 9)
			j = j * 10 + i;
		    if (j > 0 && i == -'0') {
			comspeed = j;
			break;
		    }
		    /* Fall through to error below ('S' not in optstr[]). */
		}
		for (i = 0; c != optstr[i]; i++)
		    if (i == NOPT - 1)
			return -1;
		opts ^= OPT_SET(flags[i]);
	    }
	    ioctrl = OPT_CHECK(RBX_DUAL) ? (IO_SERIAL|IO_KEYBOARD) :
		     OPT_CHECK(RBX_SERIAL) ? IO_SERIAL : IO_KEYBOARD;
	    if (ioctrl & IO_SERIAL) {
	        if (sio_init(115200 / comspeed) != 0)
		    ioctrl &= ~IO_SERIAL;
	    }
	} else {
	    for (q = arg--; *q && *q != '('; q++);
	    if (*q) {
		drv = -1;
		if (arg[1] == ':') {
		    drv = *arg - '0';
		    if (drv > 9)
			return (-1);
		    arg += 2;
		}
		if (q - arg != 2)
		    return -1;
		for (i = 0; arg[0] != dev_nm[i][0] ||
			    arg[1] != dev_nm[i][1]; i++)
		    if (i == NDEV - 1)
			return -1;
		dsk.type = i;
		arg += 3;
		dsk.unit = *arg - '0';
		if (arg[1] != ',' || dsk.unit > 9)
		    return -1;
		arg += 2;
		dsk.slice = WHOLE_DISK_SLICE;
		if (arg[1] == ',') {
		    dsk.slice = *arg - '0' + 1;
		    if (dsk.slice > NDOSPART + 1)
			return -1;
		    arg += 2;
		}
		if (arg[1] != ')')
		    return -1;
		dsk.part = *arg - 'a';
		if (dsk.part > 7)
		    return (-1);
		arg += 2;
		if (drv == -1)
		    drv = dsk.unit;
		dsk.drive = (dsk.type <= TYPE_MAXHARD
			     ? DRV_HARD : 0) + drv;
		dsk_meta = 0;
	    }
	    if ((i = ep - arg)) {
		if ((size_t)i >= sizeof(knamebuf))
		    return -1;
		memcpy(knamebuf, arg, i + 1);
		kname = knamebuf;
	    }
	}
	arg = p;
    }
    return 0;
}

static int
dskread(void *buf, unsigned lba, unsigned nblk)
{
    struct dos_partition *dp;
    struct disklabel *d;
    char *sec;
    unsigned i;
    uint8_t sl;

    if (!dsk_meta) {
	sec = dmadat->secbuf;
	dsk.start = 0;
	if (drvread(sec, DOSBBSECTOR, 1))
	    return -1;
	dp = (void *)(sec + DOSPARTOFF);
	sl = dsk.slice;
	if (sl < BASE_SLICE) {
	    for (i = 0; i < NDOSPART; i++)
		if (dp[i].dp_typ == DOSPTYP_386BSD &&
		    (dp[i].dp_flag & 0x80 || sl < BASE_SLICE)) {
		    sl = BASE_SLICE + i;
		    if (dp[i].dp_flag & 0x80 ||
			dsk.slice == COMPATIBILITY_SLICE)
			break;
		}
	    if (dsk.slice == WHOLE_DISK_SLICE)
		dsk.slice = sl;
	}
	if (sl != WHOLE_DISK_SLICE) {
	    if (sl != COMPATIBILITY_SLICE)
		dp += sl - BASE_SLICE;
	    if (dp->dp_typ != DOSPTYP_386BSD) {
		printf("Invalid %s\n", "slice");
		return -1;
	    }
	    dsk.start = dp->dp_start;
	}
	if (drvread(sec, dsk.start + LABELSECTOR, 1))
		return -1;
	d = (void *)(sec + LABELOFFSET);
	if (d->d_magic != DISKMAGIC || d->d_magic2 != DISKMAGIC) {
	    if (dsk.part != RAW_PART) {
		printf("Invalid %s\n", "label");
		return -1;
	    }
	} else {
	    if (!dsk.init) {
		if (d->d_type == DTYPE_SCSI)
		    dsk.type = TYPE_DA;
		dsk.init++;
	    }
	    if (dsk.part >= d->d_npartitions ||
		!d->d_partitions[dsk.part].p_size) {
		printf("Invalid %s\n", "partition");
		return -1;
	    }
	    dsk.start += d->d_partitions[dsk.part].p_offset;
	    dsk.start -= d->d_partitions[RAW_PART].p_offset;
	}
    }
    return drvread(buf, dsk.start + lba, nblk);
}

static void
printf(const char *fmt,...)
{
    va_list ap;
    static char buf[10];
    char *s;
    unsigned u;
    int c;

    va_start(ap, fmt);
    while ((c = *fmt++)) {
	if (c == '%') {
	    c = *fmt++;
	    switch (c) {
	    case 'c':
		putchar(va_arg(ap, int));
		continue;
	    case 's':
		for (s = va_arg(ap, char *); *s; s++)
		    putchar(*s);
		continue;
	    case 'u':
		u = va_arg(ap, unsigned);
		s = buf;
		do
		    *s++ = '0' + u % 10U;
		while (u /= 10U);
		while (--s >= buf)
		    putchar(*s);
		continue;
	    }
	}
	putchar(c);
    }
    va_end(ap);
    return;
}

static void
putchar(int c)
{
    if (c == '\n')
	xputc('\r');
    xputc(c);
}

static int
drvread(void *buf, unsigned lba, unsigned nblk)
{
    static unsigned c = 0x2d5c7c2f;

    if (!OPT_CHECK(RBX_QUIET))
	printf("%c\b", c = c << 8 | c >> 24);
    v86.ctl = V86_ADDR | V86_CALLF | V86_FLAGS;
    v86.addr = XREADORG;		/* call to xread in boot1 */
    v86.es = VTOPSEG(buf);
    v86.eax = lba;
    v86.ebx = VTOPOFF(buf);
    v86.ecx = lba >> 16;
    v86.edx = nblk << 8 | dsk.drive;
    v86int();
    v86.ctl = V86_FLAGS;
    if (V86_CY(v86.efl)) {
	printf("error %u lba %u\n", v86.eax >> 8 & 0xff, lba);
	return -1;
    }
    return 0;
}

static int
keyhit(unsigned ticks)
{
    uint32_t t0, t1;

    if (OPT_CHECK(RBX_NOINTR))
	return 0;
    t0 = 0;
    for (;;) {
	if (xgetc(1))
	    return 1;
	t1 = *(uint32_t *)PTOV(0x46c);
	if (!t0)
	    t0 = t1;
	if ((uint32_t)(t1 - t0) >= ticks)
	    return 0;
    }
}

static int
xputc(int c)
{
    if (ioctrl & IO_KEYBOARD)
	putc(c);
    if (ioctrl & IO_SERIAL)
	sio_putc(c);
    return c;
}

static int
getc(int fn)
{
    v86.addr = 0x16;
    v86.eax = fn << 8;
    v86int();
    return fn == 0 ? v86.eax & 0xff : !V86_ZR(v86.efl);
}

static int
xgetc(int fn)
{
    if (OPT_CHECK(RBX_NOINTR))
	return 0;
    for (;;) {
	if (ioctrl & IO_KEYBOARD && getc(1))
	    return fn ? 1 : getc(0);
	if (ioctrl & IO_SERIAL && sio_ischar())
	    return fn ? 1 : sio_getc();
	if (fn)
	    return 0;
    }
}
