/*-
 * Copyright (c) 2014-2017 Larry Baird
 * All rights reserved.
 *
 * Feedback provided by Ermal Luci.
 *
 * Used information from daduke's linux driver (https://daduke.org/linux/apu2)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/priv.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <x86/bus.h>
#include <isa/isavar.h>
#include <dev/led/led.h>

static struct mtx gpio_lock;
MTX_SYSINIT(gpio_lock, &gpio_lock, "gpio lock", MTX_SPIN);

/*
 * Basic idea is to create two MMIO memory resources. One for LEDs and
 * one for button on front of APU. Then create a device for each LED and
 * the button. On an apu3 also create a device for switch for switching SIMs.
 */

/* See dev/amdsbwd/amdsbwd.c for magic numbers for southbridges */

/* SB7xx RRG 2.3.3.1.1. */
#define AMDSB_PMIO_INDEX		0xcd6
#define AMDSB_PMIO_DATA			(PMIO_INDEX + 1)
#define AMDSB_PMIO_WIDTH		2

#define AMDSB_SMBUS_DEVID		0x43851002
#define AMDFCH_SMBUS_DEVID		0x780b1022

/* SB8xx RRG 2.3.7. */
#define AMDSB8_MMIO_BASE_ADDR_FIND	0x24

/* Here are some magic numbers from APU1 BIOS. */
#define SB_GPIO_OFFSET			0x100
#define GPIO_187			187	// APU1 MODESW
#define GPIO_188			188	// APU1 Unknown ??
#define GPIO_189			189	// APU1 LED1#
#define GPIO_190			190	// APU1 LED2#
#define GPIO_191			191	// APU1 LED3#

#define SB_GPIO_ON			0x08
#define SB_GPIO_OFF			0xC8

/* Here are some magic numbers for APU2. */
#define AMDFCH41_MMIO_ADDR		0xfed80000u
#define FCH_GPIO_OFFSET			0x1500
#define FCH_GPIO_BASE			(AMDFCH41_MMIO_ADDR + FCH_GPIO_OFFSET)
#define FCH_GPIO_SIZE			0x300
#define FCH_GPIO_BIT_WRITE		22
#define FCH_GPIO_BIT_READ		16
#define FCH_GPIO_BIT_DIR		23
#define GPIO_68				68	// APU2/3 LED1#
#define GPIO_69				69	// APU2/3 LED2#
#define GPIO_70				70	// APU2/3 LED3#
#define GPIO_89				89	// APU2/3 MODESW
#define GPIO_90				90	// APU3 SIM switcher

struct apu_cdev {
	struct resource	*res;
	bus_size_t	offset;
	struct cdev	*cdev;
	uint32_t	devid;
};

struct apu_rid {
	int	rid;
	int	rid_type;
	struct resource *res;
};

struct apu_softc {
	int		sc_model;
	uint32_t	sc_devid;
	struct apu_rid	sc_rid[2];
#		define IDX_RID_LED	0
#		define IDX_RID_MODESW	1
	struct apu_cdev	sc_led[3];
	struct apu_cdev	sc_sw[2];
#		define IDX_SW_MODE	0
#		define IDX_SW_SIM	1
};

/*
 * Mode switch methods.
 */
static int    sw_open(struct cdev *dev, int flags, int fmt, struct thread *td);
static int    sw_close(struct cdev *dev, int flags, int fmt, struct thread *td);
static int    sw_read(struct cdev *dev, struct uio *uio, int ioflag);
static int    sw_write(struct cdev *dev, struct uio *uio, int ioflag);

static void
apu_led_callback(void *ptr, int onoff);

static struct cdevsw modesw_cdev = {
	.d_version =	D_VERSION,
	.d_open =	sw_open,
	.d_read =	sw_read,
	.d_close =	sw_close,
	.d_name =	"modesw",
};

static struct cdevsw simsw_cdev = {
	.d_version =	D_VERSION,
	.d_open =	sw_open,
	.d_read =	sw_read,
	.d_write =	sw_write,
	.d_close =	sw_close,
	.d_name =	"simsw",
};

static int
hw_is_apu( void )
{
	int apu = 0;
	char *maker;
	char *product;

	maker = kern_getenv("smbios.system.maker");
	if (maker != NULL) {
		if (strcasecmp("PC Engines", maker) == 0) {
			product = kern_getenv("smbios.system.product");
			if (product != NULL) {
				if (strcasecmp("APU", product) == 0)
					apu = 1;
				else if (strcasecmp("apu2", product) == 0)
					apu = 2;
				else if (strcasecmp("apu3", product) == 0)
					apu = 3;
				else if (strcasecmp("apu4", product) == 0)
					apu = 4;

				freeenv(product);
			}
		}

		freeenv(maker);
	}

	return (apu);
}

static void
sb_gpio_write( struct resource *res, bus_size_t offset, int active )
{
	u_int8_t value;

	value = bus_read_1(res, offset);

	if (active)
		value = SB_GPIO_ON;
	else
		value = SB_GPIO_OFF;

	bus_write_1(res, offset, value);
}

static char
sb_gpio_read( struct resource *res, bus_size_t offset )
{
	uint8_t value;
	char ch;

	/* Is mode switch pressed? */
	value = bus_read_1(res, offset);

	if (value == 0x28 )
		ch = '1';
	else
		ch = '0';

	return (ch);
}

/*
 * gpio methods.
 */
static void
fch_gpio_dir_set( struct resource *res, bus_size_t offset, int out )
{
	u_int32_t value;
	u_int32_t dir_bit = 1 << FCH_GPIO_BIT_DIR;

	value = bus_read_4(res, offset);

	if (out)
		value |= dir_bit;
	else
		value &= ~dir_bit;

	bus_write_4(res, offset, value);
}

static char
fch_gpio_read( struct resource *res, bus_size_t offset )
{
	uint32_t value;
	char ch;
	u_int32_t read_bit = 1 << FCH_GPIO_BIT_READ;

	/* Is mode switch pressed? */
	value = bus_read_4(res, offset);

	if (!(value & read_bit))
		ch = '1';
	else
		ch = '0';

	return (ch);
}

static void
fch_gpio_write( struct resource *res, bus_size_t offset, int active )
{
	u_int32_t value;
	u_int32_t write_bit = 1 << FCH_GPIO_BIT_WRITE;

	value = bus_read_4(res, offset);

	if (active)
		value &= ~write_bit;
	else
		value |= write_bit;

	bus_write_4(res, offset, value);
}


/* Check to see if this is an APU board we support? */
static void
apuled_identify(driver_t *driver, device_t parent)
{
	device_t	child;
	device_t	smb;
	uint32_t	devid;

	if (resource_disabled("apuled", 0))
		return;

	if (device_find_child(parent, "apuled", -1) != NULL)
		return;

	/* Do was have expected south bridge chipset? */
	smb = pci_find_bsf(0, 20, 0);
	if (smb == NULL)
		return;

	devid = pci_get_devid(smb);

	switch (hw_is_apu()) {
	case 1:
		if (devid != AMDSB_SMBUS_DEVID)
			return;
		break;
	case 2:
	case 3:
	case 4:
		if (devid != AMDFCH_SMBUS_DEVID)
			return;
		break;
	default:
		return;
	}

	/* Everything looks good, enable probe */
	child = BUS_ADD_CHILD(parent, ISA_ORDER_SPECULATIVE, "apuled", -1);
	if (child == NULL)
		device_printf(parent, "apuled: bus add child failed\n");
}

static int
apu_probe_sb(device_t dev, struct apu_softc *sc)
{
	struct resource         *res;
	int			rc;
	uint32_t		gpio_mmio_base;
	int			rid;
	int			i;

	/* Find the ACPImmioAddr base address */
	rc = bus_set_resource(dev, SYS_RES_IOPORT, 0, AMDSB_PMIO_INDEX,
	    AMDSB_PMIO_WIDTH);
	if (rc != 0) {
		device_printf(dev, "bus_set_resource for MMIO failed\n");
		return (ENXIO);
	}

	rid = 0;
	res = bus_alloc_resource(dev, SYS_RES_IOPORT, &rid, 0ul, ~0ul,
	    AMDSB_PMIO_WIDTH, RF_ACTIVE | RF_SHAREABLE);

	if (res == NULL) {
		device_printf(dev, "bus_alloc_resource for MMIO failed.\n");
		return (ENXIO);
	}

	/* Find base address of memory mapped WDT registers. */
	/* This will probable be 0xfed80000 */
	for (gpio_mmio_base = 0, i = 0; i < 4; i++) {
		gpio_mmio_base <<= 8;
		bus_write_1(res, 0, AMDSB8_MMIO_BASE_ADDR_FIND + 3 - i);
		gpio_mmio_base |= bus_read_1(res, 1);
	}
	gpio_mmio_base &= ~0x07u;

	if (bootverbose)
		device_printf(dev, "MMIO base adddress 0x%x\n", gpio_mmio_base);

	bus_release_resource(dev, SYS_RES_IOPORT, rid, res);
	bus_delete_resource(dev, SYS_RES_IOPORT, rid);

	/* Set memory resource for LEDs. */
	rc = bus_set_resource(dev, SYS_RES_MEMORY, 0,
	    gpio_mmio_base + SB_GPIO_OFFSET + GPIO_189,
	    (GPIO_191 - GPIO_189) + 1);
	if (rc != 0) {
		device_printf(dev, "bus_set_resource for LEDs failed\n");
		return (ENXIO);
	}

	/* Set memory resource for switches. */
	rc = bus_set_resource(dev, SYS_RES_MEMORY, 1,
	    gpio_mmio_base + SB_GPIO_OFFSET + GPIO_187, 1);
	if (rc != 0) {
		device_printf(dev, "bus_set_resource for switches failed\n");
		return (ENXIO);
	}

	return (0);
}

static int
apu_probe_fch(device_t dev, struct apu_softc *sc)
{
	int		rc;
	u_long		count;

	/* Set memory resource for LEDs. */
	rc = bus_set_resource(dev, SYS_RES_MEMORY, 0,
	    FCH_GPIO_BASE + (GPIO_68 * sizeof(uint32_t)),
	    ((GPIO_70 - GPIO_68) + 1) * sizeof(uint32_t) );
	if (rc != 0) {
		device_printf(dev, "bus_set_resource for LEDs failed\n");
		return (ENXIO);
	}

	/* Set memory resource for switches. */
	if (sc->sc_model == 3)
		count = sizeof(uint32_t) * 2;
	else
		count = sizeof(uint32_t);
	rc = bus_set_resource(dev, SYS_RES_MEMORY, 1,
	    FCH_GPIO_BASE + (GPIO_89 * sizeof(uint32_t)), count );
	if (rc != 0) {
		device_printf(dev, "bus_set_resource for switches failed\n");
		return (ENXIO);
	}

	return (0);
}

/*
 * APU LED device methods.
 */
static int
apuled_probe(device_t dev)
{
	int			error;
	char			buf[100];
	struct apu_softc 	*sc = device_get_softc(dev);
	device_t		smb;

	/* Make sure we do not claim some ISA PNP device. */
	if (isa_get_logicalid(dev) != 0)
		return (ENXIO);

	sc->sc_model = hw_is_apu();
	if (sc->sc_model == 0)
		return (ENXIO);

	smb = pci_find_bsf(0, 20, 0);
	    if (smb == NULL)
		return (ENXIO);

	sc->sc_devid = pci_get_devid(smb);

	snprintf(buf, sizeof(buf), "APU%d", sc->sc_model);
	device_set_desc_copy(dev, buf );

	switch( sc->sc_devid ) {
	case AMDSB_SMBUS_DEVID:
		error = apu_probe_sb(dev, sc);
		if (error)
		    return error;
		break;
	case AMDFCH_SMBUS_DEVID:
		error = apu_probe_fch(dev, sc);
		if (error)
		    return error;
		break;
	default:	/* Should never reach here. */
		device_printf(dev, "Unexpected APU south bridge\n" );
		return (ENXIO);
		break;
	}

	return (0);
}

static int
apuled_attach(device_t dev)
{
	struct apu_softc *sc = device_get_softc(dev);
	int i;
	int j;

	for (i = 0; i < sizeof(sc->sc_rid)/sizeof(sc->sc_rid[0]); i++) {
	    sc->sc_rid[i].res = NULL;
	    sc->sc_rid[i].rid_type = SYS_RES_MEMORY;
	    sc->sc_rid[i].rid = i;
	}

	for (i = 0; i < sizeof(sc->sc_rid)/sizeof(sc->sc_rid[0]); i++) {
	    sc->sc_rid[i].res = bus_alloc_resource_any( dev,
		sc->sc_rid[i].rid_type, &sc->sc_rid[i].rid,
		RF_ACTIVE | RF_SHAREABLE);
	    if (sc->sc_rid[i].res == NULL) {
		    device_printf( dev, "Unable to allocate memory region %d\n", i );
		    for (j = 0; j < i; j++) {
			bus_release_resource(dev, sc->sc_rid[j].rid_type,
			    sc->sc_rid[j].rid, sc->sc_rid[j].res);
			sc->sc_rid[j].res = NULL;
			bus_delete_resource(dev, sc->sc_rid[i].rid_type,
			    sc->sc_rid[i].rid );
		    }
		    return (ENXIO);
	    }
	}

	if (sc->sc_devid == AMDFCH_SMBUS_DEVID)
	    fch_gpio_dir_set( sc->sc_rid[IDX_RID_MODESW].res, 0, FALSE );

	for (i = 0; i < sizeof(sc->sc_sw)/sizeof(sc->sc_sw[0]); i++)
	    sc->sc_sw[i].cdev = NULL;

	sc->sc_sw[IDX_SW_MODE].cdev = make_dev(&modesw_cdev, 0, UID_ROOT,
	    GID_WHEEL, 0440, "modesw");
	if (sc->sc_sw[IDX_SW_MODE].cdev == NULL) {
		device_printf( dev, "Unable to make modesw\n" );
	} else {
		sc->sc_sw[IDX_SW_MODE].cdev->si_drv1 = &sc->sc_sw[IDX_SW_MODE];
		sc->sc_sw[IDX_SW_MODE].res = sc->sc_rid[IDX_RID_MODESW].res;
		sc->sc_sw[IDX_SW_MODE].offset = 0;
		sc->sc_sw[IDX_SW_MODE].devid = sc->sc_devid;
	}

	if (sc->sc_model == 3) {
	    sc->sc_sw[IDX_SW_SIM].cdev = make_dev(&simsw_cdev, 0, UID_ROOT,
		GID_WHEEL, 0440, "simsw");
	    if (sc->sc_sw[IDX_SW_SIM].cdev == NULL) {
		    device_printf( dev, "Unable to make simsw\n" );
	    } else {
		    sc->sc_sw[IDX_SW_SIM].cdev->si_drv1 = &sc->sc_sw[IDX_SW_SIM];
		    sc->sc_sw[IDX_SW_SIM].res = sc->sc_rid[IDX_RID_MODESW].res;
		    sc->sc_sw[IDX_SW_SIM].offset = sizeof(uint32_t);
		    sc->sc_sw[IDX_SW_SIM].devid = sc->sc_devid;
	    }
	}

	for (i = 0; i < sizeof(sc->sc_led)/sizeof(sc->sc_led[0]); i++) {
		char name[30];

		snprintf( name, sizeof(name), "led%d", i + 1 );

		sc->sc_led[i].res = sc->sc_rid[IDX_RID_LED].res;
		sc->sc_led[i].devid = sc->sc_devid;

		switch (sc->sc_devid) {
		case AMDSB_SMBUS_DEVID:
			sc->sc_led[i].offset = i;
			break;
		case AMDFCH_SMBUS_DEVID:
			sc->sc_led[i].offset = i * sizeof(uint32_t);
			fch_gpio_dir_set(sc->sc_led[i].res,
			    sc->sc_led[i].offset, TRUE);
			break;
		default:
			break;
		}

		/* Make sure power LED stays on by default */
		sc->sc_led[i].cdev = led_create_state(apu_led_callback,
		    &sc->sc_led[i], name, i == 0);

		if (sc->sc_led[i].cdev == NULL)
			device_printf(dev, "%s creation failed\n", name);
	}

	return (0);
}

static int
apuled_detach(device_t dev)
{
	struct apu_softc *sc = device_get_softc(dev);
	int i;

	for (i = 0; i < sizeof(sc->sc_led)/sizeof(sc->sc_led[0]); i++)
		if (sc->sc_led[i].cdev != NULL) {
			/* Restore LEDs to stating state */
			if (i == 0)
				apu_led_callback(&sc->sc_led[i], TRUE);
			else
				apu_led_callback(&sc->sc_led[i], FALSE);

			led_destroy(sc->sc_led[i].cdev);
		}

	for (i = 0; i < sizeof(sc->sc_sw)/sizeof(sc->sc_sw[0]); i++)
	    if (sc->sc_sw[i].cdev != NULL)
		destroy_dev(sc->sc_sw[i].cdev);

	for (i = 0; i < sizeof(sc->sc_rid)/sizeof(sc->sc_rid[0]); i++) {
	    if (sc->sc_rid[i].res != NULL) {
		    bus_release_resource(dev, sc->sc_rid[i].rid_type,
			sc->sc_rid[i].rid, sc->sc_rid[i].res);
		    bus_delete_resource(dev, sc->sc_rid[i].rid_type,
			sc->sc_rid[i].rid );
	    }
	}

	return (0);
}

static int
sw_open(struct cdev *dev __unused, int flags __unused, int fmt __unused,
    struct thread *td)
{
	int error;

	error = priv_check(td, PRIV_IO);
	if (error != 0)
		return (error);
	error = securelevel_gt(td->td_ucred, 0);

	return (error);
}

static int
sw_read(struct cdev *dev, struct uio *uio, int ioflag) {
	struct apu_cdev *sw = (struct apu_cdev *)dev->si_drv1;
        char ch = '0';
        int error;

	mtx_lock_spin(&gpio_lock);

	switch (sw->devid) {
	case AMDSB_SMBUS_DEVID:
		ch = sb_gpio_read( sw->res, sw->offset );
		break;
	case AMDFCH_SMBUS_DEVID:
		fch_gpio_dir_set( sw->res, sw->offset, FALSE );
		ch = fch_gpio_read( sw->res, sw->offset );
		break;
	default:
		break;
	}

	mtx_unlock_spin(&gpio_lock);

	error = uiomove(&ch, sizeof(ch), uio);
	return (error);
}

static int
sw_write(struct cdev *dev, struct uio *uio, int ioflag) {
	struct apu_cdev *sw = (struct apu_cdev *)dev->si_drv1;
        char ch;
        int error;

	error = uiomove(&ch, sizeof(ch), uio);
	if (error)
	    return (error);

	mtx_lock_spin(&gpio_lock);

	switch (sw->devid) {
	case AMDSB_SMBUS_DEVID:
		break;
	case AMDFCH_SMBUS_DEVID:
		fch_gpio_dir_set( sw->res, sw->offset, TRUE );
		fch_gpio_write(sw->res, sw->offset, ch);
		break;
	default:
		break;
	}

	mtx_unlock_spin(&gpio_lock);

	return (0);
}

static int
sw_close(struct cdev *dev __unused, int flags __unused, int fmt __unused,
    struct thread *td __unused)
{
	return (0);
}

static void
apu_led_callback(void *ptr, int onoff)
{
	struct apu_cdev *led = (struct apu_cdev *)ptr;

	mtx_lock_spin(&gpio_lock);

	switch (led->devid) {
	case AMDSB_SMBUS_DEVID:
		sb_gpio_write( led->res, led->offset, onoff );
		break;
	case AMDFCH_SMBUS_DEVID:
		fch_gpio_write( led->res, led->offset, onoff );
		break;
	default:
		break;
	}

	mtx_unlock_spin(&gpio_lock);
}

static device_method_t apuled_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		apuled_probe),
	DEVMETHOD(device_attach,	apuled_attach),
	DEVMETHOD(device_detach,	apuled_detach),
	DEVMETHOD(device_identify,	apuled_identify),

	DEVMETHOD_END
};

static driver_t apuled_driver = {
	"apuled",
	apuled_methods,
	sizeof(struct apu_softc),
};

static devclass_t apuled_devclass;
DRIVER_MODULE(apuled, isa, apuled_driver, apuled_devclass, NULL, NULL);
