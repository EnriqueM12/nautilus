/*
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the
 * United States National  Science Foundation and the Department of Energy.
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */

/*
 * CXL (Compute Express Link) device driver.
 *
 * Detection is vendor/device-ID-independent.  We use ECAM (the MMIO-mapped
 * PCIe config space from the ACPI MCFG table) to scan every bus in every
 * MCFG region — including buses behind CXL root ports that Nautilus's own
 * PCI enumerator may not have walked — and look for the CXL DVSEC
 * (extended capability ID 0x0023, vendor 0x1E98).
 */

#include <nautilus/nautilus.h>
#include <nautilus/mm.h>
#include <nautilus/shell.h>
#include <nautilus/naut_string.h>
#include <nautilus/paging.h>
#include <nautilus/acpi.h>
#include <acpi/actbl2.h>
#include <dev/pci.h>
#include <dev/cxl.h>

#ifndef NAUT_CONFIG_DEBUG_CXL
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...)
#endif

#define INFO(fmt, args...)  INFO_PRINT("cxl: " fmt, ##args)
#define DEBUG(fmt, args...) DEBUG_PRINT("cxl: " fmt, ##args)
#define ERROR(fmt, args...) ERROR_PRINT("cxl: " fmt, ##args)

/* -----------------------------------------------------------------------
 * PCIe extended capability constants
 * ----------------------------------------------------------------------- */

#define PCIE_EXT_CAP_ID(hdr)   ((hdr) & 0xffff)
#define PCIE_EXT_CAP_NEXT(hdr) (((hdr) >> 20) & 0xffc)

#define PCIE_EXT_CAP_OFFSET    0x100
#define PCIE_EXT_CAP_ID_DVSEC  0x0023

/* DVSEC layout relative to cap base:
 *   +0x00  extended cap header
 *   +0x04  [15:0] vendor ID  [19:16] revision  [31:20] length
 *   +0x08  [15:0] DVSEC ID
 */
#define DVSEC_VENDOR_OFFSET    0x04
#define DVSEC_ID_OFFSET        0x08
#define DVSEC_VENDOR_ID_MASK   0x0000ffff
#define DVSEC_ID_MASK          0x0000ffff

#define CXL_DVSEC_VENDOR_ID    0x1E98

#define CXL_DVSEC_PCIE_DEVICE  0x0000
#define CXL_DVSEC_NON_CXL_FN   0x000A
#define CXL_DVSEC_EXTENSIONS   0x000B

/* PCI config space offsets */
#define PCI_CFG_VENDOR         0x00
#define PCI_CFG_CLASS          0x08  /* [31:24] class [23:16] sub [15:8] prog [7:0] rev */
#define PCI_CFG_HDR_TYPE       0x0c  /* byte at offset 0x0e */
#define PCI_CFG_BAR0           0x10
#define PCI_CFG_BAR1           0x14
#define PCI_CFG_COMMAND        0x04

#define PCI_CLASS_BRIDGE       0x06

#define PCI_CMD_MEM_SPACE      (1 << 1)
#define PCI_CMD_BUS_MASTER     (1 << 2)

#define PCI_HDR_MULTIFUNC      0x80
#define PCI_VENDOR_NONE        0xffff

/* -----------------------------------------------------------------------
 * ECAM state
 * ----------------------------------------------------------------------- */

struct ecam_region {
    uint64_t base;
    uint8_t  start_bus;
    uint8_t  end_bus;
};

#define MAX_ECAM_REGIONS 8
static struct ecam_region ecam_regions[MAX_ECAM_REGIONS];
static int                num_ecam_regions = 0;

/* -----------------------------------------------------------------------
 * CXL device state
 *
 * Self-contained: does not require a struct pci_dev since the device may
 * not be in Nautilus's PCI bus list.
 * ----------------------------------------------------------------------- */

struct cxl_dev {
    uint8_t          bus;
    uint8_t          slot;
    uint8_t          fun;
    uint16_t         vendor_id;
    uint16_t         device_id;
    uint8_t          class_code;
    uint8_t          subclass;
    uint16_t         dvsec_id;
    uint32_t         dvsec_offset;
    uint64_t         bar0_addr;
    uint64_t         bar0_size;
    struct list_head dev_node;
};

static struct list_head dev_list;

/* -----------------------------------------------------------------------
 * ECAM read/write
 * ----------------------------------------------------------------------- */

static uint64_t ecam_dev_base(uint8_t bus, uint8_t slot, uint8_t fun)
{
    for (int i = 0; i < num_ecam_regions; i++) {
        struct ecam_region *r = &ecam_regions[i];
        if (bus >= r->start_bus && bus <= r->end_bus)
            return r->base + ((uint64_t)bus  << 20)
                           + ((uint64_t)slot << 15)
                           + ((uint64_t)fun  << 12);
    }
    return 0;
}

static uint32_t ecam_readl(uint8_t bus, uint8_t slot, uint8_t fun, uint32_t off)
{
    uint64_t base = ecam_dev_base(bus, slot, fun);
    if (!base)
        return 0xffffffff;
    nk_map_page_nocache(ROUND_DOWN_TO_PAGE(base),
                        PTE_PRESENT_BIT | PTE_WRITABLE_BIT, PS_4K);
    return *((volatile uint32_t *)(base + off));
}

static void ecam_writel(uint8_t bus, uint8_t slot, uint8_t fun,
                        uint32_t off, uint32_t val)
{
    uint64_t base = ecam_dev_base(bus, slot, fun);
    if (!base)
        return;
    nk_map_page_nocache(ROUND_DOWN_TO_PAGE(base),
                        PTE_PRESENT_BIT | PTE_WRITABLE_BIT, PS_4K);
    *((volatile uint32_t *)(base + off)) = val;
}

/* -----------------------------------------------------------------------
 * MCFG parsing
 * ----------------------------------------------------------------------- */

static int parse_mcfg(struct acpi_table_header *hdr, void *arg)
{
    struct acpi_table_mcfg    *mcfg = (struct acpi_table_mcfg *)hdr;
    struct acpi_mcfg_allocation *entry;
    uint8_t *p   = (uint8_t *)mcfg + sizeof(*mcfg);
    uint8_t *end = (uint8_t *)mcfg + mcfg->header.length;

    while (p < end) {
        if (num_ecam_regions >= MAX_ECAM_REGIONS) {
            ERROR("Too many ECAM regions\n");
            break;
        }
        entry = (struct acpi_mcfg_allocation *)p;
        INFO("ECAM region: base=0x%016llx buses %u-%u\n",
             entry->address, entry->start_bus_number, entry->end_bus_number);
        ecam_regions[num_ecam_regions].base      = entry->address;
        ecam_regions[num_ecam_regions].start_bus = entry->start_bus_number;
        ecam_regions[num_ecam_regions].end_bus   = entry->end_bus_number;
        num_ecam_regions++;
        p += sizeof(*entry);
    }
    return 0;
}

static int ecam_init(void)
{
    if (acpi_table_parse(ACPI_SIG_MCFG, parse_mcfg, NULL)) {
        ERROR("No MCFG table — ECAM unavailable\n");
        return -1;
    }
    INFO("Found %d ECAM region(s)\n", num_ecam_regions);
    return 0;
}

/* -----------------------------------------------------------------------
 * CXL DVSEC detection
 * ----------------------------------------------------------------------- */

static uint32_t find_cxl_dvsec(uint8_t bus, uint8_t slot, uint8_t fun,
                                uint16_t want_id, uint16_t *out_id)
{
    uint32_t off = PCIE_EXT_CAP_OFFSET;

    while (off != 0 && off < 0x1000) {
        uint32_t hdr = ecam_readl(bus, slot, fun, off);
        if (hdr == 0 || hdr == 0xffffffff)
            break;

        if (PCIE_EXT_CAP_ID(hdr) == PCIE_EXT_CAP_ID_DVSEC) {
            uint16_t vendor = ecam_readl(bus, slot, fun, off + DVSEC_VENDOR_OFFSET)
                              & DVSEC_VENDOR_ID_MASK;
            uint16_t id     = ecam_readl(bus, slot, fun, off + DVSEC_ID_OFFSET)
                              & DVSEC_ID_MASK;

            if (vendor == CXL_DVSEC_VENDOR_ID &&
                (want_id == CXL_DVSEC_ANY || want_id == id)) {
                if (out_id)
                    *out_id = id;
                return off;
            }
        }

        off = PCIE_EXT_CAP_NEXT(hdr);
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * BAR reading via ECAM
 * ----------------------------------------------------------------------- */

static uint64_t ecam_bar_addr(uint8_t bus, uint8_t slot, uint8_t fun, int barnum)
{
    uint32_t bar = ecam_readl(bus, slot, fun, PCI_CFG_BAR0 + barnum * 4);

    if (bar & 1)
        return 0; /* I/O BAR, skip */

    if (((bar >> 1) & 0x3) == 0x2) {
        /* 64-bit BAR */
        uint32_t hi = ecam_readl(bus, slot, fun, PCI_CFG_BAR0 + (barnum + 1) * 4);
        return (bar & 0xfffffff0ULL) | ((uint64_t)hi << 32);
    }

    return bar & 0xfffffff0;
}

static uint64_t ecam_bar_size(uint8_t bus, uint8_t slot, uint8_t fun, int barnum)
{
    uint32_t off  = PCI_CFG_BAR0 + barnum * 4;
    uint32_t orig = ecam_readl(bus, slot, fun, off);

    ecam_writel(bus, slot, fun, off, 0xffffffff);
    uint32_t sz = ecam_readl(bus, slot, fun, off);
    ecam_writel(bus, slot, fun, off, orig);

    if (!sz || sz == 0xffffffff)
        return 0;

    return ~(sz & 0xfffffff0) + 1;
}

/* -----------------------------------------------------------------------
 * Device helpers
 * ----------------------------------------------------------------------- */

static const char *dvsec_id_str(uint16_t id)
{
    switch (id) {
    case 0x0000: return "CXL Device (Type 1/2/3)";
    case 0x0001: return "Non-CXL Function Map";
    case 0x0002: return "CXL Extensions for Ports";
    case 0x0003: return "GPF DVSEC for CXL Ports";
    case 0x0004: return "GPF DVSEC for CXL Devices";
    case 0x0007: return "PCIe DVSEC for CXL Root Ports";
    case 0x000A: return "Non-CXL Function Map (v2)";
    case 0x000B: return "CXL Extensions for Ports (v2)";
    default:     return "unknown";
    }
}

static void dump_dev(struct cxl_dev *dev)
{
    nk_vc_printf("[%02x:%02x.%x] vendor=0x%04x device=0x%04x"
                 " class=0x%02x sub=0x%02x\n",
                 dev->bus, dev->slot, dev->fun,
                 dev->vendor_id, dev->device_id,
                 dev->class_code, dev->subclass);
    nk_vc_printf("  DVSEC: offset=0x%03x id=0x%04x (%s)\n",
                 dev->dvsec_offset, dev->dvsec_id, dvsec_id_str(dev->dvsec_id));
    nk_vc_printf("  BAR0:  addr=0x%016lx size=0x%016lx\n",
                 dev->bar0_addr, dev->bar0_size);
}

/* -----------------------------------------------------------------------
 * Probe a single function
 * ----------------------------------------------------------------------- */

static int probe_function(uint8_t bus, uint8_t slot, uint8_t fun)
{
    uint32_t id_dw = ecam_readl(bus, slot, fun, PCI_CFG_VENDOR);
    uint16_t vendor = id_dw & 0xffff;

    if (vendor == PCI_VENDOR_NONE || vendor == 0x0000)
        return 0;

    /* Skip bridges — root ports carry a CXL DVSEC but are not memory devices */
    uint32_t class_dw = ecam_readl(bus, slot, fun, PCI_CFG_CLASS);
    if (((class_dw >> 24) & 0xff) == PCI_CLASS_BRIDGE)
        return 0;

    uint16_t dvsec_id;
    uint32_t dvsec_off = find_cxl_dvsec(bus, slot, fun, CXL_DVSEC_ANY, &dvsec_id);
    if (!dvsec_off)
        return 0;

    INFO("CXL device found at [%02x:%02x.%x]\n", bus, slot, fun);

    struct cxl_dev *dev = malloc(sizeof(*dev));
    if (!dev) {
        ERROR("Cannot allocate device state\n");
        return -1;
    }
    memset(dev, 0, sizeof(*dev));

    dev->bus          = bus;
    dev->slot         = slot;
    dev->fun          = fun;
    dev->vendor_id    = id_dw & 0xffff;
    dev->device_id    = (id_dw >> 16) & 0xffff;
    dev->class_code   = (class_dw >> 24) & 0xff;
    dev->subclass     = (class_dw >> 16) & 0xff;
    dev->dvsec_id     = dvsec_id;
    dev->dvsec_offset = dvsec_off;
    dev->bar0_addr    = ecam_bar_addr(bus, slot, fun, 0);
    dev->bar0_size    = ecam_bar_size(bus, slot, fun, 0);

    /* Enable MMIO and bus mastering */
    uint32_t cmd = ecam_readl(bus, slot, fun, PCI_CFG_COMMAND);
    ecam_writel(bus, slot, fun, PCI_CFG_COMMAND,
                cmd | PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER);

    INFO("  vendor=0x%04x device=0x%04x class=0x%02x sub=0x%02x\n",
         dev->vendor_id, dev->device_id, dev->class_code, dev->subclass);
    INFO("  DVSEC offset=0x%03x id=0x%04x (%s)\n",
         dev->dvsec_offset, dev->dvsec_id, dvsec_id_str(dev->dvsec_id));
    INFO("  BAR0  addr=0x%016lx size=0x%016lx\n",
         dev->bar0_addr, dev->bar0_size);

    list_add(&dev->dev_node, &dev_list);
    return 0;
}

/* -----------------------------------------------------------------------
 * Init / deinit
 * ----------------------------------------------------------------------- */

int cxl_init(struct naut_info *naut)
{
    INFO("init\n");

    INIT_LIST_HEAD(&dev_list);

    if (ecam_init())
        return -1;

    INFO("Scanning all ECAM buses for CXL devices\n");

    for (int r = 0; r < num_ecam_regions; r++) {
        struct ecam_region *region = &ecam_regions[r];

        for (int bus = region->start_bus; bus <= region->end_bus; bus++) {
            for (int slot = 0; slot < 32; slot++) {

                /* Check slot 0 exists before probing other functions */
                uint32_t id = ecam_readl(bus, slot, 0, PCI_CFG_VENDOR);
                if ((id & 0xffff) == PCI_VENDOR_NONE)
                    continue;

                uint8_t hdr_type = (ecam_readl(bus, slot, 0, PCI_CFG_HDR_TYPE) >> 16) & 0xff;
                int max_fun = (hdr_type & PCI_HDR_MULTIFUNC) ? 8 : 1;

                for (int fun = 0; fun < max_fun; fun++) {
                    if (probe_function(bus, slot, fun) < 0)
                        return -1;
                }
            }
        }
    }

    if (list_empty(&dev_list))
        INFO("No CXL devices found\n");

    return 0;
}

int cxl_deinit(void)
{
    struct list_head *cur, *tmp;

    list_for_each_safe(cur, tmp, &dev_list) {
        struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
        list_del(cur);
        free(dev);
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Shell command
 * ----------------------------------------------------------------------- */

static int handle_cxl(char *buf, void *priv)
{
    struct list_head *cur;
    int count = 0;

    if (!strncmp(buf, "cxl l", 5)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            dump_dev(dev);
            count++;
        }
        if (!count)
            nk_vc_printf("No CXL devices\n");
        return 0;
    }

    nk_vc_printf("Usage: cxl l\n");
    return 0;
}

/* -----------------------------------------------------------------------
 * Public API wrappers (declared in cxl.h)
 * ----------------------------------------------------------------------- */

uint32_t cxl_ecam_readl(uint8_t bus, uint8_t slot, uint8_t fun, uint32_t offset)
{
    return ecam_readl(bus, slot, fun, offset);
}

uint32_t cxl_find_ext_cap(uint8_t bus, uint8_t slot, uint8_t fun, uint16_t cap_id)
{
    uint32_t off = PCIE_EXT_CAP_OFFSET;
    while (off != 0 && off < 0x1000) {
        uint32_t hdr = ecam_readl(bus, slot, fun, off);
        if (hdr == 0 || hdr == 0xffffffff)
            break;
        if (PCIE_EXT_CAP_ID(hdr) == cap_id)
            return off;
        off = PCIE_EXT_CAP_NEXT(hdr);
    }
    return 0;
}

uint32_t cxl_find_dvsec(uint8_t bus, uint8_t slot, uint8_t fun,
                         uint16_t dvsec_id, uint16_t *out_id)
{
    return find_cxl_dvsec(bus, slot, fun, dvsec_id, out_id);
}

static struct shell_cmd_impl cxl_impl = {
    .cmd      = "cxl",
    .help_str = "cxl l    list detected CXL devices",
    .handler  = handle_cxl,
};
nk_register_shell_cmd(cxl_impl);
