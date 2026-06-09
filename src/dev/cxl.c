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
 *
 * Once a device is found we map its BAR0 (Component Register block),
 * locate the mailbox via the Device Capability Array, and run the
 * IDENTIFY command to learn the device's firmware revision and capacity.
 */

#include <nautilus/nautilus.h>
#include <nautilus/mm.h>
#include <nautilus/numa.h>
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
#define PCI_CFG_CLASS          0x08
#define PCI_CFG_HDR_TYPE       0x0c
#define PCI_CFG_BAR0           0x10
#define PCI_CFG_SEC_BUS        0x18   /* bits[15:8] = secondary bus number */
#define PCI_CFG_BAR1           0x14
#define PCI_CFG_COMMAND        0x04

#define PCI_CMD_MEM_SPACE      (1 << 1)
#define PCI_CMD_BUS_MASTER     (1 << 2)

#define PCI_HDR_MULTIFUNC      0x80
#define PCI_VENDOR_NONE        0xffff

/* -----------------------------------------------------------------------
 * Register Locator DVSEC (ID 0x0008) — CXL 2.0 Table 8-14
 *
 * Locates each register block (Component, Device, etc.) within a BAR.
 * Register Block entries start at DVSEC+0x0A, stride 8 bytes each.
 * ----------------------------------------------------------------------- */

#define CXL_DVSEC_REG_LOCATOR       0x0008
#define CXL_REGLOC_BLK1_OFFSET      0x0C
#define CXL_REGLOC_BLK_STRIDE       0x08
#define CXL_REGLOC_RBI_MEMDEV       3    /* CXL Device Register Interface */

/* -----------------------------------------------------------------------
 * Device Register Interface (DRI) — CXL 2.0 spec §8.2.8
 *
 * The DRI is located via the Register Locator DVSEC (above).
 * Its base address is stored in cxl_dev.dri_addr.
 * All offsets below are relative to that base.
 * ----------------------------------------------------------------------- */

/* Device Capability Array header at DRI+0x00 (CXL 2.0 Table 8-29):
 *   64-bit value; bits [15:0]=cap_id, bits [47:32]=count */
#define CXL_DEVCAP_HDR_SIZE       0x10   /* 16-byte array header (QEMU: cap_id+count then 8 reserved) */
#define CXL_DEVCAP_ENTRY_SIZE     0x10   /* each entry: 16 bytes */
#define CXL_DEVCAP_ENTRY_CAP_OFF  0x04   /* cap_offset at DWORD1 (+4) within each entry */
#define CXL_DEVCAP_ID_MBOX        0x0002 /* Primary Mailbox capability ID */

/* Mailbox register offsets from mailbox base (CXL 2.0 Table 8-28 / Linux cxlmem.h) */
#define CXL_MBOX_CAPS          0x00     /* 32-bit: capabilities */
#define CXL_MBOX_CTRL          0x04     /* 32-bit: control (doorbell) */
#define CXL_MBOX_CMD           0x08     /* 64-bit: command */
#define CXL_MBOX_STATUS        0x10     /* 64-bit: status */
#define CXL_MBOX_BG_STATUS     0x18     /* 64-bit: background command status */
#define CXL_MBOX_PAYLOAD       0x20     /* variable: payload registers */

/* Mailbox Capabilities register fields */
#define CXL_MBOX_CAPS_PAYLOAD_SZ(v) ((v) & 0xf)  /* log2 of max payload in DWORDs */

/* Mailbox Control register fields (32-bit register) */
#define CXL_MBOX_CTRL_DOORBELL  (1U << 0)   /* write 1 to submit; cleared on completion */

/* Status register fields */
#define CXL_MBOX_STATUS_RC(s)   (((s) >> 32) & 0xffff)  /* return code */

/* Mailbox return codes */
#define CXL_MBOX_RC_SUCCESS        0x0000
#define CXL_MBOX_RC_BG_STARTED    0x0001
#define CXL_MBOX_RC_INVALID_INPUT  0x0002
#define CXL_MBOX_RC_UNSUPPORTED    0x0003
#define CXL_MBOX_RC_INTERNAL_ERROR 0x0004

/* Mailbox command opcodes — format: [15:8]=command_set, [7:0]=command */
#define CXL_OPCODE_IDENTIFY          0x4000

/* Events (set 0x01) */
#define CXL_OPCODE_GET_EVT_RECORDS   0x0100
#define CXL_OPCODE_CLR_EVT_RECORDS   0x0101
#define CXL_OPCODE_GET_EVT_INT_POLICY 0x0102
#define CXL_OPCODE_SET_EVT_INT_POLICY 0x0103

/* Firmware Update (set 0x02) */
#define CXL_OPCODE_FW_INFO           0x0200

/* Timestamp (set 0x03) */
#define CXL_OPCODE_TIMESTAMP_GET     0x0300
#define CXL_OPCODE_TIMESTAMP_SET     0x0301

/* Logs (set 0x04) */
#define CXL_OPCODE_GET_SUPPORTED_LOGS 0x0400
#define CXL_OPCODE_GET_LOG           0x0401

/* CCLS Memory Device (set 0x41) */
#define CXL_OPCODE_GET_PARTITION_INFO 0x4100
#define CXL_OPCODE_GET_LSA           0x4102
#define CXL_OPCODE_SET_LSA           0x4103

/* Media and Poison (set 0x43) */
#define CXL_OPCODE_GET_POISON_LIST   0x4300
#define CXL_OPCODE_INJECT_POISON     0x4301
#define CXL_OPCODE_CLEAR_POISON      0x4302

/* Sanitize (set 0x44) */
#define CXL_OPCODE_SANITIZE_OVERWRITE 0x4400

/* Persistent Memory (set 0x45) */
#define CXL_OPCODE_GET_SECURITY_STATE 0x4500

/* Polling limit before declaring mailbox timeout */
#define CXL_MBOX_POLL_LIMIT     100000

/* -----------------------------------------------------------------------
 * CXL Component Register Capability Array  (BAR0 = component registers base)
 *
 * Each capability starts with a 32-bit header at its offset from BAR0:
 *   bits[15:0]  Capability ID
 *   bits[19:16] Capability Version
 *   bits[31:20] Next pointer — multiply by 256 to get the byte offset of
 *               the next capability from BAR0 (0 = end of list).
 * The array header at BAR0+0 always has ID=0x0001.
 * ----------------------------------------------------------------------- */

#define CXL_COMP_CAP_ID_MASK        0x0000ffffu
#define CXL_COMP_CAP_NEXT_MASK      0xfff00000u  /* bits[31:20] */
#define CXL_COMP_CAP_ID_HDM         0x0005u      /* HDM Decoder Capability */

/* CXL 2.0 §8.2.3: component register block layout within BAR0.
 * BAR0+0x0000-0x0FFF: CXL.io (PCIe-style, QEMU subregion "cxl-component-io")
 * BAR0+0x1000-0xFFFF: CXL.cache+mem — CXL Capability Array starts here */
#define CXL_COMP_CM_OFFSET          0x1000

/* HDM Decoder Capability register offsets from the capability data base
 * (the pointer in the array entry points directly at the first register). */
#define CXL_HDM_CAP_REG             0x00   /* HDM Decoder Capability Register */
#define CXL_HDM_GLOB_CTRL           0x04   /* HDM Decoder Global Control */
#define CXL_HDM_DEC_FIRST           0x10   /* first per-decoder block */
#define CXL_HDM_DEC_STRIDE          0x20   /* per-decoder block stride */
#define CXL_HDM_MAX_DECODERS        10

/* HDM Decoder Capability Register fields (at cap+CXL_HDM_CAP_REG) */
#define CXL_HDM_CAP_COUNT_MASK      0x0fu  /* bits[3:0]: decoder count encoding */

/* HDM Decoder Global Control Register fields (at cap+CXL_HDM_GLOB_CTRL) */
#define CXL_HDM_GLOB_CTRL_ENABLE    (1u << 0)

/* Per-decoder register offsets from the HDM capability header base.
 * CXL 2.0 §8.2.4 Table 8-23: base and size are 256 MB aligned, so only
 * bits[31:28] of the Low registers carry address bits. */
#define CXL_HDM_DEC_BLK(n)         (CXL_HDM_DEC_FIRST + (n) * CXL_HDM_DEC_STRIDE)
#define CXL_HDM_DEC_BASE_LO(n)     (CXL_HDM_DEC_BLK(n) + 0x00)  /* HPA[31:28] */
#define CXL_HDM_DEC_BASE_HI(n)     (CXL_HDM_DEC_BLK(n) + 0x04)  /* HPA[63:32] */
#define CXL_HDM_DEC_SIZE_LO(n)     (CXL_HDM_DEC_BLK(n) + 0x08)  /* size[31:28] */
#define CXL_HDM_DEC_SIZE_HI(n)     (CXL_HDM_DEC_BLK(n) + 0x0C)  /* size[63:32] */
#define CXL_HDM_DEC_CTRL(n)        (CXL_HDM_DEC_BLK(n) + 0x10)  /* decoder control */
#define CXL_HDM_DEC_SKIP_LO(n)     (CXL_HDM_DEC_BLK(n) + 0x14)  /* DPA skip[31:0] (type 3) */
#define CXL_HDM_DEC_SKIP_HI(n)     (CXL_HDM_DEC_BLK(n) + 0x18)  /* DPA skip[63:32] */
#define CXL_HDM_DEC_TGT_LO(n)      (CXL_HDM_DEC_BLK(n) + 0x14)  /* target list low — same offset as SKIP_LO; meaning differs by device type */

/* Decoder Control Register fields (CXL 2.0 Table 8-23) */
#define CXL_HDM_DEC_CTRL_IG_MASK     0x0fu          /* bits[3:0]:  interleave granularity */
#define CXL_HDM_DEC_CTRL_IG_SHIFT    0
#define CXL_HDM_DEC_CTRL_IW_MASK     (0x0fu << 4)   /* bits[7:4]:  interleave ways */
#define CXL_HDM_DEC_CTRL_IW_SHIFT    4
#define CXL_HDM_DEC_CTRL_COMMIT      (1u << 9)      /* write 1 to initiate commit */
#define CXL_HDM_DEC_CTRL_COMMITTED   (1u << 10)     /* read: decoder is committed */
#define CXL_HDM_DEC_CTRL_ERRCODE_MASK (0xfu << 12)  /* bits[15:12]: error code */
#define CXL_HDM_DEC_CTRL_PMEM        (1u << 16)     /* 0=volatile 1=persistent */

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

    /* BAR0 — Component Register block */
    uint64_t         bar0_addr;
    uint64_t         bar0_size;

    /* Device Register Interface base address (from Register Locator DVSEC) */
    uint64_t         dri_addr;

    /* Mailbox */
    uint32_t         mbox_off;          /* offset from dri_addr to mailbox registers */
    uint32_t         mbox_payload_size; /* max payload in bytes */

    /* IDENTIFY results */
    char             fw_revision[17];   /* null-terminated ASCII */
    uint64_t         total_mb;          /* total capacity in MB */
    uint64_t         volatile_mb;
    uint64_t         persistent_mb;
    uint32_t         lsa_size;

    /* kmem region registered after HDM decoder commit (NULL if not yet registered) */
    struct mem_region *kmem_region;

    struct list_head dev_node;
};

static struct list_head dev_list;

/* -----------------------------------------------------------------------
 * ECAM read/write  (PCIe extended config space access)
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
 * BAR0 MMIO accessors
 *
 * bar0_addr is used as both physical and virtual address — Nautilus
 * identity-maps physical memory, and nk_map_page_nocache ensures the
 * pages are present before we touch them.
 * ----------------------------------------------------------------------- */

static void bar0_map(uint64_t bar0, uint64_t size)
{
    for (uint64_t off = 0; off < size; off += 0x1000)
        nk_map_page_nocache(ROUND_DOWN_TO_PAGE(bar0 + off),
                            PTE_PRESENT_BIT | PTE_WRITABLE_BIT, PS_4K);
}

/* Map a CXL DRAM range with cached PTEs so the buddy allocator can use it.
 * Unlike BAR0 MMIO, device memory must not be mapped uncacheable.
 *
 * nk_map_page (via drill_pd) always installs 2MB page-directory entries,
 * ignoring the PS_4K hint.  Stepping in 4KB increments would overwrite the
 * same PD entry 512 times, leaving it pointing at the last non-2MB-aligned
 * address.  Step in 2MB increments so each call sets exactly one PD entry. */
static void cxl_mem_map(uint64_t base, uint64_t size)
{
    for (uint64_t off = 0; off < size; off += 0x200000)
        nk_map_page(base + off, base + off,
                    PTE_PRESENT_BIT | PTE_WRITABLE_BIT, PS_4K);
}

static inline uint32_t mmio_readl(uint64_t base, uint32_t off)
{
    return *((volatile uint32_t *)(base + off));
}

static inline void mmio_writel(uint64_t base, uint32_t off, uint32_t val)
{
    *((volatile uint32_t *)(base + off)) = val;
}

static inline uint64_t mmio_readq(uint64_t base, uint32_t off)
{
    return *((volatile uint64_t *)(base + off));
}

static inline void mmio_writeq(uint64_t base, uint32_t off, uint64_t val)
{
    *((volatile uint64_t *)(base + off)) = val;
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
 * ACPI CEDT (CXL Early Discovery Table) parsing
 *
 * Finds the CXL Fixed Memory Window (CFMWS) base HPA assigned by firmware.
 * CEDT subtable type 1 = CFMWS (ACPI 6.4 Table 5-175).
 * ----------------------------------------------------------------------- */

#define CEDT_SUBTABLE_CHBS   0
#define CEDT_SUBTABLE_CFMWS  1

struct cedt_subtable_hdr {
    uint8_t  type;
    uint8_t  reserved;
    uint16_t length;
} __packed;

/* CEDT CXL Host Bridge Structure (ACPI 6.4 Table 5-174) */
struct cedt_chbs {
    struct cedt_subtable_hdr hdr;
    uint32_t uid;
    uint32_t cxl_version;
    uint32_t reserved;
    uint64_t base;      /* base address of host bridge component registers */
    uint64_t length;
} __packed;

struct cedt_cfmws {
    struct cedt_subtable_hdr hdr;
    uint32_t reserved1;
    uint64_t base_hpa;
    uint64_t window_size;
    uint8_t  interleave_ways;
    uint8_t  granularity;
    uint16_t restrictions;
    uint16_t qtg_id;
    /* interleave_targets[] follow; variable, not accessed here */
} __packed;

static uint64_t cedt_fmw_base = 0;
static uint64_t cedt_fmw_size = 0;

static struct numa_domain *cxl_numa_dom = NULL;

#define CEDT_MAX_HBS 4
static uint64_t cedt_hb_base[CEDT_MAX_HBS];
static int      cedt_num_hbs = 0;

static int parse_cedt(struct acpi_table_header *hdr, void *arg)
{
    uint8_t *p   = (uint8_t *)hdr + sizeof(*hdr);
    uint8_t *end = (uint8_t *)hdr + hdr->length;

    INFO("CEDT: parsing (len=%u)\n", hdr->length);

    while (p < end) {
        struct cedt_subtable_hdr *sub = (struct cedt_subtable_hdr *)p;
        if (sub->length < sizeof(*sub) || p + sub->length > end)
            break;

        if (sub->type == CEDT_SUBTABLE_CHBS &&
            sub->length >= (uint16_t)sizeof(struct cedt_chbs)) {
            struct cedt_chbs *chbs = (struct cedt_chbs *)p;
            INFO("CEDT CHBS: uid=%u base=0x%016llx len=0x%016llx\n",
                 chbs->uid, chbs->base, chbs->length);
            if (cedt_num_hbs < CEDT_MAX_HBS)
                cedt_hb_base[cedt_num_hbs++] = chbs->base;
        }

        if (sub->type == CEDT_SUBTABLE_CFMWS &&
            sub->length >= (uint16_t)sizeof(struct cedt_cfmws)) {
            struct cedt_cfmws *cfmws = (struct cedt_cfmws *)p;
            INFO("CEDT CFMWS: base=0x%016llx size=0x%016llx ways=%u\n",
                 cfmws->base_hpa, cfmws->window_size, cfmws->interleave_ways);
            if (!cedt_fmw_base) {
                cedt_fmw_base = cfmws->base_hpa;
                cedt_fmw_size = cfmws->window_size;
            }
        }
        p += sub->length;
    }
    return 0;
}

static void cedt_init(void)
{
    if (acpi_table_parse("CEDT", parse_cedt, NULL))
        INFO("No CEDT table — CXL FMW base unknown\n");
    else if (cedt_fmw_base)
        INFO("CXL FMW: base=0x%016llx size=0x%016llx\n",
             cedt_fmw_base, cedt_fmw_size);
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
        return 0;
    if (((bar >> 1) & 0x3) == 0x2) {
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
 * Register Locator DVSEC parser — finds the DRI base address
 *
 * CXL 2.0 Table 8-14: Register Block entries start at DVSEC+0x0A,
 * each 8 bytes (Lower DWORD then Upper DWORD).
 * Lower: bits[2:0]=BIR (which BAR), bits[7:3]=RBI (block type),
 *        bits[31:12]=offset[31:12]
 * Upper: bits[31:0]=offset[63:32]
 * ----------------------------------------------------------------------- */

static int find_dri_location(uint8_t bus, uint8_t slot, uint8_t fun,
                              uint64_t *out_addr)
{
    /* Use the Register Locator DVSEC (ID 0x0008, CXL 2.0 §8.1.9) to find
     * the CXL Device Register Interface (RBI=3).
     * Block entries start at DVSEC+0x0C (DWORD-aligned), stride 8 bytes.
     * Lower DWORD layout: bits[2:0]=BIR, bits[13:8]=RBI, bits[31:16]=offset[31:16]
     * Upper DWORD: offset[63:32] */
    uint32_t dvsec_off = find_cxl_dvsec(bus, slot, fun, CXL_DVSEC_REG_LOCATOR, NULL);
    if (!dvsec_off) {
        ERROR("[%02x:%02x.%x] Register Locator DVSEC (0x0008) not found\n",
              bus, slot, fun);
        return -1;
    }

    uint16_t dvsec_len = ecam_readl(bus, slot, fun, dvsec_off + DVSEC_VENDOR_OFFSET) >> 20;
    int n_entries      = (dvsec_len - CXL_REGLOC_BLK1_OFFSET) / CXL_REGLOC_BLK_STRIDE;

    for (int i = 0; i < n_entries; i++) {
        uint32_t entry_off = dvsec_off + CXL_REGLOC_BLK1_OFFSET + i * CXL_REGLOC_BLK_STRIDE;
        uint32_t lo = ecam_readl(bus, slot, fun, entry_off);
        uint32_t hi = ecam_readl(bus, slot, fun, entry_off + 4);

        uint8_t  bir    = lo & 0x7;
        uint8_t  rbi    = (lo >> 8) & 0x3f;
        uint64_t offset = (lo & 0xffff0000UL) | ((uint64_t)hi << 32);

        DEBUG("  regloc[%d]: bir=%u rbi=%u offset=0x%llx\n", i, bir, rbi, offset);

        if (rbi != CXL_REGLOC_RBI_MEMDEV)
            continue;

        uint64_t bar = ecam_bar_addr(bus, slot, fun, bir);
        if (!bar) {
            ERROR("[%02x:%02x.%x] BAR%u for DRI is zero\n", bus, slot, fun, bir);
            return -1;
        }

        *out_addr = bar + offset;
        return 0;
    }

    ERROR("[%02x:%02x.%x] No RBI=3 (MemDev) entry in Register Locator DVSEC\n",
          bus, slot, fun);
    return -1;
}

/* -----------------------------------------------------------------------
 * Mailbox — Device Capability Array parser (CXL 2.0 §8.2.8.1)
 *
 * The Device Capability Array is at the start of the DRI (dri_addr+0).
 * Header is 8 bytes (64-bit); bits [47:32] = entry count.
 * Each entry is 8 bytes: lower half = cap ID, upper half = offset from DRI.
 * ----------------------------------------------------------------------- */

static uint32_t find_mbox_offset(uint64_t dri_addr)
{
    /* CXL 2.0 Table 8-29: 64-bit header at DRI+0.
     * Bits [47:32] = count of capability entries. */
    uint64_t hdr64 = mmio_readq(dri_addr, 0);
    uint16_t count = (uint16_t)(hdr64 >> 32);

    DEBUG("Device Capability Array hdr=0x%016llx count=%u\n", hdr64, count);

    for (int i = 0; i < count; i++) {
        /* Each entry is 16 bytes (Linux: CXLDEV_CAP_SIZEOF).
         * DWORD at entry+0: bits [15:0] = Capability ID
         * DWORD at entry+8: Capability Pointer (offset from DRI base) */
        uint32_t ebase   = CXL_DEVCAP_HDR_SIZE + i * CXL_DEVCAP_ENTRY_SIZE;
        uint16_t cap_id  = (uint16_t)(mmio_readl(dri_addr, ebase) & 0xffff);
        uint32_t cap_off = mmio_readl(dri_addr, ebase + CXL_DEVCAP_ENTRY_CAP_OFF);

        DEBUG("  cap[%d]: id=0x%04x offset=0x%x\n", i, cap_id, cap_off);

        if (cap_id == CXL_DEVCAP_ID_MBOX)
            return cap_off;   /* offset from DRI base */
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * CXL Component Register helpers
 * ----------------------------------------------------------------------- */

/* Walk the CXL Component Register Capability Array (CXL 2.0 §8.2.4).
 *
 * Flat table format (QEMU encoding):
 *   DWORD 0 (base+0x00): array header
 *     bits[15:0]  = 0x0001           (array header ID)
 *     bits[19:16] = CXL cap version
 *     bits[23:20] = cache/mem version
 *     bits[31:24] = N                (number of capability entries)
 *   DWORD i (base + i*4, i = 1..N): capability entry
 *     bits[15:0]  = capability ID
 *     bits[19:16] = capability version
 *     bits[31:20] = pointer P        (direct byte offset from cm region base)
 *
 * Returns byte offset from base to the capability data, 0 if not found. */
static uint32_t comp_cap_find(uint64_t base, uint16_t want_id)
{
    uint32_t hdr0   = mmio_readl(base, 0);
    uint16_t hdr_id = (uint16_t)(hdr0 & 0xffff);
    uint8_t  count  = (uint8_t)(hdr0 >> 24);

    DEBUG("comp_cap_find: hdr=0x%08x id=0x%04x count=%u\n", hdr0, hdr_id, count);

    if (hdr_id != 0x0001 || count == 0 || count > 64)
        return 0;

    for (uint8_t i = 1; i <= count; i++) {
        uint32_t entry   = mmio_readl(base, (uint32_t)i * 4);
        uint16_t cap_id  = (uint16_t)(entry & CXL_COMP_CAP_ID_MASK);
        uint32_t cap_off = (entry >> 20) & 0xfff;   /* pointer is direct byte offset */

        DEBUG("  entry[%u]: id=0x%04x off=0x%x\n", i, cap_id, cap_off);

        if (cap_id == want_id)
            return cap_off;
    }
    return 0;
}

/* CXL 2.0 HDM decoder count encoding: 0→1, 1→2, 2→4, 3→6, 4→8, 5→10. */
static int hdm_decoder_count(uint32_t cap_reg)
{
    int enc = (int)(cap_reg & CXL_HDM_CAP_COUNT_MASK);
    return enc == 0 ? 1 : enc * 2;
}

/* -----------------------------------------------------------------------
 * Mailbox — command submission (CXL 2.0 §8.2.8.4)
 *
 * Flow:
 *   1. Write input payload into Payload registers (if any)
 *   2. Write Command register: opcode + input payload length
 *   3. Set Doorbell bit in Control register to submit
 *   4. Poll Control register until Doorbell is cleared by the device
 *   5. Read Return Code from Status register
 *   6. Read output payload (if any)
 * ----------------------------------------------------------------------- */

static int mbox_send(uint64_t dri_addr, uint32_t mbox_off, uint16_t opcode,
                     const void *in, uint32_t in_len,
                     void *out, uint32_t out_len)
{
    /* Wait for mailbox to be idle before submitting.
     * CTRL is a 32-bit register; use 32-bit accessors. */
    {
        uint32_t ctrl_pre = mmio_readl(dri_addr, mbox_off + CXL_MBOX_CTRL);
        if (ctrl_pre & CXL_MBOX_CTRL_DOORBELL) {
            ERROR("Mailbox busy before submit (opcode 0x%04x ctrl=0x%08x)\n",
                  opcode, ctrl_pre);
            return -1;
        }
    }

    /* Write input payload */
    if (in && in_len) {
        const uint32_t *src = (const uint32_t *)in;
        for (uint32_t i = 0; i < (in_len + 3) / 4; i++)
            mmio_writel(dri_addr, mbox_off + CXL_MBOX_PAYLOAD + i * 4, src[i]);
    }

    /* Write command: opcode in [15:0], payload length in [36:16] */
    mmio_writeq(dri_addr, mbox_off + CXL_MBOX_CMD,
                (uint64_t)opcode | ((uint64_t)in_len << 16));

    /* Ring doorbell (32-bit CTRL register) */
    mmio_writel(dri_addr, mbox_off + CXL_MBOX_CTRL, CXL_MBOX_CTRL_DOORBELL);

    /* Poll until doorbell cleared by device */
    for (int i = 0; i < CXL_MBOX_POLL_LIMIT; i++) {
        if (!(mmio_readl(dri_addr, mbox_off + CXL_MBOX_CTRL) & CXL_MBOX_CTRL_DOORBELL))
            goto done;
    }
    {
        uint32_t ctrl_to = mmio_readl(dri_addr, mbox_off + CXL_MBOX_CTRL);
        ERROR("Mailbox timeout (opcode 0x%04x ctrl=0x%08x)\n", opcode, ctrl_to);
    }
    return -1;

done:;
    uint64_t status64 = mmio_readq(dri_addr, mbox_off + CXL_MBOX_STATUS);
    uint16_t rc = CXL_MBOX_STATUS_RC(status64);
    DEBUG("mbox op=0x%04x status=0x%016llx rc=0x%04x\n", opcode, status64, rc);
    if (rc == CXL_MBOX_RC_UNSUPPORTED || rc == CXL_MBOX_RC_INTERNAL_ERROR)
        return 1;  /* distinguishable: command not available on this device */
    if (rc != CXL_MBOX_RC_SUCCESS && rc != CXL_MBOX_RC_BG_STARTED) {
        ERROR("Mailbox command 0x%04x returned error 0x%04x\n", opcode, rc);
        return -1;
    }

    /* Read output payload */
    if (out && out_len) {
        uint32_t *dst = (uint32_t *)out;
        for (uint32_t i = 0; i < (out_len + 3) / 4; i++)
            dst[i] = mmio_readl(dri_addr, mbox_off + CXL_MBOX_PAYLOAD + i * 4);
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * IDENTIFY Memory Device command (CXL 2.0 §8.2.9.1, opcode 0x0001)
 *
 * No input payload.  Output payload layout (Table 8-37):
 *   0x00  16 bytes  FW Revision (ASCII)
 *   0x10   8 bytes  Total Capacity          (256 MB units)
 *   0x18   8 bytes  Volatile Only Capacity  (256 MB units)
 *   0x20   8 bytes  Persistent Only Capacity(256 MB units)
 *   0x28   8 bytes  Partition Alignment     (256 MB units)
 *   0x30   2 bytes  Info Event Log Size
 *   0x32   2 bytes  Warning Event Log Size
 *   0x34   2 bytes  Failure Event Log Size
 *   0x36   2 bytes  Fatal Event Log Size
 *   0x38   4 bytes  LSA Size
 *   0x3C   3 bytes  Poison List Max MER
 *   0x3F   2 bytes  Inject Poison Limit
 *   0x41   1 byte   Poison Handling Capabilities
 *   0x42   1 byte   QoS Telemetry Capabilities
 * ----------------------------------------------------------------------- */

struct cxl_identify_payload {
    uint8_t  fw_revision[16];
    uint64_t total_capacity;
    uint64_t volatile_capacity;
    uint64_t persistent_capacity;
    uint64_t partition_align;
    uint16_t info_event_log_size;
    uint16_t warning_event_log_size;
    uint16_t failure_event_log_size;
    uint16_t fatal_event_log_size;
    uint32_t lsa_size;
    uint8_t  poison_list_max_mer[3];
    uint16_t inject_poison_limit;
    uint8_t  poison_handling_caps;
    uint8_t  qos_telemetry_caps;
} __packed;

/* GET_EVT_RECORDS input */
struct cxl_get_evt_in {
    uint8_t event_log; /* 0=Informational, 1=Warning, 2=Failure, 3=Fatal */
} __packed;

/* Single event record (CXL 2.0 Table 8-43) */
struct cxl_event_record {
    uint8_t  uuid[16];
    uint8_t  flags;
    uint8_t  length;
    uint16_t rsvd;
    uint64_t handle;
    uint64_t timestamp;
    uint8_t  data[16];
} __packed;

/* GET_EVT_RECORDS output header */
struct cxl_get_evt_out {
    uint8_t  flags;
    uint8_t  rsvd;
    uint16_t overflow_err_count;
    uint64_t first_overflow_ts;
    uint64_t last_overflow_ts;
    uint16_t record_count;
    uint16_t rsvd2;
} __packed;

/* GET/SET_EVT_INT_POLICY */
struct cxl_evt_int_policy {
    uint8_t info_settings;
    uint8_t warning_settings;
    uint8_t failure_settings;
    uint8_t fatal_settings;
} __packed;

/* FW_INFO output (CXL 2.0 Table 8-50) */
struct cxl_fw_info_payload {
    uint8_t  fw_slots;
    uint8_t  fw_slot_info;
    uint8_t  activation_caps;
    uint8_t  rsvd[13];
    uint8_t  slot1_fw_rev[16];
    uint8_t  slot2_fw_rev[16];
    uint8_t  slot3_fw_rev[16];
    uint8_t  slot4_fw_rev[16];
} __packed;

/* TIMESTAMP_GET output */
struct cxl_timestamp_get_payload {
    uint64_t timestamp;
} __packed;

/* TIMESTAMP_SET input */
struct cxl_timestamp_set_payload {
    uint64_t timestamp;
} __packed;

/* Log identifier (16-byte UUID) */
#define CXL_LOG_UUID_CEL  "\x0f\x88\x00\x00\x00\x00\x00\x00\xaa\x55\x00\x00\x00\x00\x00\x00"

/* GET_SUPPORTED_LOGS output */
struct cxl_log_entry {
    uint8_t  uuid[16];
    uint32_t size;
} __packed;

struct cxl_get_supported_logs_out {
    uint16_t count;
    uint8_t  rsvd[6];
    struct cxl_log_entry entries[4];
} __packed;

/* GET_LOG input */
struct cxl_get_log_in {
    uint8_t  uuid[16];
    uint32_t offset;
    uint32_t length;
} __packed;

/* GET_PARTITION_INFO output (CXL 2.0 Table 8-78) */
struct cxl_partition_info_payload {
    uint64_t active_volatile_cap;
    uint64_t active_persistent_cap;
    uint64_t next_volatile_cap;
    uint64_t next_persistent_cap;
} __packed;

/* GET_LSA input */
struct cxl_get_lsa_in {
    uint32_t offset;
    uint32_t length;
} __packed;

/* GET_POISON_LIST input */
struct cxl_get_poison_in {
    uint64_t phy_addr;  /* starting physical address */
    uint64_t length;    /* length in bytes */
} __packed;

/* Single poison record (CXL 2.0 Table 8-108) */
struct cxl_poison_record {
    uint64_t address;   /* DPA[63:6] | length_in_64b_granules[5:0] */
    uint32_t source;    /* bits[2:0] = source type */
    uint32_t rsvd;
} __packed;

/* GET_POISON_LIST output header (CXL 2.0 Table 8-107) */
struct cxl_get_poison_out {
    uint8_t  flags;
    uint8_t  rsvd;
    uint64_t overflow_ts;
    uint16_t count;      /* at offset 10, matching spec and QEMU */
    uint8_t  rsvd2[0x14];
} __packed;

/* INJECT_POISON input */
struct cxl_poison_addr_in {
    uint64_t address;
} __packed;

/* CLEAR_POISON input — address + 64-byte cache line of write data (CXL 2.0 Table 8-111) */
struct cxl_clear_poison_in {
    uint64_t address;
    uint8_t  write_data[64];
} __packed;

/* GET_SECURITY_STATE output */
struct cxl_security_state_payload {
    uint32_t security_state;
} __packed;

static int cxl_identify(struct cxl_dev *dev)
{
    struct cxl_identify_payload p;

    if (mbox_send(dev->dri_addr, dev->mbox_off,
                  CXL_OPCODE_IDENTIFY, NULL, 0, &p, sizeof(p))) {
        ERROR("[%02x:%02x.%x] IDENTIFY failed\n",
              dev->bus, dev->slot, dev->fun);
        return -1;
    }

    memcpy(dev->fw_revision, p.fw_revision, 16);
    dev->fw_revision[16]  = '\0';
    dev->total_mb         = p.total_capacity      * 256;
    dev->volatile_mb      = p.volatile_capacity   * 256;
    dev->persistent_mb    = p.persistent_capacity * 256;
    dev->lsa_size         = p.lsa_size;

    INFO("[%02x:%02x.%x] IDENTIFY ok: fw=\"%s\" total=%lluMB "
         "volatile=%lluMB persistent=%lluMB lsa=%uB\n",
         dev->bus, dev->slot, dev->fun,
         dev->fw_revision, dev->total_mb,
         dev->volatile_mb, dev->persistent_mb, dev->lsa_size);

    return 0;
}

/* -----------------------------------------------------------------------
 * Timestamp commands
 * ----------------------------------------------------------------------- */

static int cxl_timestamp_get(struct cxl_dev *dev, uint64_t *out_ts)
{
    struct cxl_timestamp_get_payload p;
    if (mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_TIMESTAMP_GET,
                  NULL, 0, &p, sizeof(p)))
        return -1;
    *out_ts = p.timestamp;
    return 0;
}

static int cxl_timestamp_set(struct cxl_dev *dev, uint64_t ts)
{
    struct cxl_timestamp_set_payload p = { .timestamp = ts };
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_TIMESTAMP_SET,
                     &p, sizeof(p), NULL, 0);
}

/* -----------------------------------------------------------------------
 * Firmware Info
 * ----------------------------------------------------------------------- */

static int cxl_fw_info(struct cxl_dev *dev, struct cxl_fw_info_payload *out)
{
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_FW_INFO,
                     NULL, 0, out, sizeof(*out));
}

/* -----------------------------------------------------------------------
 * Logs
 * ----------------------------------------------------------------------- */

static int cxl_get_supported_logs(struct cxl_dev *dev,
                                   struct cxl_get_supported_logs_out *out)
{
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_SUPPORTED_LOGS,
                     NULL, 0, out, sizeof(*out));
}

static int cxl_get_log(struct cxl_dev *dev, const uint8_t *uuid,
                       uint32_t offset, void *buf, uint32_t len)
{
    struct cxl_get_log_in in;
    memcpy(in.uuid, uuid, 16);
    in.offset = offset;
    in.length = len;
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_LOG,
                     &in, sizeof(in), buf, len);
}

/* -----------------------------------------------------------------------
 * Events
 * ----------------------------------------------------------------------- */

static int cxl_get_evt_records(struct cxl_dev *dev, uint8_t log_type,
                                struct cxl_get_evt_out *hdr,
                                struct cxl_event_record *recs, int max_recs,
                                int *out_count)
{
    struct cxl_get_evt_in in = { .event_log = log_type };
    /* output: header + up to max_recs records */
    uint8_t buf[sizeof(struct cxl_get_evt_out) +
                sizeof(struct cxl_event_record) * 16];
    memset(buf, 0, sizeof(buf));
    int limit = max_recs > 16 ? 16 : max_recs;
    uint32_t out_sz = sizeof(struct cxl_get_evt_out) +
                      limit * sizeof(struct cxl_event_record);
    if (mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_EVT_RECORDS,
                  &in, sizeof(in), buf, out_sz))
        return -1;
    memcpy(hdr, buf, sizeof(*hdr));
    int cnt = hdr->record_count < limit ? hdr->record_count : limit;
    if (recs)
        memcpy(recs, buf + sizeof(*hdr), cnt * sizeof(struct cxl_event_record));
    *out_count = cnt;
    return 0;
}

static int cxl_get_evt_int_policy(struct cxl_dev *dev,
                                   struct cxl_evt_int_policy *out)
{
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_EVT_INT_POLICY,
                     NULL, 0, out, sizeof(*out));
}

static int cxl_set_evt_int_policy(struct cxl_dev *dev,
                                   const struct cxl_evt_int_policy *in)
{
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_SET_EVT_INT_POLICY,
                     in, sizeof(*in), NULL, 0);
}

/* -----------------------------------------------------------------------
 * Partition Info / LSA
 * ----------------------------------------------------------------------- */

static int cxl_get_partition_info(struct cxl_dev *dev,
                                   struct cxl_partition_info_payload *out)
{
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_PARTITION_INFO,
                     NULL, 0, out, sizeof(*out));
}

static int cxl_get_lsa(struct cxl_dev *dev, uint32_t offset,
                        void *buf, uint32_t len)
{
    struct cxl_get_lsa_in in = { .offset = offset, .length = len };
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_LSA,
                     &in, sizeof(in), buf, len);
}

static int cxl_set_lsa(struct cxl_dev *dev, uint32_t offset,
                        const void *buf, uint32_t len)
{
    /* SET_LSA payload: 4-byte offset, 4-byte reserved, then data */
    uint8_t tmp[8 + 256];
    if (len > 256)
        return -1;
    ((uint32_t *)tmp)[0] = offset;
    ((uint32_t *)tmp)[1] = 0;
    memcpy(tmp + 8, buf, len);
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_SET_LSA,
                     tmp, 8 + len, NULL, 0);
}

/* -----------------------------------------------------------------------
 * Poison
 * ----------------------------------------------------------------------- */

static int cxl_get_poison_list(struct cxl_dev *dev, uint64_t phy_addr,
                                uint64_t length,
                                struct cxl_get_poison_out *hdr,
                                struct cxl_poison_record *recs, int max_recs,
                                int *out_count)
{
    struct cxl_get_poison_in in = { .phy_addr = phy_addr, .length = length };
    uint8_t buf[sizeof(struct cxl_get_poison_out) +
                sizeof(struct cxl_poison_record) * 16];
    memset(buf, 0, sizeof(buf));
    int limit = max_recs > 16 ? 16 : max_recs;
    uint32_t out_sz = sizeof(struct cxl_get_poison_out) +
                      limit * sizeof(struct cxl_poison_record);
    if (mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_POISON_LIST,
                  &in, sizeof(in), buf, out_sz))
        return -1;
    memcpy(hdr, buf, sizeof(*hdr));
    int cnt = hdr->count < limit ? hdr->count : limit;
    if (recs)
        memcpy(recs, buf + sizeof(*hdr), cnt * sizeof(struct cxl_poison_record));
    *out_count = cnt;
    return 0;
}

static int cxl_inject_poison(struct cxl_dev *dev, uint64_t address)
{
    struct cxl_poison_addr_in in = { .address = address };
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_INJECT_POISON,
                     &in, sizeof(in), NULL, 0);
}

static int cxl_clear_poison(struct cxl_dev *dev, uint64_t address)
{
    struct cxl_clear_poison_in in;
    in.address = address;
    memset(in.write_data, 0, sizeof(in.write_data));
    return mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_CLEAR_POISON,
                     &in, sizeof(in), NULL, 0);
}

/* -----------------------------------------------------------------------
 * Sanitize (background operation)
 * ----------------------------------------------------------------------- */

static int cxl_sanitize_overwrite(struct cxl_dev *dev)
{
    /* No input payload; QEMU returns immediately, sets bg_status */
    int rc = mbox_send(dev->dri_addr, dev->mbox_off,
                       CXL_OPCODE_SANITIZE_OVERWRITE, NULL, 0, NULL, 0);
    if (rc)
        return rc;
    nk_vc_printf("  sanitize submitted; polling background status...\n");
    for (int i = 0; i < 1000000; i++) {
        uint64_t bg  = mmio_readq(dev->dri_addr, dev->mbox_off + CXL_MBOX_BG_STATUS);
        uint8_t  active = (bg & 0x1);        /* bit 0: 1=in-progress, 0=done */
        uint8_t  pct    = (bg >> 8) & 0x7f;  /* bits[14:8]: completion % */
        if (!active) {
            uint16_t bg_rc = (bg >> 32) & 0xffff;  /* bits[47:32]: return code */
            nk_vc_printf("  sanitize complete: bg_rc=0x%04x\n", bg_rc);
            return bg_rc ? -1 : 0;
        }
        if (i % 100000 == 0)
            nk_vc_printf("  sanitize %u%%...\n", pct);
    }
    nk_vc_printf("  sanitize TIMEOUT\n");
    return -1;
}

/* -----------------------------------------------------------------------
 * Security State
 * ----------------------------------------------------------------------- */

static int cxl_get_security_state(struct cxl_dev *dev, uint32_t *state_out)
{
    struct cxl_security_state_payload p;
    if (mbox_send(dev->dri_addr, dev->mbox_off, CXL_OPCODE_GET_SECURITY_STATE,
                  NULL, 0, &p, sizeof(p)))
        return -1;
    *state_out = p.security_state;
    return 0;
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
    case 0x0008: return "Register Locator DVSEC";
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
    nk_vc_printf("  DVSEC:  offset=0x%03x id=0x%04x (%s)\n",
                 dev->dvsec_offset, dev->dvsec_id, dvsec_id_str(dev->dvsec_id));
    nk_vc_printf("  BAR0:   addr=0x%016lx size=0x%016lx\n",
                 dev->bar0_addr, dev->bar0_size);
    if (dev->fw_revision[0])
        nk_vc_printf("  FW:     \"%s\"\n", dev->fw_revision);
    if (dev->total_mb)
        nk_vc_printf("  Capacity: total=%lluMB volatile=%lluMB persistent=%lluMB\n",
                     dev->total_mb, dev->volatile_mb, dev->persistent_mb);
    if (dev->kmem_region)
        nk_vc_printf("  kmem:   registered at 0x%016llx size=%lluMB\n",
                     dev->kmem_region->base_addr, dev->kmem_region->len >> 20);
    else
        nk_vc_printf("  kmem:   not registered\n");
}

/* Default CXL FMW base: right above the 4GB main-memory ceiling.
 * Matches the QEMU run script: -M cxl-fmw.0.size=4G with 4G main RAM. */
#define CXL_HDM_DEFAULT_HPA_BASE    0x100000000ULL

/* -----------------------------------------------------------------------
 * Host bridge HDM decoder programming
 *
 * Programs one decoder on the CXL host bridge (pxb-cxl) for a specific HPA
 * sub-range, with the target set to the root port slot that leads to the
 * endpoint.  Must be called once per endpoint, incrementing dec_idx.
 * ----------------------------------------------------------------------- */

static int cxl_program_host_bridge_decoder(int dec_idx,
                                            uint64_t hpa_base, uint64_t hpa_size,
                                            uint8_t target_port)
{
    if (cedt_num_hbs == 0) {
        nk_vc_printf("  no CEDT CHBS — cannot program host bridge decoder\n");
        return -1;
    }

    uint64_t hb_base = cedt_hb_base[0];
    bar0_map(hb_base, 0x10000);

    uint64_t cm = hb_base + CXL_COMP_CM_OFFSET;
    uint32_t hdm_off = comp_cap_find(cm, CXL_COMP_CAP_ID_HDM);
    if (!hdm_off) {
        nk_vc_printf("  HB HDM capability not found\n");
        return -1;
    }

    uint32_t ctrl = mmio_readl(cm, hdm_off + CXL_HDM_DEC_CTRL(dec_idx));
    if (ctrl & CXL_HDM_DEC_CTRL_COMMITTED) {
        nk_vc_printf("  HB decoder[%d] already committed\n", dec_idx);
        return 0;
    }

    mmio_writel(cm, hdm_off + CXL_HDM_DEC_BASE_LO(dec_idx),
                (uint32_t)(hpa_base & 0xf0000000u));
    mmio_writel(cm, hdm_off + CXL_HDM_DEC_BASE_HI(dec_idx),
                (uint32_t)(hpa_base >> 32));
    mmio_writel(cm, hdm_off + CXL_HDM_DEC_SIZE_LO(dec_idx),
                (uint32_t)(hpa_size & 0xf0000000u));
    mmio_writel(cm, hdm_off + CXL_HDM_DEC_SIZE_HI(dec_idx),
                (uint32_t)(hpa_size >> 32));
    /* target list low: bits[3:0] = target port for 1-way interleave */
    mmio_writel(cm, hdm_off + CXL_HDM_DEC_TGT_LO(dec_idx), target_port & 0xf);
    mmio_writel(cm, hdm_off + CXL_HDM_DEC_CTRL(dec_idx), CXL_HDM_DEC_CTRL_COMMIT);

    int committed = 0, j;
    for (j = 0; j < 1000000; j++) {
        ctrl = mmio_readl(cm, hdm_off + CXL_HDM_DEC_CTRL(dec_idx));
        if (ctrl & CXL_HDM_DEC_CTRL_COMMITTED) { committed = 1; break; }
    }
    if (!committed) {
        nk_vc_printf("  HB decoder[%d] commit TIMEOUT\n", dec_idx);
        return -1;
    }

    uint32_t gctr = mmio_readl(cm, hdm_off + CXL_HDM_GLOB_CTRL);
    mmio_writel(cm, hdm_off + CXL_HDM_GLOB_CTRL, gctr | CXL_HDM_GLOB_CTRL_ENABLE);

    nk_vc_printf("  HB decoder[%d] committed: hpa=0x%016llx size=0x%016llx target=%u\n",
                 dec_idx, hpa_base, hpa_size, target_port);
    return 0;
}

/* -----------------------------------------------------------------------
 * HDM Decoder programming  (CXL 2.0 §8.2.4 / Table 8-23)
 * ----------------------------------------------------------------------- */

/* Program one HDM decoder on dev.
 * hpa_base and hpa_size must be 256 MB aligned (bits[27:0] == 0).
 * DPA skip is always 0 (decoder maps DPA from device start). */
static int cxl_hdm_program_decoder(struct cxl_dev *dev, int dec_idx,
                                    uint64_t hpa_base, uint64_t hpa_size,
                                    int is_pmem)
{
    if (!dev->bar0_addr) {
        nk_vc_printf("  BAR0 not mapped\n");
        return -1;
    }

    bar0_map(dev->bar0_addr, 0x4000);
    uint64_t cm_base = dev->bar0_addr + CXL_COMP_CM_OFFSET;

    uint32_t hdm_off = comp_cap_find(cm_base, CXL_COMP_CAP_ID_HDM);
    if (!hdm_off) {
        nk_vc_printf("  HDM Decoder capability not found\n");
        return -1;
    }

    int ndec = hdm_decoder_count(mmio_readl(cm_base, hdm_off + CXL_HDM_CAP_REG));
    if (dec_idx >= ndec) {
        nk_vc_printf("  Decoder %d out of range (device has %d)\n", dec_idx, ndec);
        return -1;
    }

    uint32_t ctrl = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_CTRL(dec_idx));
    if (ctrl & CXL_HDM_DEC_CTRL_COMMITTED) {
        nk_vc_printf("  Decoder %d already committed — run cxl hdm to inspect\n", dec_idx);
        return -1;
    }

    if ((hpa_base & 0x0fffffffULL) || (hpa_size & 0x0fffffffULL)) {
        nk_vc_printf("  hpa_base and hpa_size must be 256 MB aligned\n");
        return -1;
    }
    if (!hpa_size) {
        nk_vc_printf("  hpa_size is 0\n");
        return -1;
    }

    /* 1. Write base, size, DPA skip (skip = 0: start of device DPA space). */
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_BASE_LO(dec_idx),
                (uint32_t)(hpa_base & 0xf0000000u));
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_BASE_HI(dec_idx),
                (uint32_t)(hpa_base >> 32));
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_SIZE_LO(dec_idx),
                (uint32_t)(hpa_size & 0xf0000000u));
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_SIZE_HI(dec_idx),
                (uint32_t)(hpa_size >> 32));
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_SKIP_LO(dec_idx), 0);
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_SKIP_HI(dec_idx), 0);

    /* 2. Write control with Commit bit: 1-way, 256B granularity, volatile/pmem. */
    uint32_t new_ctrl = CXL_HDM_DEC_CTRL_COMMIT;
    if (is_pmem)
        new_ctrl |= CXL_HDM_DEC_CTRL_PMEM;
    mmio_writel(cm_base, hdm_off + CXL_HDM_DEC_CTRL(dec_idx), new_ctrl);

    /* Readback to confirm write reached the register. */
    uint32_t ctrl_rb = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_CTRL(dec_idx));
    nk_vc_printf("  ctrl after write: 0x%08x (commit=%d)\n",
                 ctrl_rb, (ctrl_rb & CXL_HDM_DEC_CTRL_COMMIT) != 0);

    /* 3. Poll for Committed or Error. */
    int committed = 0;
    for (int i = 0; i < 1000000; i++) {
        ctrl = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_CTRL(dec_idx));
        if (ctrl & CXL_HDM_DEC_CTRL_ERRCODE_MASK) {
            nk_vc_printf("  Decoder %d commit ERROR (ctrl=0x%08x errcode=%u)\n",
                         dec_idx, ctrl, (ctrl & CXL_HDM_DEC_CTRL_ERRCODE_MASK) >> 12);
            return -1;
        }
        if (ctrl & CXL_HDM_DEC_CTRL_COMMITTED) {
            committed = 1;
            break;
        }
    }
    if (!committed) {
        ctrl = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_CTRL(dec_idx));
        nk_vc_printf("  Decoder %d commit TIMEOUT (ctrl=0x%08x)\n", dec_idx, ctrl);
        return -1;
    }

    /* 4. Enable global HDM decoder control. */
    uint32_t gctr = mmio_readl(cm_base, hdm_off + CXL_HDM_GLOB_CTRL);
    mmio_writel(cm_base, hdm_off + CXL_HDM_GLOB_CTRL,
                gctr | CXL_HDM_GLOB_CTRL_ENABLE);

    nk_vc_printf("  [%02x:%02x.%x] decoder[%d] committed: "
                 "hpa=0x%016llx size=0x%016llx type=%s\n",
                 dev->bus, dev->slot, dev->fun, dec_idx,
                 hpa_base, hpa_size, is_pmem ? "pmem" : "volatile");
    return 0;
}

/* -----------------------------------------------------------------------
 * HDM Decoder dump  (CXL 2.0 §8.2.4 / Table 8-22 & 8-23)
 * ----------------------------------------------------------------------- */

static void cxl_dump_hdm(struct cxl_dev *dev)
{
    if (!dev->bar0_addr) {
        nk_vc_printf("  BAR0 not mapped\n");
        return;
    }

    /* CXL Capability Array is in the CXL.cache+mem sub-region at BAR0+0x1000. */
    bar0_map(dev->bar0_addr, 0x4000);
    uint64_t cm_base = dev->bar0_addr + CXL_COMP_CM_OFFSET;

    uint32_t hdm_off = comp_cap_find(cm_base, CXL_COMP_CAP_ID_HDM);
    if (!hdm_off) {
        nk_vc_printf("  HDM Decoder capability not found in component registers\n");
        return;
    }

    uint32_t cap_reg  = mmio_readl(cm_base, hdm_off + CXL_HDM_CAP_REG);
    uint32_t ctrl_reg = mmio_readl(cm_base, hdm_off + CXL_HDM_GLOB_CTRL);
    int      ndec     = hdm_decoder_count(cap_reg);

    nk_vc_printf("  HDM cap @ bar0+0x%x: %d decoder(s) global=%s\n",
                 CXL_COMP_CM_OFFSET + hdm_off, ndec,
                 (ctrl_reg & CXL_HDM_GLOB_CTRL_ENABLE) ? "enabled" : "disabled");

    static const uint32_t iw_tbl[] = {1, 2, 4, 8, 16};
    static const uint32_t ig_tbl[] = {256, 512, 1024, 2048, 4096, 8192, 16384};

    for (int i = 0; i < ndec && i < CXL_HDM_MAX_DECODERS; i++) {
        uint32_t base_lo = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_BASE_LO(i));
        uint32_t base_hi = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_BASE_HI(i));
        uint32_t size_lo = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_SIZE_LO(i));
        uint32_t size_hi = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_SIZE_HI(i));
        uint32_t ctrl    = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_CTRL(i));
        uint32_t skip_lo = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_SKIP_LO(i));
        uint32_t skip_hi = mmio_readl(cm_base, hdm_off + CXL_HDM_DEC_SKIP_HI(i));

        uint64_t hpa_base = ((uint64_t)base_hi << 32) | (base_lo & 0xf0000000u);
        uint64_t hpa_size = ((uint64_t)size_hi << 32) | (size_lo & 0xf0000000u);
        uint64_t dpa_skip = ((uint64_t)skip_hi << 32) | skip_lo;

        int      committed = (ctrl & CXL_HDM_DEC_CTRL_COMMITTED)   != 0;
        int      errcode   = (ctrl & CXL_HDM_DEC_CTRL_ERRCODE_MASK) >> 12;
        unsigned iw_enc    = (ctrl & CXL_HDM_DEC_CTRL_IW_MASK) >> CXL_HDM_DEC_CTRL_IW_SHIFT;
        unsigned ig_enc    = (ctrl & CXL_HDM_DEC_CTRL_IG_MASK) >> CXL_HDM_DEC_CTRL_IG_SHIFT;
        int      is_pmem   = (ctrl & CXL_HDM_DEC_CTRL_PMEM)        != 0;

        uint32_t iw = iw_enc < 5 ? iw_tbl[iw_enc] : 0;
        uint32_t ig = ig_enc < 7 ? ig_tbl[ig_enc] : 0;

        nk_vc_printf("  [%d] hpa=0x%016llx size=0x%016llx ctrl=0x%08x %s%s\n",
                     i, hpa_base, hpa_size, ctrl,
                     committed ? "committed" : "uncommitted",
                     errcode ? " ERROR" : "");
        nk_vc_printf("      iw=%u ig=%uB type=%s dpa_skip=0x%016llx\n",
                     iw, ig, is_pmem ? "pmem" : "volatile", dpa_skip);
    }
}

/* -----------------------------------------------------------------------
 * Probe a single PCI function
 * ----------------------------------------------------------------------- */

static int probe_function(uint8_t bus, uint8_t slot, uint8_t fun)
{
    uint32_t id_dw  = ecam_readl(bus, slot, fun, PCI_CFG_VENDOR);
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

    /* Map BAR0 (component registers) */
    if (dev->bar0_addr && dev->bar0_size)
        bar0_map(dev->bar0_addr, dev->bar0_size);

    /* Locate the Device Register Interface by scanning BARs for the
     * DRI header (cap_id=0x0000, non-zero count per CXL 2.0 Table 8-29). */
    if (find_dri_location(bus, slot, fun, &dev->dri_addr)) {
        ERROR("[%02x:%02x.%x] DRI not found\n", bus, slot, fun);
    } else {
        INFO("[%02x:%02x.%x] DRI at 0x%llx\n", bus, slot, fun, dev->dri_addr);

        /* Map enough of the DRI region to reach the mailbox (which in
         * QEMU is at DRI+0x400, well within the first 4KB page). */
        bar0_map(dev->dri_addr, 0x10000);

        /* Locate mailbox within the Device Capability Array */
        dev->mbox_off = find_mbox_offset(dev->dri_addr);
        if (!dev->mbox_off) {
            INFO("[%02x:%02x.%x] mailbox not found; falling back to dri+0x400\n",
                 bus, slot, fun);
            dev->mbox_off = 0x400;
        }

        /* Payload size: 2^(caps[3:0]) DWORDs */
        uint32_t caps = mmio_readl(dev->dri_addr, dev->mbox_off + CXL_MBOX_CAPS);
        dev->mbox_payload_size = (1 << CXL_MBOX_CAPS_PAYLOAD_SZ(caps)) * 4;
        INFO("[%02x:%02x.%x] mailbox at dri+0x%x, payload %u bytes, caps=0x%08x\n",
             bus, slot, fun, dev->mbox_off, dev->mbox_payload_size, caps);

        cxl_identify(dev);
    }

    list_add(&dev->dev_node, &dev_list);
    return 0;
}

/* -----------------------------------------------------------------------
 * Init / deinit
 * ----------------------------------------------------------------------- */

static void cxl_program_all_hdm(uint64_t hpa_base);

int cxl_init(struct naut_info *naut)
{
    INFO("init\n");

    INIT_LIST_HEAD(&dev_list);

    if (ecam_init())
        return -1;

    cedt_init();

    INFO("Scanning all ECAM buses for CXL devices\n");

    for (int r = 0; r < num_ecam_regions; r++) {
        struct ecam_region *region = &ecam_regions[r];

        for (int bus = region->start_bus; bus <= region->end_bus; bus++) {
            for (int slot = 0; slot < 32; slot++) {
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

    if (list_empty(&dev_list)) {
        INFO("No CXL devices found\n");
        return 0;
    }

#ifdef NAUT_CONFIG_CXL_AUTO_INIT_HDM
    cxl_program_all_hdm(cedt_fmw_base ? cedt_fmw_base : CXL_HDM_DEFAULT_HPA_BASE);
#endif

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
 * HDM programming — program all discovered devices and register with kmem
 * ----------------------------------------------------------------------- */

static void cxl_program_all_hdm(uint64_t hpa_base)
{
    struct list_head *cur;
    int hb_dec_idx = 0;
    struct sys_info *sys = &(nk_get_nautilus_info()->sys);

    /* Create a dedicated NUMA domain for CXL memory so the allocator
     * treats it as a remote tier, preferring DRAM first. */
    struct numa_domain *cxl_dom = NULL;
    unsigned cxl_dom_id = nk_get_num_domains();
    if (cxl_dom_id < MAX_NUMA_DOMAINS) {
        cxl_dom = kmem_malloc(sizeof(*cxl_dom));
        if (cxl_dom) {
            memset(cxl_dom, 0, sizeof(*cxl_dom));
            cxl_dom->id = cxl_dom_id;
            INIT_LIST_HEAD(&cxl_dom->regions);
            INIT_LIST_HEAD(&cxl_dom->adj_list);
            sys->locality_info.domains[cxl_dom_id] = cxl_dom;
            sys->locality_info.num_domains++;
            cxl_numa_dom = cxl_dom;
            INFO("CXL NUMA domain %u created\n", cxl_dom_id);
        } else {
            ERROR("Failed to allocate CXL NUMA domain\n");
        }
    } else {
        ERROR("MAX_NUMA_DOMAINS reached — CXL domain not created\n");
    }

    list_for_each(cur, &dev_list) {
        struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);

        if (!dev->total_mb) {
            INFO("[%02x:%02x.%x] total_mb=0 — skipping HDM programming\n",
                 dev->bus, dev->slot, dev->fun);
            continue;
        }

        uint64_t hpa_size = (uint64_t)dev->total_mb << 20;
        int is_pmem = dev->persistent_mb > 0;

        /* Find the root port for this endpoint by scanning for a bridge
         * whose secondary bus matches the device's bus number. */
        uint8_t rp_slot = 0xff;
        for (int r2 = 0; r2 < num_ecam_regions && rp_slot == 0xff; r2++) {
            for (int b2 = ecam_regions[r2].start_bus;
                 b2 <= ecam_regions[r2].end_bus && rp_slot == 0xff; b2++) {
                for (int s2 = 0; s2 < 32 && rp_slot == 0xff; s2++) {
                    uint32_t id2 = ecam_readl(b2, s2, 0, PCI_CFG_VENDOR);
                    if ((id2 & 0xffff) == PCI_VENDOR_NONE) continue;
                    uint32_t cls2 = ecam_readl(b2, s2, 0, PCI_CFG_CLASS);
                    if (((cls2 >> 24) & 0xff) != 0x06) continue;
                    uint8_t sec2 = (ecam_readl(b2, s2, 0, PCI_CFG_SEC_BUS) >> 8) & 0xff;
                    if (sec2 == dev->bus)
                        rp_slot = (uint8_t)s2;
                }
            }
        }

        INFO("[%02x:%02x.%x] programming decoder[0]: "
             "hpa=0x%016llx size=0x%016llx (%lluMB) type=%s rp_slot=%u\n",
             dev->bus, dev->slot, dev->fun,
             hpa_base, hpa_size, dev->total_mb,
             is_pmem ? "pmem" : "volatile",
             rp_slot == 0xff ? 255 : rp_slot);

        if (rp_slot != 0xff)
            cxl_program_host_bridge_decoder(hb_dec_idx++, hpa_base, hpa_size, rp_slot);

        if (cxl_hdm_program_decoder(dev, 0, hpa_base, hpa_size, is_pmem) == 0) {
            struct mem_region *mr = kmem_malloc(sizeof(*mr));
            if (!mr) {
                ERROR("[%02x:%02x.%x] kmem_malloc for mem_region failed\n",
                      dev->bus, dev->slot, dev->fun);
            } else {
                memset(mr, 0, sizeof(*mr));
                mr->base_addr     = hpa_base;
                mr->len           = hpa_size;
                mr->enabled       = 1;
                mr->hot_pluggable = 1;
                mr->nonvolatile   = is_pmem;
                INIT_LIST_HEAD(&mr->entry);
                INIT_LIST_HEAD(&mr->glob_link);

                cxl_mem_map(hpa_base, hpa_size);

                if (kmem_create_zone(mr) < 0) {
                    ERROR("[%02x:%02x.%x] kmem_create_zone failed\n",
                          dev->bus, dev->slot, dev->fun);
                    kmem_free(mr);
                } else {
                    kmem_add_memory(mr, hpa_base, hpa_size);
                    dev->kmem_region = mr;
                    INFO("[%02x:%02x.%x] registered %lluMB at 0x%016llx with kmem\n",
                         dev->bus, dev->slot, dev->fun, hpa_size >> 20, hpa_base);

                    /* Associate region with the CXL NUMA domain. */
                    if (cxl_dom) {
                        mr->domain_id = cxl_dom_id;
                        list_add_tail(&mr->entry, &cxl_dom->regions);
                        cxl_dom->addr_space_size += hpa_size;
                        cxl_dom->num_regions++;
                    }
                }
            }
            hpa_base += hpa_size;
        }
    }

    /* Wire CXL domain into every existing domain's adjacency list (at the
     * tail = farthest), and wire existing domains into the CXL domain's
     * adjacency list so distance-ordered traversal works both ways. */
    if (cxl_dom && cxl_dom->num_regions > 0) {
        for (unsigned i = 0; i < cxl_dom_id; i++) {
            struct numa_domain *d = sys->locality_info.domains[i];
            if (!d) continue;

            struct domain_adj_entry *fwd = kmem_malloc(sizeof(*fwd));
            if (fwd) {
                fwd->domain = cxl_dom;
                list_add_tail(&fwd->list_ent, &d->adj_list);
            }

            struct domain_adj_entry *rev = kmem_malloc(sizeof(*rev));
            if (rev) {
                rev->domain = d;
                list_add_tail(&rev->list_ent, &cxl_dom->adj_list);
            }
        }
        INFO("CXL NUMA domain %u: %u region(s) %lluMB wired into topology\n",
             cxl_dom_id, cxl_dom->num_regions, cxl_dom->addr_space_size >> 20);
    }
}

/* -----------------------------------------------------------------------
 * Shell command
 * ----------------------------------------------------------------------- */

static int handle_cxl(char *buf, void *priv)
{
    struct list_head *cur;
    int count = 0;

    if (!strcmp(buf, "cxl l")) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            dump_dev(dev);
            count++;
        }
        if (!count)
            nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl identify", 12)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;
            nk_vc_printf("[%02x:%02x.%x] running IDENTIFY (mbox_off=0x%x)...\n",
                         dev->bus, dev->slot, dev->fun, dev->mbox_off);
            if (!dev->dri_addr || !dev->mbox_off) {
                nk_vc_printf("  DRI or mailbox not found\n");
                continue;
            }
            if (cxl_identify(dev))
                nk_vc_printf("  IDENTIFY failed\n");
            else
                nk_vc_printf("  fw=\"%s\" total=%lluMB\n",
                             dev->fw_revision, dev->total_mb);
        }
        if (!count)
            nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl dvsec", 9)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;
            nk_vc_printf("[%02x:%02x.%x] extended capability chain:\n",
                         dev->bus, dev->slot, dev->fun);
            uint32_t off = PCIE_EXT_CAP_OFFSET;
            while (off && off < 0x1000) {
                uint32_t hdr = ecam_readl(dev->bus, dev->slot, dev->fun, off);
                if (!hdr || hdr == 0xffffffff)
                    break;
                uint16_t cap_id   = PCIE_EXT_CAP_ID(hdr);
                uint16_t cap_ver  = (hdr >> 16) & 0xf;
                uint32_t next_off = PCIE_EXT_CAP_NEXT(hdr);
                if (cap_id == PCIE_EXT_CAP_ID_DVSEC) {
                    uint32_t v        = ecam_readl(dev->bus, dev->slot, dev->fun, off + DVSEC_VENDOR_OFFSET);
                    uint16_t vendor   = v & 0xffff;
                    uint16_t dvsec_rev = (v >> 16) & 0xf;
                    uint16_t dvsec_len = v >> 20;
                    uint16_t dvsec_id  = ecam_readl(dev->bus, dev->slot, dev->fun, off + DVSEC_ID_OFFSET) & 0xffff;
                    nk_vc_printf("  +0x%03x DVSEC vendor=0x%04x rev=%u len=%u id=0x%04x (%s)\n",
                                 off, vendor, dvsec_rev, dvsec_len, dvsec_id, dvsec_id_str(dvsec_id));
                    if (vendor == CXL_DVSEC_VENDOR_ID && dvsec_id == CXL_DVSEC_REG_LOCATOR) {
                        nk_vc_printf("    raw dwords:");
                        for (int j = 0; j < (int)(dvsec_len / 4); j++)
                            nk_vc_printf(" [+%02x]%08x", j * 4,
                                ecam_readl(dev->bus, dev->slot, dev->fun, off + j * 4));
                        nk_vc_printf("\n");
                        int n = (dvsec_len - CXL_REGLOC_BLK1_OFFSET) / CXL_REGLOC_BLK_STRIDE;
                        for (int i = 0; i < n; i++) {
                            uint32_t e  = off + CXL_REGLOC_BLK1_OFFSET + i * CXL_REGLOC_BLK_STRIDE;
                            uint32_t lo = ecam_readl(dev->bus, dev->slot, dev->fun, e);
                            uint32_t hi = ecam_readl(dev->bus, dev->slot, dev->fun, e + 4);
                            nk_vc_printf("    block[%d]: lo=0x%08x hi=0x%08x bir=%u rbi=%u offset=0x%llx\n",
                                         i, lo, hi, lo & 0x7, (lo >> 8) & 0x3f,
                                         (lo & 0xffff0000UL) | ((uint64_t)hi << 32));
                        }
                    }
                } else {
                    nk_vc_printf("  +0x%03x cap=0x%04x ver=%u\n", off, cap_id, cap_ver);
                }
                off = next_off;
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl diag", 8)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;

            nk_vc_printf("[%02x:%02x.%x] bar0=0x%llx dri=0x%llx\n",
                         dev->bus, dev->slot, dev->fun,
                         dev->bar0_addr, dev->dri_addr);

            if (!dev->dri_addr) {
                nk_vc_printf("  DRI not found\n");
                continue;
            }

            /* Raw DWORD dump: DRI+0x00 through DRI+0x40 */
            nk_vc_printf("  DRI raw:");
            for (int j = 0; j < 16; j++) {
                if (j % 4 == 0)
                    nk_vc_printf("\n  +%02x:", j * 4);
                nk_vc_printf(" %08x", mmio_readl(dev->dri_addr, j * 4));
            }
            nk_vc_printf("\n");

            /* Device Capability Array header (64-bit, count in bits [47:32]) */
            uint64_t devcap_hdr   = mmio_readq(dev->dri_addr, 0);
            uint16_t devcap_count = (uint16_t)(devcap_hdr >> 32);
            nk_vc_printf("  DevCap hdr=0x%016llx count=%u\n",
                         devcap_hdr, devcap_count);

            /* 16-byte entries: cap_id at entry+0, cap_off at entry+8 */
            for (int i = 0; i < devcap_count && i < 8; i++) {
                uint32_t ebase   = CXL_DEVCAP_HDR_SIZE + i * CXL_DEVCAP_ENTRY_SIZE;
                uint16_t cap_id  = (uint16_t)(mmio_readl(dev->dri_addr, ebase) & 0xffff);
                uint32_t cap_off = mmio_readl(dev->dri_addr, ebase + CXL_DEVCAP_ENTRY_CAP_OFF);
                nk_vc_printf("  cap[%d]: id=0x%04x off=0x%x\n", i, cap_id, cap_off);
            }

            nk_vc_printf("  mbox_off=0x%x payload_size=%u\n",
                         dev->mbox_off, dev->mbox_payload_size);

            if (dev->mbox_off) {
                uint32_t caps   = mmio_readl(dev->dri_addr,
                                             dev->mbox_off + CXL_MBOX_CAPS);
                uint32_t ctrl   = mmio_readl(dev->dri_addr,
                                             dev->mbox_off + CXL_MBOX_CTRL);
                uint64_t cmd    = mmio_readq(dev->dri_addr,
                                             dev->mbox_off + CXL_MBOX_CMD);
                uint64_t status = mmio_readq(dev->dri_addr,
                                             dev->mbox_off + CXL_MBOX_STATUS);
                nk_vc_printf("  mbox caps=0x%08x ctrl=0x%08x\n"
                             "       cmd =0x%016llx status=0x%016llx\n"
                             "       doorbell=%s payload_sz=%u\n",
                             caps, ctrl, cmd, status,
                             (ctrl & CXL_MBOX_CTRL_DOORBELL) ? "SET(busy)" : "clear(idle)",
                             dev->mbox_payload_size);
            }
        }
        if (!count)
            nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl ts get", 10)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            uint64_t ts;
            if (!cxl_timestamp_get(dev, &ts))
                nk_vc_printf("[%02x:%02x.%x] timestamp=0x%016llx\n",
                             dev->bus, dev->slot, dev->fun, ts);
            else
                nk_vc_printf("[%02x:%02x.%x] TIMESTAMP_GET failed\n",
                             dev->bus, dev->slot, dev->fun);
            count++;
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl ts set ", 11)) {
        uint64_t ts = 0;
        if (sscanf(buf + 11, "%llu", &ts) != 1) {
            nk_vc_printf("Usage: cxl ts set <nanoseconds>\n");
            return 0;
        }
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            if (!cxl_timestamp_set(dev, ts))
                nk_vc_printf("[%02x:%02x.%x] timestamp set ok\n",
                             dev->bus, dev->slot, dev->fun);
            else
                nk_vc_printf("[%02x:%02x.%x] TIMESTAMP_SET failed\n",
                             dev->bus, dev->slot, dev->fun);
            count++;
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl fwinfo", 10)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            struct cxl_fw_info_payload fw;
            count++;
            int rc = cxl_fw_info(dev, &fw);
            if (rc == 1) {
                nk_vc_printf("[%02x:%02x.%x] FW_INFO: unavailable (QEMU cxl-type3 has no firmware slots configured)\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            if (rc) {
                nk_vc_printf("[%02x:%02x.%x] FW_INFO failed\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            nk_vc_printf("[%02x:%02x.%x] fw_slots=%u slot_info=0x%02x act_caps=0x%02x\n",
                         dev->bus, dev->slot, dev->fun,
                         fw.fw_slots, fw.fw_slot_info, fw.activation_caps);
            /* print non-empty slot revisions */
            uint8_t *slots[4] = { fw.slot1_fw_rev, fw.slot2_fw_rev,
                                   fw.slot3_fw_rev, fw.slot4_fw_rev };
            for (int s = 0; s < 4; s++) {
                if (slots[s][0]) {
                    char tmp[17]; memcpy(tmp, slots[s], 16); tmp[16] = '\0';
                    nk_vc_printf("  slot%d: \"%s\"\n", s+1, tmp);
                }
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl logs", 8)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            struct cxl_get_supported_logs_out sl;
            count++;
            if (cxl_get_supported_logs(dev, &sl)) {
                nk_vc_printf("[%02x:%02x.%x] GET_SUPPORTED_LOGS failed\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            nk_vc_printf("[%02x:%02x.%x] %u log(s)\n",
                         dev->bus, dev->slot, dev->fun, sl.count);
            int n = sl.count < 4 ? sl.count : 4;
            for (int i = 0; i < n; i++) {
                nk_vc_printf("  [%d] uuid=%02x%02x...%02x%02x size=%u\n", i,
                             sl.entries[i].uuid[0], sl.entries[i].uuid[1],
                             sl.entries[i].uuid[14], sl.entries[i].uuid[15],
                             sl.entries[i].size);
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    /* cxl events [0-3]   (0=info,1=warn,2=fail,3=fatal) */
    if (!strncmp(buf, "cxl events", 10)) {
        uint8_t log_type = 0;
        sscanf(buf + 10, " %hhu", &log_type);
        const char *names[] = { "Informational", "Warning", "Failure", "Fatal" };
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            struct cxl_get_evt_out hdr;
            struct cxl_event_record recs[16];
            int cnt = 0;
            count++;
            if (cxl_get_evt_records(dev, log_type, &hdr, recs, 16, &cnt)) {
                nk_vc_printf("[%02x:%02x.%x] GET_EVT_RECORDS failed\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            nk_vc_printf("[%02x:%02x.%x] %s events: count=%d overflow_errs=%u\n",
                         dev->bus, dev->slot, dev->fun,
                         log_type < 4 ? names[log_type] : "?",
                         cnt, hdr.overflow_err_count);
            for (int i = 0; i < cnt; i++) {
                nk_vc_printf("  [%d] handle=0x%016llx ts=0x%016llx flags=0x%02x\n",
                             i, recs[i].handle, recs[i].timestamp, recs[i].flags);
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl partition", 13)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            struct cxl_partition_info_payload pi;
            count++;
            if (cxl_get_partition_info(dev, &pi)) {
                nk_vc_printf("[%02x:%02x.%x] GET_PARTITION_INFO failed\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            nk_vc_printf("[%02x:%02x.%x] active: volatile=%llu persistent=%llu\n"
                         "             next:   volatile=%llu persistent=%llu\n"
                         "             (units: 256MB)\n",
                         dev->bus, dev->slot, dev->fun,
                         pi.active_volatile_cap, pi.active_persistent_cap,
                         pi.next_volatile_cap, pi.next_persistent_cap);
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl lsa get", 11)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;
            if (!dev->lsa_size) {
                nk_vc_printf("[%02x:%02x.%x] lsa_size=0 (run cxl identify first)\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            uint32_t sz = dev->lsa_size < 256 ? dev->lsa_size : 256;
            uint8_t  lsa[256];
            memset(lsa, 0, sizeof(lsa));
            if (cxl_get_lsa(dev, 0, lsa, sz)) {
                nk_vc_printf("[%02x:%02x.%x] GET_LSA failed\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            nk_vc_printf("[%02x:%02x.%x] LSA (first %u bytes):\n",
                         dev->bus, dev->slot, dev->fun, sz);
            for (uint32_t i = 0; i < sz; i++) {
                if (i % 16 == 0) nk_vc_printf("  %04x:", i);
                nk_vc_printf(" %02x", lsa[i]);
                if (i % 16 == 15 || i == sz-1) nk_vc_printf("\n");
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    /* cxl lsa set <hex-string>  — sets LSA bytes at offset 0 */
    if (!strncmp(buf, "cxl lsa set ", 12)) {
        const char *hex = buf + 12;
        uint8_t data[256];
        uint32_t len = 0;
        while (len < 256) {
            char hi = hex[0], lo = hex[1];
            if (!hi || !lo) break;
            int h = (hi>='0'&&hi<='9') ? hi-'0' : (hi>='a'&&hi<='f') ? hi-'a'+10 : (hi>='A'&&hi<='F') ? hi-'A'+10 : -1;
            int l = (lo>='0'&&lo<='9') ? lo-'0' : (lo>='a'&&lo<='f') ? lo-'a'+10 : (lo>='A'&&lo<='F') ? lo-'A'+10 : -1;
            if (h < 0 || l < 0) break;
            data[len++] = (uint8_t)((h << 4) | l);
            hex += 2;
            if (*hex == ' ') hex++;
        }
        if (!len) {
            nk_vc_printf("Usage: cxl lsa set <hexbytes>\n");
            return 0;
        }
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            if (!cxl_set_lsa(dev, 0, data, len))
                nk_vc_printf("[%02x:%02x.%x] SET_LSA ok (%u bytes)\n",
                             dev->bus, dev->slot, dev->fun, len);
            else
                nk_vc_printf("[%02x:%02x.%x] SET_LSA failed\n",
                             dev->bus, dev->slot, dev->fun);
            count++;
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl poison get", 14)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            struct cxl_get_poison_out hdr;
            struct cxl_poison_record recs[16];
            int cnt = 0;
            count++;
            if (cxl_get_poison_list(dev, 0, 0xffffffffffffffff,
                                    &hdr, recs, 16, &cnt)) {
                nk_vc_printf("[%02x:%02x.%x] GET_POISON_LIST failed\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            nk_vc_printf("[%02x:%02x.%x] %d poison record(s) flags=0x%02x\n",
                         dev->bus, dev->slot, dev->fun, cnt, hdr.flags);
            for (int i = 0; i < cnt; i++) {
                nk_vc_printf("  [%d] dpa=0x%016llx source=0x%02x len=%u*64B\n",
                             i, recs[i].address & ~0x3fULL,
                             recs[i].source & 0x7,
                             (uint32_t)(recs[i].address & 0x3f));
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl poison inject ", 18)) {
        uint64_t addr = 0;
        if (sscanf(buf + 18, "%llx", &addr) != 1) {
            nk_vc_printf("Usage: cxl poison inject <hex-addr>\n");
            return 0;
        }
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            if (!cxl_inject_poison(dev, addr))
                nk_vc_printf("[%02x:%02x.%x] INJECT_POISON ok addr=0x%llx\n",
                             dev->bus, dev->slot, dev->fun, addr);
            else
                nk_vc_printf("[%02x:%02x.%x] INJECT_POISON failed\n",
                             dev->bus, dev->slot, dev->fun);
            count++;
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl poison clear ", 17)) {
        uint64_t addr = 0;
        if (sscanf(buf + 17, "%llx", &addr) != 1) {
            nk_vc_printf("Usage: cxl poison clear <hex-addr>\n");
            return 0;
        }
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            if (!cxl_clear_poison(dev, addr))
                nk_vc_printf("[%02x:%02x.%x] CLEAR_POISON ok addr=0x%llx\n",
                             dev->bus, dev->slot, dev->fun, addr);
            else
                nk_vc_printf("[%02x:%02x.%x] CLEAR_POISON failed\n",
                             dev->bus, dev->slot, dev->fun);
            count++;
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl sanitize", 12)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;
            nk_vc_printf("[%02x:%02x.%x] starting SANITIZE OVERWRITE...\n",
                         dev->bus, dev->slot, dev->fun);
            if (!cxl_sanitize_overwrite(dev))
                nk_vc_printf("[%02x:%02x.%x] sanitize ok\n",
                             dev->bus, dev->slot, dev->fun);
            else
                nk_vc_printf("[%02x:%02x.%x] sanitize failed\n",
                             dev->bus, dev->slot, dev->fun);
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl hdm program", 15)) {
        uint64_t hpa_base = cedt_fmw_base ? cedt_fmw_base : CXL_HDM_DEFAULT_HPA_BASE;
        if (buf[15] == ' ')
            sscanf(buf + 16, "%llx", &hpa_base);
        cxl_program_all_hdm(hpa_base);
        list_for_each(cur, &dev_list) { count++; }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl cedt", 8)) {
        if (cedt_fmw_base)
            nk_vc_printf("CXL FMW: base=0x%016llx size=0x%016llx\n",
                         cedt_fmw_base, cedt_fmw_size);
        else
            nk_vc_printf("No CXL FMW found in CEDT (or CEDT not present)\n");
        return 0;
    }

    if (!strncmp(buf, "cxl numa", 8)) {
        if (!cxl_numa_dom) {
            nk_vc_printf("CXL NUMA domain not created (run cxl hdm program first)\n");
        } else {
            nk_vc_printf("CXL NUMA domain %u: %u region(s) %lluMB\n",
                         cxl_numa_dom->id, cxl_numa_dom->num_regions,
                         cxl_numa_dom->addr_space_size >> 20);
            struct mem_region *mr;
            list_for_each_entry(mr, &cxl_numa_dom->regions, entry) {
                nk_vc_printf("  base=0x%016llx len=%lluMB domain=%u\n",
                             mr->base_addr, mr->len >> 20, mr->domain_id);
            }
            struct domain_adj_entry *ent;
            nk_vc_printf("  adj_list (DRAM domains):");
            list_for_each_entry(ent, &cxl_numa_dom->adj_list, list_ent)
                nk_vc_printf(" %u", ent->domain->id);
            nk_vc_printf("\n");
        }
        return 0;
    }

    if (!strncmp(buf, "cxl hdm", 7)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;
            nk_vc_printf("[%02x:%02x.%x] HDM Decoders (bar0=0x%llx):\n",
                         dev->bus, dev->slot, dev->fun, dev->bar0_addr);
            cxl_dump_hdm(dev);
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl security", 12)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            uint32_t state;
            count++;
            int rc = cxl_get_security_state(dev, &state);
            if (!rc)
                nk_vc_printf("[%02x:%02x.%x] security_state=0x%08x\n",
                             dev->bus, dev->slot, dev->fun, state);
            else if (rc == 1)
                nk_vc_printf("[%02x:%02x.%x] GET_SECURITY_STATE: unsupported\n",
                             dev->bus, dev->slot, dev->fun);
            else
                nk_vc_printf("[%02x:%02x.%x] GET_SECURITY_STATE failed\n",
                             dev->bus, dev->slot, dev->fun);
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl mem test", 12)) {
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            count++;
            if (!dev->kmem_region) {
                nk_vc_printf("[%02x:%02x.%x] no memory registered (run cxl hdm program first)\n",
                             dev->bus, dev->slot, dev->fun);
                continue;
            }
            uint64_t base = dev->kmem_region->base_addr;
            volatile uint32_t *p = (volatile uint32_t *)base;
            for (uint32_t i = 0; i < 1024; i++) p[i] = 0xCEC50000u ^ i;
            int ok = 1;
            uint32_t fail_idx = 0, fail_got = 0, fail_exp = 0;
            for (uint32_t i = 0; i < 1024; i++) {
                uint32_t got = p[i];
                if (got != (0xCEC50000u ^ i)) {
                    ok = 0; fail_idx = i; fail_got = got;
                    fail_exp = 0xCEC50000u ^ i; break;
                }
            }
            if (ok) {
                nk_vc_printf("[%02x:%02x.%x] direct r/w 4KB at 0x%016llx: OK\n",
                             dev->bus, dev->slot, dev->fun, base);
            } else {
                nk_vc_printf("[%02x:%02x.%x] direct r/w 4KB at 0x%016llx: FAIL"
                             " (idx=%u expected=0x%08x got=0x%08x)\n",
                             dev->bus, dev->slot, dev->fun, base,
                             fail_idx, fail_exp, fail_got);
            }
        }
        if (!count) nk_vc_printf("No CXL devices\n");
        return 0;
    }

    if (!strncmp(buf, "cxl mem alloc", 13)) {
        void *ptr = malloc(1 << 20);
        if (!ptr) {
            nk_vc_printf("malloc(1MB) failed\n");
            return 0;
        }
        struct mem_region *r = kmem_get_region_by_addr((ulong_t)ptr);
        int from_cxl = 0;
        list_for_each(cur, &dev_list) {
            struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
            if (dev->kmem_region && dev->kmem_region == r) { from_cxl = 1; break; }
        }
        nk_vc_printf("malloc(1MB) -> %p  region_base=0x%llx  %s\n",
                     ptr, r ? (unsigned long long)r->base_addr : 0ULL,
                     from_cxl ? "FROM CXL" : "not from CXL");
        if (from_cxl) {
            volatile uint32_t *q = ptr;
            uint32_t n = (1 << 20) / 4;
            for (uint32_t i = 0; i < n; i++) q[i] = 0xA110C000u ^ i;
            int ok = 1;
            for (uint32_t i = 0; i < n; i++)
                if (q[i] != (0xA110C000u ^ i)) { ok = 0; break; }
            nk_vc_printf("  1MB pattern r/w: %s\n", ok ? "OK" : "FAIL");
        }
        free(ptr);
        return 0;
    }

    if (!strncmp(buf, "cxl mem stress", 14)) {
        /* Allocate 1MB chunks until the allocator falls back to CXL */
#define STRESS_MAX 4096
        void **ptrs = kmem_malloc(STRESS_MAX * sizeof(void *));
        if (!ptrs) {
            nk_vc_printf("failed to allocate pointer table\n");
            return 0;
        }
        memset(ptrs, 0, STRESS_MAX * sizeof(void *));
        int n = 0, first_cxl = -1;
        nk_vc_printf("allocating 1MB chunks until CXL fallback (max %d)...\n", STRESS_MAX);
        for (n = 0; n < STRESS_MAX; n++) {
            ptrs[n] = malloc(1 << 20);
            if (!ptrs[n]) {
                nk_vc_printf("OOM at allocation %d\n", n);
                break;
            }
            struct mem_region *r = kmem_get_region_by_addr((ulong_t)ptrs[n]);
            int from_cxl = 0;
            list_for_each(cur, &dev_list) {
                struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
                if (dev->kmem_region && dev->kmem_region == r) { from_cxl = 1; break; }
            }
            if (from_cxl) { first_cxl = n; n++; break; }
        }
        if (first_cxl < 0)
            nk_vc_printf("no CXL fallback in %d allocations (%dMB) — DRAM not exhausted or no CXL registered\n",
                         n, n);
        else
            nk_vc_printf("DRAM exhausted after %d x 1MB (%dMB), first CXL ptr=%p: OK\n",
                         first_cxl, first_cxl, ptrs[first_cxl]);
        for (int i = 0; i < n; i++) { if (ptrs[i]) { kmem_free(ptrs[i]); } }
        kmem_free(ptrs);
        return 0;
    }

    if (!strncmp(buf, "cxl mem isolate", 15)) {
        /* Verify that CXL alloc/free does not corrupt DRAM allocations */
#define ISOLATE_MAX 4096
        void **ptrs = kmem_malloc(ISOLATE_MAX * sizeof(void *));
        if (!ptrs) {
            nk_vc_printf("failed to allocate pointer table\n");
            return 0;
        }
        memset(ptrs, 0, ISOLATE_MAX * sizeof(void *));
        int n = 0, first_cxl = -1;
        void *cxl_ptr = NULL;

        nk_vc_printf("phase 1: exhausting DRAM to obtain a CXL allocation...\n");
        for (n = 0; n < ISOLATE_MAX; n++) {
            ptrs[n] = malloc(1 << 20);
            if (!ptrs[n]) { nk_vc_printf("  OOM at %d\n", n); break; }
            struct mem_region *r = kmem_get_region_by_addr((ulong_t)ptrs[n]);
            int from_cxl = 0;
            list_for_each(cur, &dev_list) {
                struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
                if (dev->kmem_region && dev->kmem_region == r) { from_cxl = 1; break; }
            }
            if (from_cxl) { first_cxl = n; cxl_ptr = ptrs[n]; n++; break; }
        }
        if (first_cxl < 0) {
            nk_vc_printf("  could not obtain CXL allocation — test skipped\n");
            for (int i = 0; i < n; i++) { if (ptrs[i]) { kmem_free(ptrs[i]); } }
            kmem_free(ptrs);
            return 0;
        }
        nk_vc_printf("  CXL block at %p after %d DRAM allocations\n", cxl_ptr, first_cxl);

        nk_vc_printf("phase 2: writing pattern to CXL block...\n");
        volatile uint32_t *q = cxl_ptr;
        uint32_t nw = (1 << 20) / 4;
        for (uint32_t i = 0; i < nw; i++) q[i] = 0xC4C10000u ^ i;

        nk_vc_printf("phase 3: freeing all blocks (%d DRAM + 1 CXL)...\n", first_cxl);
        for (int i = 0; i < n; i++) { if (ptrs[i]) { kmem_free(ptrs[i]); ptrs[i] = NULL; } }

        nk_vc_printf("phase 4: re-allocating 16 x 1MB, checking for CXL bleed and r/w...\n");
        int iso_ok = 1;
        int m = 0;
        for (m = 0; m < 16; m++) {
            ptrs[m] = malloc(1 << 20);
            if (!ptrs[m]) { nk_vc_printf("  OOM at re-alloc %d\n", m); iso_ok = 0; break; }
            struct mem_region *r = kmem_get_region_by_addr((ulong_t)ptrs[m]);
            int from_cxl = 0;
            list_for_each(cur, &dev_list) {
                struct cxl_dev *dev = list_entry(cur, struct cxl_dev, dev_node);
                if (dev->kmem_region && dev->kmem_region == r) { from_cxl = 1; break; }
            }
            if (from_cxl) {
                nk_vc_printf("  re-alloc[%d]=%p: unexpected CXL address\n", m, ptrs[m]);
                iso_ok = 0;
            }
            volatile uint32_t *p2 = ptrs[m];
            for (uint32_t j = 0; j < nw; j++) p2[j] = 0xD4A20000u ^ j;
            int rw_ok = 1;
            for (uint32_t j = 0; j < nw; j++)
                if (p2[j] != (0xD4A20000u ^ j)) { rw_ok = 0; break; }
            if (!rw_ok) {
                nk_vc_printf("  re-alloc[%d]=%p: r/w pattern FAIL\n", m, ptrs[m]);
                iso_ok = 0;
            }
        }
        nk_vc_printf("result: %s\n",
                     iso_ok ? "OK — DRAM allocations clean after CXL free"
                            : "FAIL — see errors above");
        for (int i = 0; i < m; i++) { if (ptrs[i]) { kmem_free(ptrs[i]); } }
        kmem_free(ptrs);
        return 0;
    }

    nk_vc_printf("Usage:\n");
    nk_vc_printf("  cxl l                    list devices\n");
    nk_vc_printf("  cxl identify             run IDENTIFY on all devices\n");
    nk_vc_printf("  cxl dvsec                dump PCIe extended capability chain\n");
    nk_vc_printf("  cxl diag                 dump mailbox registers\n");
    nk_vc_printf("  cxl ts get               get timestamp\n");
    nk_vc_printf("  cxl ts set <ns>          set timestamp (nanoseconds)\n");
    nk_vc_printf("  cxl fwinfo               firmware update info\n");
    nk_vc_printf("  cxl logs                 list supported logs\n");
    nk_vc_printf("  cxl events [0-3]         get event records (0=info 1=warn 2=fail 3=fatal)\n");
    nk_vc_printf("  cxl partition            partition info\n");
    nk_vc_printf("  cxl lsa get              read LSA\n");
    nk_vc_printf("  cxl lsa set <hexbytes>   write LSA\n");
    nk_vc_printf("  cxl poison get           list poison records\n");
    nk_vc_printf("  cxl poison inject <addr> inject poison at hex address\n");
    nk_vc_printf("  cxl poison clear <addr>  clear poison at hex address\n");
    nk_vc_printf("  cxl sanitize             sanitize overwrite (background op)\n");
    nk_vc_printf("  cxl security             get security state\n");
    nk_vc_printf("  cxl cedt                 show CXL FMW base from ACPI CEDT\n");
    nk_vc_printf("  cxl numa                 show CXL NUMA domain info\n");
    nk_vc_printf("  cxl hdm                  dump HDM decoder state\n");
    nk_vc_printf("  cxl hdm program [<base>] program decoder[0] on each device\n");
    nk_vc_printf("                           (default: CEDT FMW base or 0x100000000)\n");
    nk_vc_printf("  cxl mem test             direct r/w pattern test on registered CXL memory\n");
    nk_vc_printf("  cxl mem alloc            malloc 1MB and verify it comes from CXL memory\n");
    nk_vc_printf("  cxl mem stress           alloc 1MB chunks until CXL fallback (DRAM pressure test)\n");
    nk_vc_printf("  cxl mem isolate          alloc/free CXL memory and verify DRAM stays clean\n");
    nk_vc_printf("\n");
    return 0;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

uint32_t cxl_ecam_readl(uint8_t bus, uint8_t slot, uint8_t fun, uint32_t offset)
{
    return ecam_readl(bus, slot, fun, offset);
}

uint32_t cxl_find_ext_cap(uint8_t bus, uint8_t slot, uint8_t fun, uint16_t cap_id)
{
    uint32_t off = PCIE_EXT_CAP_OFFSET;
    while (off && off < 0x1000) {
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
