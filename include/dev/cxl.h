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
#ifndef __CXL_H__
#define __CXL_H__

#include <nautilus/nautilus.h>

/* Read a 32-bit dword from PCIe extended config space (offset >= 0x100) via ECAM */
uint32_t cxl_ecam_readl(uint8_t bus, uint8_t slot, uint8_t fun, uint32_t offset);

/* Find a PCIe extended capability by ID; returns config space offset or 0 */
uint32_t cxl_find_ext_cap(uint8_t bus, uint8_t slot, uint8_t fun, uint16_t cap_id);

/*
 * Find a CXL DVSEC (vendor 0x1E98) by DVSEC ID.
 * Pass CXL_DVSEC_ANY to match the first CXL DVSEC found regardless of ID.
 * Returns config space offset or 0. Writes matched ID into *out_id if non-NULL.
 */
#define CXL_DVSEC_ANY 0xffff
uint32_t cxl_find_dvsec(uint8_t bus, uint8_t slot, uint8_t fun,
                         uint16_t dvsec_id, uint16_t *out_id);

int cxl_init(struct naut_info *naut);
int cxl_deinit(void);

#endif
