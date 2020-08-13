
#ifndef __UPGRADE_PACKAGE_H
#define __UPGRADE_PACKAGE_H

#include "boot_types.h"

typedef struct
{
 
    uint8_t prefix[4];
    uint32_t version;
    uint32_t size;
    uint8_t reserved[4];
    uint8_t signature[128];
} boot_image_metadata_t;

typedef struct
{
    boot_image_metadata_t metadata;
    uint8_t image[1];
    /* TODO image here */
} boot_upgrade_package_t;

#endif
