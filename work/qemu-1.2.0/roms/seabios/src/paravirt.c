// Paravirtualization support.
//
// Copyright (C) 2009 Red Hat Inc.
//
// Authors:
//  Gleb Natapov <gnatapov@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "config.h" // CONFIG_COREBOOT
#include "util.h" // ntoh[ls]
#include "ioport.h" // outw
#include "paravirt.h" // qemu_cfg_port_probe
#include "smbios.h" // struct smbios_structure_header

int qemu_cfg_present;

static void
qemu_cfg_select(u16 f)
{
    outw(f, PORT_QEMU_CFG_CTL);
}

static void
qemu_cfg_read(u8 *buf, int len)
{
    insb(PORT_QEMU_CFG_DATA, buf, len);
}

static void
qemu_cfg_skip(int len)
{
    while (len--)
        inb(PORT_QEMU_CFG_DATA);
}

static void
qemu_cfg_read_entry(void *buf, int e, int len)
{
    qemu_cfg_select(e);
    qemu_cfg_read(buf, len);
}

void qemu_cfg_port_probe(void)
{
    char *sig = "QEMU";
    int i;

    if (CONFIG_COREBOOT)
        return;

    qemu_cfg_present = 1;

    qemu_cfg_select(QEMU_CFG_SIGNATURE);

    for (i = 0; i < 4; i++)
        if (inb(PORT_QEMU_CFG_DATA) != sig[i]) {
            qemu_cfg_present = 0;
            break;
        }
    dprintf(4, "qemu_cfg_present=%d\n", qemu_cfg_present);
}

void qemu_cfg_get_uuid(u8 *uuid)
{
    if (!qemu_cfg_present)
        return;

    qemu_cfg_read_entry(uuid, QEMU_CFG_UUID, 16);
}

int qemu_cfg_show_boot_menu(void)
{
    u16 v;
    if (!qemu_cfg_present)
        return 1;

    qemu_cfg_read_entry(&v, QEMU_CFG_BOOT_MENU, sizeof(v));

    return v;
}

int qemu_cfg_irq0_override(void)
{
    u8 v;

    if (!qemu_cfg_present)
        return 0;

    qemu_cfg_read_entry(&v, QEMU_CFG_IRQ0_OVERRIDE, sizeof(v));

    return v;
}

u16 qemu_cfg_acpi_additional_tables(void)
{
    u16 cnt;

    if (!qemu_cfg_present)
        return 0;

    qemu_cfg_read_entry(&cnt, QEMU_CFG_ACPI_TABLES, sizeof(cnt));

    return cnt;
}

u16 qemu_cfg_next_acpi_table_len(void)
{
    u16 len;

    qemu_cfg_read((u8*)&len, sizeof(len));

    return len;
}

void* qemu_cfg_next_acpi_table_load(void *addr, u16 len)
{
    qemu_cfg_read(addr, len);
    return addr;
}

u16 qemu_cfg_smbios_entries(void)
{
    u16 cnt;

    if (!qemu_cfg_present)
        return 0;

    qemu_cfg_read_entry(&cnt, QEMU_CFG_SMBIOS_ENTRIES, sizeof(cnt));

    return cnt;
}

u32 qemu_cfg_e820_entries(void)
{
    u32 cnt;

    if (!qemu_cfg_present)
        return 0;

    qemu_cfg_read_entry(&cnt, QEMU_CFG_E820_TABLE, sizeof(cnt));
    return cnt;
}

void* qemu_cfg_e820_load_next(void *addr)
{
    qemu_cfg_read(addr, sizeof(struct e820_reservation));
    return addr;
}

struct smbios_header {
    u16 length;
    u8 type;
} PACKED;

struct smbios_field {
    struct smbios_header header;
    u8 type;
    u16 offset;
    u8 data[];
} PACKED;

struct smbios_table {
    struct smbios_header header;
    u8 data[];
} PACKED;

#define SMBIOS_FIELD_ENTRY 0
#define SMBIOS_TABLE_ENTRY 1

size_t qemu_cfg_smbios_load_field(int type, size_t offset, void *addr)
{
    int i;

    for (i = qemu_cfg_smbios_entries(); i > 0; i--) {
        struct smbios_field field;

        qemu_cfg_read((u8 *)&field, sizeof(struct smbios_header));
        field.header.length -= sizeof(struct smbios_header);

        if (field.header.type != SMBIOS_FIELD_ENTRY) {
            qemu_cfg_skip(field.header.length);
            continue;
        }

        qemu_cfg_read((u8 *)&field.type,
                      sizeof(field) - sizeof(struct smbios_header));
        field.header.length -= sizeof(field) - sizeof(struct smbios_header);

        if (field.type != type || field.offset != offset) {
            qemu_cfg_skip(field.header.length);
            continue;
        }

        qemu_cfg_read(addr, field.header.length);
        return (size_t)field.header.length;
    }
    return 0;
}

int qemu_cfg_smbios_load_external(int type, char **p, unsigned *nr_structs,
                                  unsigned *max_struct_size, char *end)
{
    static u64 used_bitmap[4] = { 0 };
    char *start = *p;
    int i;

    /* Check if we've already reported these tables */
    if (used_bitmap[(type >> 6) & 0x3] & (1ULL << (type & 0x3f)))
        return 1;

    /* Don't introduce spurious end markers */
    if (type == 127)
        return 0;

    for (i = qemu_cfg_smbios_entries(); i > 0; i--) {
        struct smbios_table table;
        struct smbios_structure_header *header = (void *)*p;
        int string;

        qemu_cfg_read((u8 *)&table, sizeof(struct smbios_header));
        table.header.length -= sizeof(struct smbios_header);

        if (table.header.type != SMBIOS_TABLE_ENTRY) {
            qemu_cfg_skip(table.header.length);
            continue;
        }

        if (end - *p < sizeof(struct smbios_structure_header)) {
            warn_noalloc();
            break;
        }

        qemu_cfg_read((u8 *)*p, sizeof(struct smbios_structure_header));
        table.header.length -= sizeof(struct smbios_structure_header);

        if (header->type != type) {
            qemu_cfg_skip(table.header.length);
            continue;
        }

        *p += sizeof(struct smbios_structure_header);

        /* Entries end with a double NULL char, if there's a string at
         * the end (length is greater than formatted length), the string
         * terminator provides the first NULL. */
        string = header->length < table.header.length +
                 sizeof(struct smbios_structure_header);

        /* Read the rest and terminate the entry */
        if (end - *p < table.header.length) {
            warn_noalloc();
            *p -= sizeof(struct smbios_structure_header);
            continue;
        }
        qemu_cfg_read((u8 *)*p, table.header.length);
        *p += table.header.length;
        *((u8*)*p) = 0;
        (*p)++;
        if (!string) {
            *((u8*)*p) = 0;
            (*p)++;
        }

        (*nr_structs)++;
        if (*p - (char *)header > *max_struct_size)
            *max_struct_size = *p - (char *)header;
    }

    if (start != *p) {
        /* Mark that we've reported on this type */
        used_bitmap[(type >> 6) & 0x3] |= (1ULL << (type & 0x3f));
        return 1;
    }

    return 0;
}

int qemu_cfg_get_numa_nodes(void)
{
    u64 cnt;

    qemu_cfg_read_entry(&cnt, QEMU_CFG_NUMA, sizeof(cnt));

    return (int)cnt;
}

void qemu_cfg_get_numa_data(u64 *data, int n)
{
    int i;

    for (i = 0; i < n; i++)
        qemu_cfg_read((u8*)(data + i), sizeof(u64));
}

u16 qemu_cfg_get_max_cpus(void)
{
    u16 cnt;

    if (!qemu_cfg_present)
        return 0;

    qemu_cfg_read_entry(&cnt, QEMU_CFG_MAX_CPUS, sizeof(cnt));

    return cnt;
}

int qemu_cfg_read_file(struct romfile_s *file, void *dst, u32 maxlen)
{
    if (file->size > maxlen)
        return -1;
    qemu_cfg_read_entry(dst, file->id, file->size);
    return file->size;
}

struct QemuCfgFile {
    u32  size;        /* file size */
    u16  select;      /* write this to 0x510 to read it */
    u16  reserved;
    char name[56];
};

void qemu_cfg_romfile_setup(void)
{
    if (CONFIG_COREBOOT || !qemu_cfg_present)
        return;

    u32 count;
    qemu_cfg_read_entry(&count, QEMU_CFG_FILE_DIR, sizeof(count));
    count = ntohl(count);
    u32 e;
    for (e = 0; e < count; e++) {
        struct QemuCfgFile qfile;
        qemu_cfg_read((void*)&qfile, sizeof(qfile));
        struct romfile_s *file = malloc_tmp(sizeof(*file));
        if (!file) {
            warn_noalloc();
            return;
        }
        memset(file, 0, sizeof(*file));
        strtcpy(file->name, qfile.name, sizeof(file->name));
        file->size = ntohl(qfile.size);
        file->id = ntohs(qfile.select);
        file->copy = qemu_cfg_read_file;
        romfile_add(file);
        dprintf(3, "Found fw_cfg file: %s (size=%d)\n", file->name, file->size);
    }
}
