// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024
 *
 *
 */

#include <common.h>
#include <command.h>
#include <dm.h>
#include <button.h>
#include <dm/uclass-internal.h>
#include <env.h>
#include <linux/delay.h>
#include <gzip.h>
#include <mapmem.h>
#include <u-boot/sha256.h>
#include <fat.h>
#include <vsprintf.h> 
#include "jsmn.h"
#include "tar.h"

typedef struct {
	char *module;
	int module_size;
	char *path;
	int path_size;
	char *sha256;
	int sha256_size;
} jcontent;

typedef struct {
	char module[100];
	unsigned long addr;
	int type;
} flash_layout;

enum {
	PART_INVALID,
	PART_RAW,
	PART_EXT4,
	PART_FAT
};

static flash_layout flash[16] = {
	{.module = "gpt",            .addr =           0, .type = PART_RAW},  // 0  gpt
	{.module = "bootloader.pri", .addr =    0x100000, .type = PART_RAW},  // 1
	{.module = "bootloader.bak", .addr =   0x8100000, .type = PART_RAW},  // 2
	{.module = "env.pri",        .addr =  0x10100000, .type = PART_RAW},  // 3
	{.module = "env.bak",        .addr =  0x10300000, .type = PART_RAW},  // 4
	{.module = "app.a",          .addr =  0x10500000, .type = PART_EXT4}, // 5  files: fit.itb
	{.module = "app.b",          .addr =  0x50500000, .type = PART_EXT4}, // 6  files: fit.itb
	{.module = "factory",        .addr =  0x90500000, .type = PART_EXT4}, // 7  files: factory.itb, u-boot-fip.bin, empty.ext4
	{.module = "update",         .addr =  0xD0500000, .type = PART_FAT},  // 8  files: fw_001.bin
	{.module = "config.pri",     .addr = 0x110500000, .type = PART_EXT4}, // 9  mount bind to /etc TODO migrate to file
	{.module = "config.bak",     .addr = 0x150500000, .type = PART_EXT4}, // 10 mount bind to /etc
	{.module = "",               .addr = -1,          .type = PART_INVALID}
};

#define FACTORY_PARTITION 7
#define FACTORY_IMAGE_NAME "/factory.img.gz"
#define UPDATE_PARTITION 8

static char cmd[512];

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

static void toupper(void *str)
{
	char *s = str;
	while (*s != '\0') {
		if( *s >= 'a' && *s <= 'z')
			*s = *s - ('a' - 'A');
		s++;
	}
}

static int parse_json(char *data, int size, jcontent* jc)
{
    int i,j;
    jsmn_parser p;
	const int max_token_count = 128; /* We expect no more than 128 tokens */
    jsmntok_t t[max_token_count];
    int r;
    char *cp;
	int items = 0;

    jsmn_init(&p);
    r = jsmn_parse(&p, data, size, t,
                    sizeof(t) / sizeof(t[0]));
    if (r < 0) {
        printf("Failed to parse JSON: %d\n", r);
        return -1;
    }

	if (r > max_token_count) {
		printf("JSON token count (%d) more then the max value %d.\n", r, max_token_count);
        return -1;
	}

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        printf("Object expected\n");
        return -1;
    }

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++) {
        cp = data + t[i].start;
        if (*cp == '{') { // array element
			jc[items].module = data + t[i - 1].start;
			jc[items].module_size = t[i - 1].end - t[i - 1].start;

			printf("- module: %.*s\n", jc[items].module_size,
					jc[items].module);
			jc[items].module[jc[items].module_size]= 0;
            j = i + 1;
            if (jsoneq(data, &t[j], "path") == 0) {
				jc[items].path = data + t[j + 1].start;
				jc[items].path_size = t[j + 1].end - t[j + 1].start;
				printf("- path: %.*s\n", jc[items].path_size,
						jc[items].path);
				jc[items].path[jc[items].path_size]= 0;
            }
            j += 2;
            if (jsoneq(data, &t[j], "sha256") == 0) {
				jc[items].sha256 = data + t[j + 1].start;
				jc[items].sha256_size = t[j + 1].end - t[j + 1].start;
				printf("- sha256: %.*s\n", jc[items].sha256_size,
						jc[items].sha256);
				jc[items].sha256[jc[items].sha256_size]= 0;
				toupper(jc[items].sha256);
            }
			items++;
        }
    }
    return items;
}

static int untar(char *data, int size, tar_files *files)
{
    size_t spare_size, file_size, file_offset, tar_offset;
    int i = 0, j;
	tar_header *h;

    if (size > TARBLOCKSIZE) {
        tar_offset = 0;
        while (tar_offset < (size - TARBLOCKSIZE * 2)) {
            h = (tar_header *) (data + tar_offset);
            file_size = simple_strtol(h->size, NULL, 8);
            spare_size = (file_size + TARBLOCKSIZE - 1) & ~(TARBLOCKSIZE - 1);
            if (0 == file_size || 0 == strlen(h->name)) {
                break;
            }
			// Remove symbols ./ in front of the name.
			for (j = 0; j < strlen(h->name); j++) {
				if ( !(h->name[j] == '.' || h->name[j] == '/') )
					break;
			}
            file_offset = tar_offset + TARBLOCKSIZE;
            tar_offset += spare_size + TARBLOCKSIZE;
            strcpy(files[i].name, h->name + j);
            files[i].size = file_size;
            files[i].offset = file_offset;
            printf("name %s, size: %ld, spare_size %ld, flag %d\n", files[i].name,
					files[i].size, spare_size, (int)h->typeflag);
            i++;
        }
    } else {
        return -1; /* Tar file too small */
    }
    return i;
}

static void swap_curr_part(int indx)
{
	char mmc_new_char[4];
	printf("Swap redundancy partitions.\n");
	snprintf(mmc_new_char, sizeof(mmc_new_char), "%d", indx);
	env_set("mmc_cur", mmc_new_char);
	env_save();
	env_save();
}

static unsigned long get_file_size(void)
{
	const char *filesize_str = env_get("filesize");
	return hextoul(filesize_str, NULL);
}

static int update_from_file(char *filename, int mmc_new)
{
	int ret;
	unsigned long filesize, blkcount;
	unsigned long src, dst, dst_len, src_len, uncomp_size;
	char *uncomp_data;
	int files_count;
	tar_files files[MAX_FILES_IN_TAR];
	jcontent jc[MAX_FILES_IN_TAR];
	int j_items = 0;
	int i, j, ia, fi;
	sha256_context ctx;
	uint8_t digits[32];
	char crc_str[65];
	char *crc_p;
	int part_count;
	int dst_part[2];
	unsigned long file_addr;

	src = 0x63000000;
	snprintf(cmd, sizeof(cmd), "fatload mmc 0:%d 0x%lX /%s", UPDATE_PARTITION, src, filename);
	ret = run_command(cmd, 0);
	filesize = get_file_size();
	if ((0 == ret) && (filesize > 0)) {
		printf("Update is available.\n");
		dst = 0x6c000000;
		dst_len = 0x16000000;
		src_len = filesize;

		if (gunzip(uncomp_data = map_sysmem(dst, dst_len), dst_len, map_sysmem(src, src_len),
				&src_len) != 0) {
			return 1;
		}

		uncomp_size = src_len; // length of uncompressed data

		files_count = untar(uncomp_data, uncomp_size, files);

		if (files_count > 0) {
			for (fi = 0; fi < files_count; fi++) {
				if (!strcmp(files[fi].name, "meta.json")) {
					printf("Parse json 0x%lX 0x%lX.\n", (size_t)(uncomp_data + files[fi].offset), files[fi].size);
					j_items = parse_json(uncomp_data + files[fi].offset, files[fi].size, jc);
					break;
				}
			}
		}

		if (j_items > 0) {
			printf("Json read successfully.\n");
			// flash
			for (j = 0; j < j_items; j++) {
				// find file
				for (fi = 0; fi < files_count; fi++) {
					// printf("path: %s, name: %s\n", jc[j].path, files[fi].name);
					if (!strcmp(jc[j].path, files[fi].name))
						break;
				}
				if (fi < files_count) { // file found
					file_addr = (unsigned long)uncomp_data + files[fi].offset;
					// calculate crc
					sha256_starts(&ctx);
					sha256_update(&ctx, (const uint8_t *)file_addr, files[fi].size);
					sha256_finish(&ctx, digits);
					printf("Calculating CRC:\n");
					crc_p = crc_str;
					for (i = 0; i < 32; i++) {
						crc_p += sprintf(crc_p, "%2.2X", digits[i]);
					}
					printf("CRC:  %s\n", crc_str);
					printf("CRC1: %s\n", jc[j].sha256);
					if (!strcmp(jc[j].sha256, crc_str)) {
						printf("CRC ok\n");

						// Finding dst addr.
						ia = 0;
						part_count = 0;
						while (flash[ia].addr != (unsigned long)-1) {
							if (!strncmp(jc[j].module, flash[ia].module, strlen(jc[j].module))) {
								dst_part[part_count++] = ia;
							}
							ia++;
						}		
						if (part_count > 0) { // Addr found
							
							switch (flash[dst_part[0]].type)
							{
							case PART_RAW:
								printf("Update raw.\n");
								printf("flash file: %s, addr src 0x%lX, addr dst 0x%lX\n",
											jc[j].path, file_addr, flash[dst_part[0]].addr);
								blkcount = files[fi].size / 512 + 1;
								snprintf(cmd, sizeof(cmd), "mmc write 0x%lX 0x%lX 0x%lX",
										file_addr, flash[mmc_new].addr / 512, blkcount);
								printf("RUN: %s\n", cmd);
								ret = run_command(cmd, 0);
								break;
							case PART_EXT4:
								printf("Update ext4.\n");
								if (part_count == 2) {
									// Redundancy update.
									printf("flash file: %s, addr src 0x%lX, addr dst 0x%lX\n",
											jc[j].path, file_addr, flash[mmc_new].addr);
									snprintf(cmd, sizeof(cmd), "ext4write mmc 0:%d 0x%lX /fit.itb 0x%lX",
											mmc_new, file_addr, files[fi].size);
									printf("RUN: %s\n", cmd);
									ret = run_command(cmd, 0);
									if (0 == ret) {
										swap_curr_part(mmc_new);
									}
								} else {
									// write to addr.
									printf("flash file: %s, addr src 0x%lX, addr dst 0x%lX\n",
											jc[j].path, file_addr, flash[dst_part[0]].addr);
									snprintf(cmd, sizeof(cmd), "ext4write mmc 0:%d 0x%lX /fit.itb 0x%lX",
											dst_part[0], file_addr, files[fi].size);
									printf("RUN: %s\n", cmd);
									ret = run_command(cmd, 0);
								}
								break;
							case PART_FAT:
								printf("Update fat.\n");
								break;
							default:
								printf("Unknown part type.\n");
								break;
							}
						} else {
							printf("Destination not found\n");
							return -1;
						}
					} else {
						printf("CRC check fail\n");
						return -1;
					}
				} else {
					printf("File described in json not found\n");
					return -1;
				}
			}
			// Update done.
			return 0;
		} else {
			printf("Empty json.\n");
			return -1;
		}
	} else {
		printf("File load error.\n");
		return -1;
	}
}

int do_startp(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	int ret = 0;
	int i, min;
	char filename[100];
	const char *p, *pv, *mmc_curr;
	int max_wait = 10;
	int mmc_new, cfg_part;
	unsigned long src, dst;
	struct fs_dir_stream *dir;
	struct fs_dirent *dirent;

	mmc_curr = env_get("mmc_cur");
	if (*mmc_curr == '5') {
		mmc_new = 6;
		cfg_part = 10;
	} else {
		mmc_new = 5;
		cfg_part = 9;
	}

	pv = env_get("recvalue");

	for (i = 0; i < max_wait; i++) {
		snprintf(cmd, sizeof(cmd), "gpio read recbutton ${recgpio}");
		ret = run_command(cmd, 0);
		p = env_get("recgpio");
		if (*pv == *p) {
			printf("Button is pressed.\n");
		} else {
			printf("Button in not pressed.\n");
			break;
		}
		snprintf(cmd, sizeof(cmd), "gpio toggle 61");
		ret = run_command(cmd, 0);
		udelay(500);
		ret = run_command(cmd, 0);
		udelay(500);
	}
	// Checking if the button has been pressed.
	if (i == max_wait) {
		printf("Try factory restore\n");
		src = 0x63000000;
		dst = 0x67000000;
		snprintf(cmd, sizeof(cmd), "ext4load mmc 0:%d 0x%lX %s", FACTORY_PARTITION, src, FACTORY_IMAGE_NAME);
		ret = run_command(cmd, 0);
		if (0 == ret) {
			snprintf(cmd, sizeof(cmd), "unzip 0x%lX 0x%lX", src, dst);
			ret = run_command(cmd, 0);
			if (0 == ret) {
				snprintf(cmd, sizeof(cmd), "ext4write mmc 0:%d 0x%lX /fit.itb 0x%lX", mmc_new, dst, get_file_size());
				run_command(cmd, 0);
			}
		} else {
			printf("Factory image not found\n");
		}
	} else {
		printf("Try to update.\n");
		if (!fs_set_blk_dev("mmc", "0:8", FS_TYPE_FAT)) {
			fat_opendir("/", &dir);
			min = 0x7FFFFFFF;
			filename[0] = 0;
			while (!fat_readdir(dir, &dirent)) {
				printf("File name: %s.\n", dirent->name);
				p = strstr(dirent->name, "FW_");
				if ( p != NULL) {
					i = simple_strtol(p, NULL, 10);
					if (i < min) {
						strcpy(filename, dirent->name);
					}
				}
			}
			fat_closedir(dir);
			if (strlen(filename) > 0) {
				ret = update_from_file(filename, mmc_new);
				fat_unlink(filename);
				if (0 == ret) {
					snprintf(cmd, sizeof(cmd), "reset");
					ret = run_command(cmd, 0);
				}
			} else {
				printf("There is no valid update files.\n");
			}
		}
	}
	// Normal boot.
	src = 0x80000000;
	snprintf(cmd, sizeof(cmd), "ext4load mmc 0:%s 0x%lX /fit.itb", mmc_curr, src);
	ret = run_command(cmd, 0);
	if (0 == ret) {
		snprintf(cmd, sizeof(cmd), "bootm 0x%lX", src);
		ret = run_command(cmd, 0);
	} else {
		printf("File load failure.\n");
		swap_curr_part(mmc_new);
	}
	return ret;
}

U_BOOT_CMD(
	startp, 1, 0, do_startp,
	"startp",
	"startp to start proxeet boot"
);
