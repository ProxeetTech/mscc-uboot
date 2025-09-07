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

enum {
	UPD_MODE_NONE,
	UPD_MODE_FILE,
	UPD_MODE_IMAGE
};

typedef struct {
	char *module;
	int module_size;
	char *path;
	int path_size;
	char *sha256;
	int sha256_size;
	int mode;
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
	{.module = "bootloader.pri", .addr =    0x100000, .type = PART_RAW},  // 1  fip.bin
	{.module = "bootloader.bak", .addr =   0x8100000, .type = PART_RAW},  // 2  fip.bin factory restore
	{.module = "env.pri",        .addr =  0x10100000, .type = PART_RAW},  // 3  environment
	{.module = "env.bak",        .addr =  0x10300000, .type = PART_RAW},  // 4  environment backup
	{.module = "app.a",          .addr =  0x10500000, .type = PART_EXT4}, // 5  files: fit.itb
	{.module = "app.b",          .addr =  0x50500000, .type = PART_EXT4}, // 6  files: fit.itb
	{.module = "factory",        .addr =  0x90500000, .type = PART_EXT4}, // 7  files: fit.itb,
																		  //           u-boot-fip.bin, u-boot-factory-fip.bin,
																		  //           empty_ext4.img.gz, empty_fat.img.gz
	{.module = "update",         .addr =  0xD0500000, .type = PART_FAT},  // 8  files: etc fw_001.bin
	{.module = "config.a",       .addr = 0x110500000, .type = PART_EXT4}, // 9  config.bin
	{.module = "config.b",       .addr = 0x150500000, .type = PART_EXT4}, // 10 config.bin
	{.module = "",               .addr = -1,          .type = PART_INVALID}
};

#define FACTORY_PARTITION 7
// #define FACTORY_IMAGE_NAME "/fit.itb.gz"
#define UPDATE_PARTITION 8
#define FACTORY_PARTITION_IMAGE_NAME "factory.img.gz"
#define MAX_FILE_SIZE 0x4000000

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
    char *mode_start;
    int mode_size;

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
            for (j = i + 1; j < r; j++) {
                if (jsoneq(data, &t[j], "update_mode") == 0) {
                    mode_start = data + t[j + 1].start;
                    mode_size = t[j + 1].end - t[j + 1].start;
                    mode_start[mode_size]= 0;
                    if (strncmp("file", mode_start, min(mode_size, 4)) == 0) {
                        jc[items].mode = UPD_MODE_FILE;
                    } else if (strncmp("image", mode_start, min(mode_size, 5)) == 0) {
                        jc[items].mode = UPD_MODE_IMAGE;
                    } else {
                        jc[items].mode = UPD_MODE_NONE;
                    }
                    printf("- update_mode %s(%d)\n", mode_start, jc[items].mode);
                    j += 1;
                }
                if (jsoneq(data, &t[j], "path") == 0) {
                    jc[items].path = data + t[j + 1].start;
                    jc[items].path_size = t[j + 1].end - t[j + 1].start;
                    printf("- path: %.*s\n", jc[items].path_size,
                            jc[items].path);
                    jc[items].path[jc[items].path_size]= 0;
                    j += 1;
                }
                if (jsoneq(data, &t[j], "sha256") == 0) {
                    jc[items].sha256 = data + t[j + 1].start;
                    jc[items].sha256_size = t[j + 1].end - t[j + 1].start;
                    printf("- sha256: %.*s\n", jc[items].sha256_size,
                            jc[items].sha256);
                    jc[items].sha256[jc[items].sha256_size]= 0;
                    toupper(jc[items].sha256);
                    j += 1;
                }
                cp = data + t[j].start;
                if (*cp == '{') {
                    break;
                }
            }
            printf("-----\n");
            items++;
        }
    }
    return items;
}

static int is_valid_octal(char *str, size_t len)
{
    for (size_t i = 0; i < len && str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '7') {
            if (str[i] != ' ' && str[i] != '\0') {
                return 0;
            }
        }
    }
    return 1;
}

static int untar(char *data, int size, tar_files *files)
{
    size_t spare_size, file_size, file_offset, tar_offset;
    int i = 0, j;
    tar_header *h;

    printf("untar size: %d\n", size);

    if (size > TARBLOCKSIZE) {
        tar_offset = 0;
        while (tar_offset < (size - TARBLOCKSIZE * 2)) {
            h = (tar_header *) (data + tar_offset);
            if (strncmp(h->magic, TMAGIC, TMAGLEN) != 0) {
                break;
            }
            if (!is_valid_octal(h->size, sizeof(h->size))) {
                printf("!is_valid_octal\n");
                break;
            }
            file_size = simple_strtol(h->size, NULL, 8);
            spare_size = (file_size + TARBLOCKSIZE - 1) & ~(TARBLOCKSIZE - 1);
            file_offset = tar_offset + TARBLOCKSIZE;
            tar_offset += spare_size + TARBLOCKSIZE;
            if (h->typeflag == '0') { // Regular file.
                if (0 == strlen(h->name))
                    break;
                // Remove symbols ./ in front of the name.
                for (j = 0; j < strlen(h->name); j++) {
                    if ( !(h->name[j] == '.' || h->name[j] == '/') )
                        break;
                }
                strcpy(files[i].name, h->name + j);
                files[i].size = file_size;
                files[i].offset = file_offset;
                printf("name %s, size: %ld, spare_size %ld, flag %d\n", files[i].name,
                        files[i].size, spare_size, (int)h->typeflag);
                i++;
            }
        }
    } else {
        printf("Tar file is too small.\n");
        return -1;
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

static unsigned long get_env_addr(const char* name)
{
	const char *str = env_get(name);
	return hextoul(str, NULL);
}

static tar_files files[MAX_FILES_IN_TAR];
static jcontent jc[MAX_FILES_IN_TAR];

static int flash_file(int json_index, int file_index, unsigned long file_addr, int part)
{
	printf("write file: %s, addr src 0x%lX, addr dst 0x%lX\n",
			jc[json_index].path, file_addr, flash[part].addr);
	snprintf(cmd, sizeof(cmd), "ext4write mmc 0:%d 0x%lX /%s 0x%lX",
			part, file_addr, jc[json_index].path, files[file_index].size);
	printf("RUN: %s\n", cmd);
	return run_command(cmd, 0);
}

static int flash_image(int json_index, int file_index, unsigned long file_addr, int part)
{
	unsigned long blkcount;
	printf("flash image: %s, addr src 0x%lX, addr dst 0x%lX\n",
				jc[json_index].path, file_addr, flash[part].addr);
	blkcount = files[file_index].size / 512 + 1;
	snprintf(cmd, sizeof(cmd), "mmc write 0x%lX 0x%lX 0x%lX",
			file_addr, flash[part].addr / 512, blkcount);
	printf("RUN: %s\n", cmd);
	return run_command(cmd, 0);
}

static int update_from_file(char *filename, int mmc_new)
{
	int ret;
	unsigned long filesize;
	unsigned long src, dst, dst_len, src_len, uncomp_size;
	char *uncomp_data;
	int files_count;
	int j_items = 0;
	int i, j, ia, fi;
	sha256_context ctx;
	uint8_t digits[32];
	char crc_str[65];
	char *crc_p;
	int part_count;
	int dst_part[2];
	unsigned long file_addr;

	src = get_env_addr("loadaddr");
	snprintf(cmd, sizeof(cmd), "fatload mmc 0:%d 0x%lX /%s", UPDATE_PARTITION, src, filename);
	ret = run_command(cmd, 0);
	filesize = get_file_size();
	// Unlink file immediately if there is a failure during the unzip process this will protect us from reboot loop.
	fat_unlink(filename);
	if ((0 == ret) && (filesize > 0)) {
		printf("Update is available.\n");
		dst = src + 0x7000000; // 112Mb for update
		dst_len = 0x16000000;
		src_len = filesize;

		if (gunzip(uncomp_data = map_sysmem(dst, dst_len), dst_len, map_sysmem(src, src_len),
				&src_len) != 0) {
			printf("Unable extract update file\n");
			return 1;
		}

		uncomp_size = src_len; // length of uncompressed data

		files_count = untar(uncomp_data, uncomp_size, files);

		printf("%d files in tar\n", files_count);

		if (files_count > 0) {
			for (fi = 0; fi < files_count; fi++) {
				if (!strcmp(files[fi].name, "meta.json")) {
					printf("Parse json 0x%lX 0x%lX.\n", (size_t)(uncomp_data + files[fi].offset), files[fi].size);
					j_items = parse_json(uncomp_data + files[fi].offset, files[fi].size, jc);
					break;
				}
			}
		} else {
			printf("Empty tar file.\n");
			return -1;
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
					printf("Calculating CRC %d 0x%lX 0x%lX\n", fi, file_addr, files[fi].size);
					sha256_starts(&ctx);
					sha256_update(&ctx, (const uint8_t *)file_addr, files[fi].size);
					sha256_finish(&ctx, digits);
					printf("CRC calculated:\n");
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
								printf("Update raw partition.\n");
								ret = flash_image(j, fi, file_addr, dst_part[0]);
								break;
							case PART_EXT4:
								printf("Update ext4 partition.\n");
								if (part_count == 2) {
									// Redundancy update.
									if ((UPD_MODE_FILE == jc[j].mode) || (UPD_MODE_NONE == jc[j].mode)) {
										ret = flash_file(j, fi, file_addr, mmc_new);
										if (0 == ret) {
											swap_curr_part(mmc_new);
										}
									} else if (UPD_MODE_IMAGE == jc[j].mode) {
										ret = flash_image(j, fi, file_addr, mmc_new);
										if (0 == ret) {
											swap_curr_part(mmc_new);
										}
									}
									// TODO copy config?
								} else {
									// Write to specific partition.
									ret = flash_file(j, fi, file_addr, dst_part[0]);
								}
								break;
							case PART_FAT:
								printf("Update fat partition.\n");
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
	//unsigned long src, dst;
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
		p = env_get("recbutton");
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
		snprintf(cmd, sizeof(cmd), "run factory_boot");
		ret = run_command(cmd, 0);
		return ret;
		// src = get_env_addr("loadaddr");
		// dst = src + MAX_FILE_SIZE;
		// snprintf(cmd, sizeof(cmd), "ext4load mmc 0:%d 0x%lX %s", FACTORY_PARTITION, src, FACTORY_IMAGE_NAME);
		// ret = run_command(cmd, 0);
		// if (0 == ret) {
		// 	snprintf(cmd, sizeof(cmd), "unzip 0x%lX 0x%lX", src, dst);
		// 	ret = run_command(cmd, 0);
		// 	if (0 == ret) {
		// 		snprintf(cmd, sizeof(cmd), "ext4write mmc 0:%d 0x%lX /fit.itb 0x%lX", mmc_new, dst, get_file_size());
		// 		ret = run_command(cmd, 0);
		// 		if (0 != ret) {
		// 			printf("restore fail, try startf - factory restore process\n");
		// 			return ret;
		// 		}
		// 	} else {
		// 		printf("unzip fail %s\n", FACTORY_IMAGE_NAME);
		// 	}
		// } else {
		// 	printf("Factory image not found\n");
		// }
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
				if (0 == ret) {
					snprintf(cmd, sizeof(cmd), "reset");
					ret = run_command(cmd, 0);
				}
			} else {
				printf("There is no valid update files.\n");
			}
		} else {

		}
	}
	// Normal boot.
	// src = get_env_addr("loadaddr");
	// snprintf(cmd, sizeof(cmd), "ext4load mmc 0:%s 0x%lX /fit.itb", mmc_curr, src);
	// ret = run_command(cmd, 0);
	// if (0 == ret) {
	// 	snprintf(cmd, sizeof(cmd), "bootm 0x%lX#${pcb}", src);
	// 	ret = run_command(cmd, 0);
	// } else {
	// 	printf("File load failure.\n");
	// 	swap_curr_part(mmc_new);
	// }
	snprintf(cmd, sizeof(cmd), "run cboot");
	ret = run_command(cmd, 0);
	return ret;
}

int do_startf(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	int ret;
	unsigned long filesize, blkcount;
	unsigned long src, dst;

	src = get_env_addr("loadaddr");
	dst = src + MAX_FILE_SIZE;
	snprintf(cmd, sizeof(cmd), "tftp 0x%lX %s", src, FACTORY_PARTITION_IMAGE_NAME);
	ret = run_command(cmd, 0);
	if (0 == ret) {
		snprintf(cmd, sizeof(cmd), "unzip 0x%lX 0x%lX", src, dst);
		ret = run_command(cmd, 0);
		if (0 == ret) {
			blkcount = get_file_size() / 512 + 1;
			snprintf(cmd, sizeof(cmd), "mmc write 0x%lX 0x%lX 0x%lX",
					dst, flash[FACTORY_PARTITION].addr / 512, blkcount);
			ret = run_command(cmd, 0);
			if (0 == ret) {
				snprintf(cmd, sizeof(cmd), "ext4load 0:%d 0x%lX /empty_ext4.img.gz",
					FACTORY_PARTITION, src);
				ret = run_command(cmd, 0);
				if (0 == ret) {
					snprintf(cmd, sizeof(cmd), "unzip 0x%lX 0x%lX", src, dst);
					ret = run_command(cmd, 0);
					if (0 == ret) {
						filesize = get_file_size();
						blkcount = filesize / 512 + 1;
						snprintf(cmd, sizeof(cmd), "mmc write 0x%lX 0x%lX 0x%lX",
								dst, flash[5].addr / 512, blkcount);
						ret = run_command(cmd, 0);
						if (0 != ret) {
							printf("Can't create app.a partition\n");
						}

						snprintf(cmd, sizeof(cmd), "mmc write 0x%lX 0x%lX 0x%lX",
								dst, flash[6].addr / 512, blkcount);
						ret = run_command(cmd, 0);
						if (0 != ret) {
							printf("Can't create app.b partition\n");
						}

						snprintf(cmd, sizeof(cmd), "ext4load 0:%d 0x%lX /empty_fat.img.gz",
							FACTORY_PARTITION, src);
						ret = run_command(cmd, 0);
						if (0 == ret) {
							snprintf(cmd, sizeof(cmd), "unzip 0x%lX 0x%lX", src, dst);
							ret = run_command(cmd, 0);
							if (0 == ret) {
								filesize = get_file_size();
								blkcount = filesize / 512 + 1;
								snprintf(cmd, sizeof(cmd), "mmc write 0x%lX 0x%lX 0x%lX",
										dst, flash[8].addr / 512, blkcount);
								ret = run_command(cmd, 0);
								if (0 != ret) {
									printf("Can't create update partition\n");
								}

							} else {
								printf("Can't unzip empty fat partition\n");
							}
						} else {
							printf("Can't load empty fat partition\n");
						}

					} else {
						printf("Can't unzip empty ext4 partition\n");
					}
				} else {
					printf("Can't load empty ext4 partition\n");
				}
			} else {
				printf("Can't write factory partition\n");
			}
		} else {
			printf("Can't unzip factory partition\n");
		}
	} else {
		printf("Can't load factory partition\n");
	}
	return ret;
}

U_BOOT_CMD(
	startp, 1, 0, do_startp,
	"startp",
	"startp to start proxeet boot"
);

U_BOOT_CMD(
	startf, 1, 0, do_startf,
	"startf",
	"startp to start factory"
);
