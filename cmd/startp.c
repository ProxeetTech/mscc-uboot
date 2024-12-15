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

int do_startp(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	int ret = 0;
	int i;
	char cmd[1024];
	const char *p, *pv, *mmc_curr, *filesize_str;
	int max_wait = 10;
	unsigned long blkcount, filesize;

	pv = env_get("recvalue");

	for (i = 0; i < max_wait; i++) {
		snprintf(cmd, sizeof(cmd), "gpio read recbutton ${recgpio}");
		ret = run_command(cmd, 0);
		p = env_get("recgpio");
		if (*pv == *p) {
			printf("key pressed\n");
		} else {
			printf("key in not pressed\n");
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
		snprintf(cmd, sizeof(cmd), "ext4load mmc 0:7 0x63000000 /factory.img.gz");
		ret = run_command(cmd, 0);
		if (0 == ret) {
			snprintf(cmd, sizeof(cmd), "unzip 0x63000000 0x67000000");
			ret = run_command(cmd, 0);
			if (0 == ret) {
				filesize_str = env_get("filesize");
				blkcount = hextoul(filesize_str, NULL);
				blkcount = blkcount/512 + 1;
				mmc_curr = env_get("mmc_cur");
				if (*mmc_curr == '5') {
					// to 6
					snprintf(cmd, sizeof(cmd), "mmc write 0x67000000 0x00282800 0x%lX", blkcount);
				} else {
					// to 5
					snprintf(cmd, sizeof(cmd), "mmc write 0x67000000 0x00082800 0x%lX", blkcount);
				}
				ret = run_command(cmd, 0);
				if (0 == ret) {
					if (*mmc_curr == '5') {
						env_set("mmc_cur", "6");
					} else {
						env_set("mmc_cur", "5");
					}
					env_save();
					env_save();
				}
			}
		}
	} else {
		// Update is available.
		printf("Try to update.\n");
		snprintf(cmd, sizeof(cmd), "ext4size mmc 0:7 /update.bin");
		ret = run_command(cmd, 0);
		filesize_str = env_get("filesize");
		filesize = hextoul(filesize_str, NULL);
		if ((0 == ret) && (filesize > 0)) {
			printf("Update is available.\n");
			snprintf(cmd, sizeof(cmd), "ext4load mmc 0:7 0x63000000 /update.bin");
			ret = run_command(cmd, 0);
			if (0 == ret) {
				filesize_str = env_get("filesize");
				blkcount = hextoul(filesize_str, NULL);
				blkcount = blkcount/512 + 1;
				mmc_curr = env_get("mmc_cur");
				if (*mmc_curr == '5') {
					// to 6
					snprintf(cmd, sizeof(cmd), "mmc write 0x63000000 0x00282800 0x%lX", blkcount);
				} else {
					// to 5
					snprintf(cmd, sizeof(cmd), "mmc write 0x63000000 0x00082800 0x%lX", blkcount);
				}
				ret = run_command(cmd, 0);
				if (0 == ret) {
					if (*mmc_curr == '5') {
						env_set("mmc_cur", "6");
					} else {
						env_set("mmc_cur", "5");
					}
					env_save();
					env_save();
					snprintf(cmd, sizeof(cmd), "ext4write mmc 0:7 0x67000000 /update.bin 0x0");
					ret = run_command(cmd, 0);
				}
			}
		}
	}
	snprintf(cmd, sizeof(cmd), "run mmcboot");
	ret = run_command(cmd, 0);
	return ret;
}

U_BOOT_CMD(
	startp, 1, 0, do_startp,
	"startp",
	"startp to start proxeet boot"
);
