/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LAN966X_MAIN
#define LAN966X_MAIN

void lan966x_otp_init(void);
bool lan966x_otp_get_mac(u8 *mac);
bool lan966x_otp_get_pcb(u16 *pcb);
bool lan966x_otp_get_mac_count(char *mac_count);
bool lan966x_otp_get_partid(char *part);
bool lan966x_otp_get_serial_number(char *serial);

#endif
