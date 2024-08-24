// SPDX-License-Identifier: GPL-2.0+

#include <common.h>
#include <clk.h>
#include <errno.h>
#include <serial.h>
#include <debug_uart.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <dm/device.h>

#include "lan966x_udphs_regs.h"
#include "usb.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define UDPHS				0xE0808000
#define UDPHS_RAM_ADDR			0x00200000

#define DMA_MAX_FIFO_SIZE		65536
#define EPT_VIRTUAL_SIZE		8192

#define EP_OUT				1
#define EP_IN				2
#define EP_INTER			3

#define SHIFT_INTERUPT			8

#define UDPHS_EPTCFG_EPT_SIZE_512	0x6
#define UDPHS_EPTCFG_EPT_SIZE_1024	0x7

#define UDPHS_EPTCFG_EPT_SIZE_8		0x0
#define UDPHS_EPTCFG_EPT_SIZE_16	0x1
#define UDPHS_EPTCFG_EPT_SIZE_32	0x2
#define UDPHS_EPTCFG_EPT_SIZE_64	0x3
#define UDPHS_EPTCFG_EPT_SIZE_128	0x4
#define UDPHS_EPTCFG_EPT_SIZE_256	0x5
#define UDPHS_EPTCFG_EPT_SIZE_512	0x6
#define UDPHS_EPTCFG_EPT_SIZE_1024	0x7

#define BUFF_SIZE 512

static const unsigned int lan966x_regs[NUM_TARGETS] = {
	0x0,				/*  0 */
	0x0,				/*  1 */
	0x0,				/*  2 */
	0x0,				/*  3 */
	0x0,				/*  4 */
	0x0,				/*  5 */
	0xe00C0000,			/*  6 (TARGET_CPU) */
	0x0,				/*  7 */
	0x0,				/*  8 */
	0x0,				/*  9 */
	0x0,				/* 10 */
	0x0,				/* 11 */
	0x0,				/* 12 */
	0x0,				/* 13 */
	0x0,				/* 14 */
	0x0,				/* 15 */
	0x0,				/* 16 */
	0x0,				/* 17 */
	0x0,				/* 18 */
	0x0,				/* 19 */
	0x0,				/* 20 */
	0x0,				/* 21 */
	0x0,				/* 22 */
	0x0,				/* 23 */
	0x0,				/* 24 */
	0x0,				/* 25 */
	0x0,				/* 26 */
	0x0,				/* 27 */
	0x0,				/* 28 */
	0x0,				/* 29 */
	0x0,				/* 30 */
	0x0,				/* 31 */
	0x0,				/* 32 */
	0x0,				/* 33 */
	0x0,				/* 34 */
	0x0,				/* 35 */
	0x0,				/* 36 */
	0x0,				/* 37 */
	0x0,				/* 38 */
	0x0,				/* 39 */
	0x0,				/* 40 */
	0x0,				/* 41 */
	0x0,				/* 42 */
	0x0,				/* 43 */
	0x0,				/* 44 */
	0x0,				/* 45 */
	0x0,				/* 46 */
	0x0,				/* 47 */
	0x0,				/* 48 */
	0x0,				/* 49 */
	0x0,				/* 50 */
	0x0,				/* 51 */
	0x0,				/* 52 */
	0x0,				/* 53 */
	0x0,				/* 54 */
	0x0,				/* 55 */
	0x0,				/* 56 */
	0x0,				/* 57 */
	0x0,				/* 58 */
	0xe0808000,			/* 59 (TARGET_UDPHS) */
	0x0,				/* 60 */
	0x0,				/* 61 */
	0x0,				/* 62 */
	0x0,				/* 63 */
	0x0,				/* 64 */
	0x0,				/* 65 */
};

#define LAN_RD_(id, tinst, tcnt,		\
		gbase, ginst, gcnt, gwidth,		\
		raddr, rinst, rcnt, rwidth)		\
	readl(lan966x_regs[id + (tinst)] +		\
	      gbase + ((ginst) * gwidth) +		\
	      raddr + ((rinst) * rwidth))

#define LAN_WR_(val, id, tinst, tcnt,		\
		gbase, ginst, gcnt, gwidth,		\
		raddr, rinst, rcnt, rwidth)		\
	writel(val, lan966x_regs[id + (tinst)] +	\
	       gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth))

#define LAN_RMW_(val, mask, id, tinst, tcnt,	\
		 gbase, ginst, gcnt, gwidth,		\
		 raddr, rinst, rcnt, rwidth) do {	\
	u32 _v_;					\
	_v_ = readl(lan966x_regs[id + (tinst)] +	\
		    gbase + ((ginst) * gwidth) +	\
		    raddr + ((rinst) * rwidth));	\
	_v_ = ((_v_ & ~(mask)) | ((val) & (mask)));	\
	writel(_v_, lan966x_regs[id + (tinst)] +	\
	       gbase + ((ginst) * gwidth) +		\
	       raddr + ((rinst) * rwidth)); } while (0)

#define LAN_WR(...) LAN_WR_(__VA_ARGS__)
#define LAN_RD(...) LAN_RD_(__VA_ARGS__)
#define LAN_RMW(...) LAN_RMW_(__VA_ARGS__)

static const u8 devDescriptor[] = {
    /* Device descriptor */
    18,    // bLength
    USBGenericDescriptor_DEVICE,   // bDescriptorType
    0x00,   // bcdUSBL
    0x02,   //
    CDCDeviceDescriptor_CLASS,   // bDeviceClass:    CDC class code
    CDCDeviceDescriptor_SUBCLASS,   // bDeviceSubclass: CDC class sub code
    CDCDeviceDescriptor_PROTOCOL,   // bDeviceProtocol: CDC Device protocol
    64,   // bMaxPacketSize0
    0x25,   // idVendorL
    0x05,   //
    0xa7,   // idProductL
    0xa4,   //
    0x10,   // bcdDeviceL
    0x01,   //
    0, // No string descriptor for manufacturer
    0x00,   // iProduct
    0, // No string descriptor for serial number
    1 // Device has 1 possible configuration
};

static u8 sConfiguration[] = {
    //! ============== CONFIGURATION 1 ===========
    //! Table 9-10. Standard Configuration Descriptor
    9,                            // bLength;              // size of this descriptor in bytes
    USBGenericDescriptor_CONFIGURATION,// bDescriptorType;    // CONFIGURATION descriptor type
    67, // total length of data returned 2 EP + Control + OTG
    0x00,
    2, // There are two interfaces in this configuration
    1, // This is configuration #1
    0, // No string descriptor for this configuration
    USB_CONFIG_SELF_NOWAKEUP,        // bmAttibutes;          // Configuration characteristics
    50,                            // 100mA

    //! Communication Class Interface Descriptor Requirement
    //! Table 9-12. Standard Interface Descriptor
    9,                       // Size of this descriptor in bytes
    USBGenericDescriptor_INTERFACE,// INTERFACE Descriptor Type
    0, // This is interface #0
    0, // This is alternate setting #0 for this interface
    1, // This interface uses 1 endpoint
    CDCCommunicationInterfaceDescriptor_CLASS, // bInterfaceClass
    CDCCommunicationInterfaceDescriptor_ABSTRACTCONTROLMODEL,       // bInterfaceSubclass
    CDCCommunicationInterfaceDescriptor_NOPROTOCOL,                       // bInterfaceProtocol
    0,  // No string descriptor for this interface

    //! 5.2.3.1 Header Functional Descriptor (usbcdc11.pdf)
    5, // bFunction Length
    CDCGenericDescriptor_INTERFACE, // bDescriptor type: CS_INTERFACE
    CDCGenericDescriptor_HEADER,    // bDescriptor subtype: Header Func Desc
    0x10,             // bcdCDC: CDC Class Version 1.10
    0x01,

    //! 5.2.3.2 Call Management Functional Descriptor (usbcdc11.pdf)
    5, // bFunctionLength
    CDCGenericDescriptor_INTERFACE, // bDescriptor Type: CS_INTERFACE
    CDCGenericDescriptor_CALLMANAGEMENT,       // bDescriptor Subtype: Call Management Func Desc
    0x00,             // bmCapabilities: D1 + D0
    0x01,             // bDataInterface: Data Class Interface 1

    //! 5.2.3.3 Abstract Control Management Functional Descriptor (usbcdc11.pdf)
    4,             // bFunctionLength
    CDCGenericDescriptor_INTERFACE, // bDescriptor Type: CS_INTERFACE
    CDCGenericDescriptor_ABSTRACTCONTROLMANAGEMENT,       // bDescriptor Subtype: ACM Func Desc
    0x00,             // bmCapabilities

    //! 5.2.3.8 Union Functional Descriptor (usbcdc11.pdf)
    5,             // bFunctionLength
    CDCGenericDescriptor_INTERFACE, // bDescriptorType: CS_INTERFACE
    CDCGenericDescriptor_UNION,     // bDescriptor Subtype: Union Func Desc
    0, // Number of master interface is #0
    1, // First slave interface is #1

    //! Endpoint 1 descriptor
    //! Table 9-13. Standard Endpoint Descriptor
    7,                    // bLength
    USBGenericDescriptor_ENDPOINT,// bDescriptorType
    0x80 | EP_INTER,     // bEndpointAddress, Endpoint EP_INTER - IN
    USBEndpointDescriptor_INTERRUPT,// bmAttributes      INT
    0x40, 0x00,              // wMaxPacketSize = 64
    0x10,             // Endpoint is polled every 16ms

    //! Table 9-12. Standard Interface Descriptor
    9,                     // bLength
    USBGenericDescriptor_INTERFACE,// bDescriptorType
    1, // This is interface #1
    0, // This is alternate setting #0 for this interface
    2, // This interface uses 2 endpoints
    CDCDataInterfaceDescriptor_CLASS,
    CDCDataInterfaceDescriptor_SUBCLASS,
    CDCDataInterfaceDescriptor_NOPROTOCOL,
    0,  // No string descriptor for this interface

    //! First alternate setting
    //! Table 9-13. Standard Endpoint Descriptor
    7,                            // bLength
    USBGenericDescriptor_ENDPOINT,// bDescriptorType
    EP_OUT,            // bEndpointAddress, Endpoint EP_OUT - OUT
    USBEndpointDescriptor_BULK,   // bmAttributes      BULK
    0x00, 0x02,                   // wMaxPacketSize = 512
    0, // Must be 0 for full-speed bulk endpoints

    //! Table 9-13. Standard Endpoint Descriptor
    7,                            // bLength
    USBGenericDescriptor_ENDPOINT,// bDescriptorType
    0x80 | EP_IN,             // bEndpointAddress, Endpoint EP_IN - IN
    USBEndpointDescriptor_BULK,   // bmAttributes      BULK
    0x00, 0x02,                   // wMaxPacketSize = 512
    0 // Must be 0 for full-speed bulk endpoints
};

static u8 sOtherSpeedConfiguration[] = {
    //! ============== CONFIGURATION 1 ===========
    //! Table 9-10. Standard Configuration Descriptor
    0x09,                            // bLength;              // size of this descriptor in bytes
    USBGenericDescriptor_OTHERSPEEDCONFIGURATION,    // bDescriptorType;      // CONFIGURATION descriptor type
    67,                            // wTotalLength;         // total length of data returned 2 EP + Control
    0x00,
    0x02, // There are two interfaces in this configuration
    0x01, // This is configuration #1
    0x00, // No string descriptor for this configuration
    USB_CONFIG_SELF_NOWAKEUP,        // bmAttibutes;          // Configuration characteristics
    50,   // 100mA

    //! Communication Class Interface Descriptor Requirement
    //! Table 9-12. Standard Interface Descriptor
    9,                       // Size of this descriptor in bytes
    USBGenericDescriptor_INTERFACE,// INTERFACE Descriptor Type
    0, // This is interface #0
    0, // This is alternate setting #0 for this interface
    1, // This interface uses 1 endpoint
    CDCCommunicationInterfaceDescriptor_CLASS, // bInterfaceClass
    CDCCommunicationInterfaceDescriptor_ABSTRACTCONTROLMODEL,       // bInterfaceSubclass
    CDCCommunicationInterfaceDescriptor_NOPROTOCOL,                       // bInterfaceProtocol
    0x00, // No string descriptor for this interface

    //! 5.2.3.1 Header Functional Descriptor (usbcdc11.pdf)
    5, // bFunction Length
    CDCGenericDescriptor_INTERFACE, // bDescriptor type: CS_INTERFACE
    CDCGenericDescriptor_HEADER,    // bDescriptor subtype: Header Func Desc
    0x10,             // bcdCDC: CDC Class Version 1.10
    0x01,

    //! 5.2.3.2 Call Management Functional Descriptor (usbcdc11.pdf)
    5, // bFunctionLength
    CDCGenericDescriptor_INTERFACE, // bDescriptor Type: CS_INTERFACE
    CDCGenericDescriptor_CALLMANAGEMENT,       // bDescriptor Subtype: Call Management Func Desc
    0x00,             // bmCapabilities: D1 + D0
    0x01,             // bDataInterface: Data Class Interface 1

    //! 5.2.3.3 Abstract Control Management Functional Descriptor (usbcdc11.pdf)
    4,             // bFunctionLength
    CDCGenericDescriptor_INTERFACE, // bDescriptor Type: CS_INTERFACE
    CDCGenericDescriptor_ABSTRACTCONTROLMANAGEMENT,       // bDescriptor Subtype: ACM Func Desc
    0x00,             // bmCapabilities

    //! 5.2.3.8 Union Functional Descriptor (usbcdc11.pdf)
    5,             // bFunctionLength
    CDCGenericDescriptor_INTERFACE, // bDescriptorType: CS_INTERFACE
    CDCGenericDescriptor_UNION,     // bDescriptor Subtype: Union Func Desc
    0, // Number of master interface is #0
    1, // First slave interface is #1

    //! Endpoint 1 descriptor
    //! Table 9-13. Standard Endpoint Descriptor
    7,                    // bLength
    USBGenericDescriptor_ENDPOINT, // bDescriptorType
    0x80 | EP_INTER,     // bEndpointAddress, Endpoint EP_INTER - IN
    USBEndpointDescriptor_INTERRUPT, // bmAttributes      INT
    0x40, 0x00,              // wMaxPacketSize
    0x10,                    // bInterval, for HS value between 0x01 and 0x10 = 16ms here

    //! Table 9-12. Standard Interface Descriptor
    9,                     // bLength
    USBGenericDescriptor_INTERFACE,// bDescriptorType
    1, // This is interface #1
    0, // This is alternate setting #0 for this interface
    2, // This interface uses 2 endpoints
    CDCDataInterfaceDescriptor_CLASS,
    CDCDataInterfaceDescriptor_SUBCLASS,
    CDCDataInterfaceDescriptor_NOPROTOCOL,
    0,  // No string descriptor for this interface

    //! First alternate setting
    //! Table 9-13. Standard Endpoint Descriptor
    7,                     // bLength
    USBGenericDescriptor_ENDPOINT,  // bDescriptorType
    EP_OUT,         // bEndpointAddress, Endpoint EP_OUT - OUT
    USBEndpointDescriptor_BULK,// bmAttributes      BULK
    0x40, 0x00,                // wMaxPacketSize = 64
    0, // Must be 0 for full-speed bulk endpoints

    //! Table 9-13. Standard Endpoint Descriptor
    7,                     // bLength
    USBGenericDescriptor_ENDPOINT,  // bDescriptorType
    0x80 | EP_IN,          // bEndpointAddress, Endpoint EP_IN - IN
    USBEndpointDescriptor_BULK,// bmAttributes      BULK
    0x40, 0x00,                // wMaxPacketSize = 64
    0 // Must be 0 for full-speed bulk endpoints
};


//! CDC line coding
struct cdc_line_coding {
	u32 dwDTERRate;   // Baudrate
	u8  bCharFormat;  // Stop bit
	u8  bParityType;  // Parity
	u8  bDataBits;    // data bits
};

static struct cdc_line_coding line ={ 115200, // baudrate
                               0,   // 1 Stop Bit
                               0,   // None Parity
                               8    // 8 Data bits
};

#define MAXPACKETCTRL (u16)(devDescriptor[7])
#define MAXPACKETSIZEOUT (u16)(sConfiguration[57]+(sConfiguration[58]<<8))
#define OSCMAXPACKETSIZEOUT (u16)(sOtherSpeedConfiguration[57]+(sOtherSpeedConfiguration[58]<<8))
#define MAXPACKETSIZEIN (u16)(sConfiguration[64]+(sConfiguration[65]<<8))
#define OSCMAXPACKETSIZEIN (u16)(sOtherSpeedConfiguration[64]+(sOtherSpeedConfiguration[65]<<8))
#define MAXPACKETSIZEINTER (u16)(sConfiguration[41]+(sConfiguration[42]<<8))
#define OSCMAXPACKETSIZEINTER (u16)(sOtherSpeedConfiguration[41]+(sOtherSpeedConfiguration[42]<<8))

static void pause(u32 val)
{
	register int i = 0;

	for (i = 0; i < val; ++i)
	    asm volatile("nop;");
}

struct udphs_dma {
	u32 dmanxtdsc;
	u32 dmaaddress;
	u32 dmacontrol;
	u32 dmastatus;
};

struct udphs_ept {
	u32 eptcfg;
	u32 eptctlenb;
	u32 eptctldis;
	u32 eptctl;
	u32 res[1];
	u32 eptsetsta;
	u32 eptclrsta;
	u32 eptsta;
};

#define UDPHSEPT_NUMBER 16
#define UDPHSDMA_NUMBER 7

struct udphs {
	u32 ctrl;
	u32 fnum;
	u32 reserved1[2];
	u32 ien;
	u32 intsta;
	u32 clrint;
	u32 eptrst;
	u32 reserved2[44];
	u32 tstsofcnt;
	u32 tstcnta;
	u32 tstcntb;
	u32 tstmodereg;
	u32 tst;
	u32 reserved3[6];
	u32 version;
	struct udphs_ept ept[UDPHSEPT_NUMBER];
	struct udphs_dma dma[UDPHSDMA_NUMBER];
};

union usb_request {
	u32 data32[2];
	u16 data16[4];
	u8 data8[8];
	struct {
		u8 bmRequestType;        //!< Characteristics of the request
		u8 bRequest;             //!< Specific request
		u16 wValue;              //!< field that varies according to request
		u16 wIndex;              //!< field that varies according to request
		u16 wLength;             //!< Number of bytes to transfer if Data
	} request;
};

struct cdc {
	struct udphs		*interface;
	u32			*interface_ept;
	u8			current_configuration;
	u8			current_connection;
	u8			set_line;
	u16			dev_status;
	u16			ept_status;
	union usb_request	*setup;
};

struct usb_wrapper {
	struct cdc		cdc;
	union usb_request	setup_payload;

	u8 buff[BUFF_SIZE];
	u16 buff_start;
	u16 buff_end;
};

static void lan966x_send_data(struct cdc *cdc, const u8 *data, u32 length)
{
	u32 *interface_ept = cdc->interface_ept;
	u32 index = 0;
	u32 cpt = 0;
	u8 *fifo;

	while (0 != (LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_TXRDY_EPTSTA0_M))
		   ;

	if(0 != length) {
		while (length) {
			cpt = MIN(length, MAXPACKETCTRL);
			length -= cpt;
			fifo = (u8*)interface_ept;

			while (cpt--) {
				fifo[index] = data[index];
				index++;
			}

			LAN_WR(UDPHS_EPTSETSTA0_TXRDY_EPTSETSTA0(1),
			       UDPHS_EPTSETSTA0);

			while ((0 != (LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_TXRDY_EPTSTA0_M)) &&
			       ((LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) != UDPHS_INTSTA_DET_SUSPD_INTSTA_M))
				;

			if ((LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) == UDPHS_INTSTA_DET_SUSPD_INTSTA_M)
				break;
		}
	}
	else {
		while (0 != (LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_TXRDY_EPTSTA0_M))
			;

		LAN_WR(UDPHS_EPTSETSTA0_TXRDY_EPTSETSTA0(1),
		       UDPHS_EPTSETSTA0);

		while ((0 != (LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_TXRDY_EPTSTA0_M)) &&
		       ((LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) != UDPHS_INTSTA_DET_SUSPD_INTSTA_M))
				;
	}
}

static void lan966x_send_zlp(void)
{
	while (0 != (LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_TXRDY_EPTSTA0_M))
		;

	LAN_WR(UDPHS_EPTSETSTA0_TXRDY_EPTSETSTA0(1), UDPHS_EPTSETSTA0);

	while ((0 != (LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_TXRDY_EPTSTA0_M)) &&
	      ((LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) != UDPHS_INTSTA_DET_SUSPD_INTSTA_M))
		;
}

static void lan966x_send_stall(void)
{
	LAN_WR(UDPHS_EPTSETSTA0_FRCESTALL_EPTSETSTA0(1), UDPHS_EPTSETSTA0);
}

static u8 lan966x_size_endpoint(u16 packet_size)
{
	if ( packet_size == 8 ) {
		return UDPHS_EPTCFG_EPT_SIZE_8;
	} else if ( packet_size == 16 ) {
		return UDPHS_EPTCFG_EPT_SIZE_16;
	} else if ( packet_size == 32 ) {
		return UDPHS_EPTCFG_EPT_SIZE_32;
	} else if ( packet_size == 64 ) {
		return UDPHS_EPTCFG_EPT_SIZE_64;
	} else if ( packet_size == 128 ) {
		return UDPHS_EPTCFG_EPT_SIZE_128;
	} else if ( packet_size == 256 ) {
		return UDPHS_EPTCFG_EPT_SIZE_256;
	} else if ( packet_size == 512 ) {
		return UDPHS_EPTCFG_EPT_SIZE_512;
	} else if ( packet_size == 1024 ) {
		return UDPHS_EPTCFG_EPT_SIZE_1024;
	}

	return 0;
}

static void cdc_enumerate(struct cdc *cdc)
{
	u32 *interface_ept = cdc->interface_ept;
	union usb_request *setup_data = cdc->setup;
	u16 wMaxPacketSizeOUT;
	u16 wMaxPacketSizeIN;
	u16 wMaxPacketSizeINTER;
	u16 sizeEpt;

	if ((LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_RX_SETUP_EPTSTA0_M) != UDPHS_EPTSTA0_RX_SETUP_EPTSTA0_M)
		return;

	setup_data->data32[0] = readl(interface_ept);
	setup_data->data32[1] = readl(interface_ept);

	LAN_WR(UDPHS_EPTCLRSTA0_RX_SETUP_EPTCLRSTA0(1), UDPHS_EPTCLRSTA0);

	// Handle supported standard device request Cf Table 9-3 in USB specification Rev 1.1
	switch (setup_data->request.bRequest) {
	case USBGenericRequest_GETDESCRIPTOR:
		if (setup_data->request.wValue == (USBGenericDescriptor_DEVICE << 8)) {
			lan966x_send_data(cdc, devDescriptor, MIN(sizeof(devDescriptor), setup_data->request.wLength));

			// Waiting for Status stage
			while ((LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M) != UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M)
				;

			LAN_WR(UDPHS_EPTCLRSTA0_RXRDY_TXKL_EPTCLRSTA0(1),
			       UDPHS_EPTCLRSTA0);
		}
		else if (setup_data->request.wValue == (USBGenericDescriptor_CONFIGURATION << 8)) {
			if (LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_SPEED_M) {
				sConfiguration[1] = USBGenericDescriptor_CONFIGURATION;
				lan966x_send_data(cdc, sConfiguration, MIN(sizeof(sConfiguration), setup_data->request.wLength));

				// Waiting for Status stage
				while ((LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M) != UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M)
					;

				LAN_WR(UDPHS_EPTCLRSTA0_RXRDY_TXKL_EPTCLRSTA0(1),
				       UDPHS_EPTCLRSTA0);
			}
			else {
				sOtherSpeedConfiguration[1] = USBGenericDescriptor_CONFIGURATION;
				lan966x_send_data(cdc, sOtherSpeedConfiguration, MIN(sizeof(sOtherSpeedConfiguration), setup_data->request.wLength));

				// Waiting for Status stage
				while ((LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M) != UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M)
					;

				LAN_WR(UDPHS_EPTCLRSTA0_RXRDY_TXKL_EPTCLRSTA0(1),
				       UDPHS_EPTCLRSTA0);
			}
		}
		else {
			lan966x_send_stall();
		}
		break;

	case USBGenericRequest_SETADDRESS:
		lan966x_send_zlp();
		LAN_RMW(UDPHS_CTRL_DEV_ADDR(setup_data->request.wValue & 0x7F) |
			UDPHS_CTRL_FADDR_EN(1),
			UDPHS_CTRL_DEV_ADDR_M |
			UDPHS_CTRL_FADDR_EN_M,
			UDPHS_CTRL);
		break;

	case USBGenericRequest_SETCONFIGURATION:
		cdc->current_configuration = (uint8_t)setup_data->request.wValue;  // The lower byte of the wValue field specifies the desired configuration.
		lan966x_send_zlp();

		if (LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_SPEED_M) {
			// High Speed
			wMaxPacketSizeOUT   = MAXPACKETSIZEOUT;
			wMaxPacketSizeIN    = MAXPACKETSIZEIN;
			wMaxPacketSizeINTER = MAXPACKETSIZEINTER;
		} else {
			// Full Speed
			wMaxPacketSizeOUT   = OSCMAXPACKETSIZEOUT;
			wMaxPacketSizeIN    = OSCMAXPACKETSIZEIN;
			wMaxPacketSizeINTER = OSCMAXPACKETSIZEINTER;
		}

		sizeEpt = lan966x_size_endpoint(wMaxPacketSizeOUT);
		LAN_WR(UDPHS_EPTCFG1_EPT_SIZE_EPTCFG1(sizeEpt) |
		       UDPHS_EPTCFG1_EPT_TYPE_EPTCFG1(2) |
		       UDPHS_EPTCFG1_BK_NUMBER_EPTCFG1(2),
		       UDPHS_EPTCFG1);
		while ((LAN_RD(UDPHS_EPTCFG1) & UDPHS_EPTCFG1_EPT_MAPD_EPTCFG1_M) != UDPHS_EPTCFG1_EPT_MAPD_EPTCFG1_M)
			;
		LAN_WR(UDPHS_EPTCTLENB1_RXRDY_TXKL_EPTCTLENB1(1) |
		       UDPHS_EPTCTLENB1_EPT_ENABL_EPTCTLENB1(1),
		       UDPHS_EPTCTLENB1);

		sizeEpt = lan966x_size_endpoint(wMaxPacketSizeIN);
		LAN_WR(UDPHS_EPTCFG2_EPT_SIZE_EPTCFG2(sizeEpt) |
		       UDPHS_EPTCFG2_EPT_DIR_EPTCFG2(1) |
		       UDPHS_EPTCFG2_EPT_TYPE_EPTCFG2(2) |
		       UDPHS_EPTCFG2_BK_NUMBER_EPTCFG2(2),
		       UDPHS_EPTCFG2);
		while ((LAN_RD(UDPHS_EPTCFG2) & UDPHS_EPTCFG2_EPT_MAPD_EPTCFG2_M) != UDPHS_EPTCFG2_EPT_MAPD_EPTCFG2_M)
			;
		LAN_WR(UDPHS_EPTCTLENB2_SHRT_PCKT_EPTCTLENB2(1) |
		       UDPHS_EPTCTLENB2_EPT_ENABL_EPTCTLENB2(1),
		       UDPHS_EPTCTLENB2);

		sizeEpt = lan966x_size_endpoint(wMaxPacketSizeINTER);
		LAN_WR(UDPHS_EPTCFG3_EPT_SIZE_EPTCFG3(sizeEpt) |
		       UDPHS_EPTCFG3_EPT_DIR_EPTCFG3(1) |
		       UDPHS_EPTCFG3_EPT_TYPE_EPTCFG3(3) |
		       UDPHS_EPTCFG3_BK_NUMBER_EPTCFG3(1),
		       UDPHS_EPTCFG3);
		while ((LAN_RD(UDPHS_EPTCFG3) & UDPHS_EPTCFG3_EPT_MAPD_EPTCFG3_M) != UDPHS_EPTCFG3_EPT_MAPD_EPTCFG3_M)
			;
		LAN_WR(UDPHS_EPTCTLENB3_EPT_ENABL_EPTCTLENB3(1),
		       UDPHS_EPTCTLENB3);

		break;

	case USBGenericRequest_GETCONFIGURATION:
		lan966x_send_data(cdc, (u8*) &(cdc->current_configuration), sizeof(cdc->current_configuration));
		break;

	// handle CDC class requests
	case CDCGenericRequest_SETLINECODING:
		// Waiting for Status stage
		while ((LAN_RD(UDPHS_EPTSTA0) & UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M) != UDPHS_EPTSTA0_RXRDY_TXKL_EPTSTA0_M)
			;

		LAN_WR(UDPHS_EPTCLRSTA0_RXRDY_TXKL_EPTCLRSTA0(1),
		       UDPHS_EPTCLRSTA0);

		cdc->set_line = 1;
		lan966x_send_zlp();
                break;

	case CDCGenericRequest_GETLINECODING:
		lan966x_send_data(cdc, (u8*) &line, MIN(sizeof(line), setup_data->request.wLength));
		break;

	case CDCGenericRequest_SETCONTROLLINESTATE:
		cdc->current_connection = (u8)setup_data->request.wValue;
		cdc->set_line = 0;
		lan966x_send_zlp();
		break;

	// case USBGenericRequest_SETINTERFACE:  MUST BE STALL for us
	default:
		lan966x_send_stall();
		break;
	}
}

static u8 lan966x_is_configured(struct cdc *cdc)
{
	u32 isr = LAN_RD(UDPHS_INTSTA);
	u16 size_ept;

	// Resume
	if ((isr & UDPHS_INTSTA_WAKE_UP_INTSTA_M) ||
	    (isr & UDPHS_INTSTA_ENDOFRSM_INTSTA_M))
		LAN_RMW(UDPHS_CLRINT_WAKE_UP_CLRINT(1) |
			UDPHS_CLRINT_ENDOFRSM_CLRINT(1),
			UDPHS_CLRINT_WAKE_UP_CLRINT_M |
			UDPHS_CLRINT_ENDOFRSM_CLRINT_M,
			UDPHS_CLRINT);

	if (isr & (UDPHS_INTSTA_INT_SOF_INTSTA_M)) {
		LAN_RMW(UDPHS_CLRINT_INT_SOF_CLRINT(1),
			UDPHS_CLRINT_INT_SOF_CLRINT_M,
			UDPHS_CLRINT);
	} else {
		if (isr & (UDPHS_INTSTA_MICRO_SOF_INTSTA_M)) {
			LAN_RMW(UDPHS_CLRINT_MICRO_SOF_CLRINT(1),
				UDPHS_CLRINT_MICRO_SOF_CLRINT_M,
				UDPHS_CLRINT);
		}
	}

	// Suspend
	if (isr & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) {
		cdc->current_configuration = 0;
		cdc->set_line = 0;
		LAN_RMW(UDPHS_CLRINT_DET_SUSPD_CLRINT(1),
			UDPHS_CLRINT_DET_SUSPD_CLRINT_M,
			UDPHS_CLRINT);
	} else {
		if (isr & UDPHS_INTSTA_ENDRESET_INTSTA_M) {
			cdc->current_configuration = 0;
			cdc->set_line = 0;

			size_ept = lan966x_size_endpoint(MAXPACKETCTRL);

			LAN_RMW(UDPHS_EPTCFG0_EPT_SIZE_EPTCFG0(size_ept) |
				UDPHS_EPTCFG0_EPT_TYPE_EPTCFG0(0) |
				UDPHS_EPTCFG0_BK_NUMBER_EPTCFG0(1),
				UDPHS_EPTCFG0_EPT_SIZE_EPTCFG0_M |
				UDPHS_EPTCFG0_EPT_TYPE_EPTCFG0_M |
				UDPHS_EPTCFG0_BK_NUMBER_EPTCFG0_M,
				UDPHS_EPTCFG0);

			while( (LAN_RD(UDPHS_EPTCFG0) & UDPHS_EPTCFG0_EPT_MAPD_EPTCFG0_M) != UDPHS_EPTCFG0_EPT_MAPD_EPTCFG0_M)
				;

			LAN_RMW(UDPHS_EPTCTLENB0_RX_SETUP_EPTCTLENB0(1) |
				UDPHS_EPTCTLENB0_EPT_ENABL_EPTCTLENB0(1),
				UDPHS_EPTCTLENB0_RX_SETUP_EPTCTLENB0_M |
				UDPHS_EPTCTLENB0_EPT_ENABL_EPTCTLENB0_M,
				UDPHS_EPTCTLENB0);

			LAN_RMW(UDPHS_CLRINT_ENDRESET_CLRINT(1),
				UDPHS_CLRINT_ENDRESET_CLRINT_M,
				UDPHS_CLRINT);
		} else {
			if (isr & (1<<SHIFT_INTERUPT))
			    cdc_enumerate(cdc);
		}
	}

	return cdc->current_configuration && cdc->set_line;
}

static u32 lan966x_write(struct cdc *cdc, const u8 *data, u32 length)
{
	unsigned long count = 0;
	u32 cpt = 0;
	u32 packet_size;
	u8 *fifo;

	if (!lan966x_is_configured(cdc))
		return 0;

	if (0 != length) {
		packet_size = LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_SPEED_M ?
			MAXPACKETSIZEIN : OSCMAXPACKETSIZEIN;

		while (length) {
			cpt = MIN(length, packet_size);
			length -= cpt;
			fifo = (u8*)((u32*)cdc->interface_ept + (16384 * EP_IN));

			while (cpt) {
				*(fifo++) = *(data++);
				--cpt;
			}

			LAN_WR(UDPHS_EPTSETSTA2_TXRDY_EPTSETSTA2(1),
			       UDPHS_EPTSETSTA2);

			while (((LAN_RD(UDPHS_EPTSTA2) & UDPHS_EPTSTA2_TXRDY_EPTSTA2_M)) &&
				((LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) != UDPHS_INTSTA_DET_SUSPD_INTSTA_M)) {
				if (count == 100)
					return 0;
				udelay(10);
				count++;
			}

			if ((LAN_RD(UDPHS_INTSTA) & UDPHS_INTSTA_DET_SUSPD_INTSTA_M) == UDPHS_INTSTA_DET_SUSPD_INTSTA_M)
				break;
		}
	}

	return length;
}

static u32 lan966x_read(struct usb_wrapper *usb, struct cdc *cdc, u8 *data)
{
	u32 recv = 0;
	u8 *fifo;
	u32 size;

	if (!lan966x_is_configured(cdc))
		return 0;

	if (0 != (LAN_RD(UDPHS_EPTSTA1) & UDPHS_EPTSTA1_RXRDY_TXKL_EPTSTA1_M)) {
		size = (LAN_RD(UDPHS_EPTSTA1) & UDPHS_EPTSTA1_BYTE_COUNT_EPTSTA1_M) >> 20;
		fifo = (u8*)((u32*)cdc->interface_ept + (16384 * EP_OUT));

		while (size--) {
			/* Maybe it should be readb */
			data[usb->buff_end] = fifo[recv];
			recv++;

			usb->buff_end = (usb->buff_end + 1) % BUFF_SIZE;
			if (usb->buff_end == usb->buff_start)
				break;
		}

		LAN_WR(UDPHS_EPTCLRSTA1_RXRDY_TXKL_EPTCLRSTA1(1),
		       UDPHS_EPTCLRSTA1);
	}

	return 0;
}

static void lan966x_cdc_init(struct cdc *cdc, union usb_request *setup_payload,
			     void *interface, void *interface_ept)
{
	memset(cdc, 0x0, sizeof(struct cdc));
	memset(setup_payload, 0x0, sizeof(union usb_request));

	cdc->interface = interface;
	cdc->interface_ept = interface_ept;
	cdc->setup = setup_payload;
	cdc->current_configuration = 0;
	cdc->current_connection = 0;
	cdc->set_line = 0;
}

static void lan966x_serial_init(void)
{
	// enable clock
	LAN_WR(LAN_RD(CPU_CLK_GATING) | CPU_CLK_GATING_UDPHS_CLK_GATING(1),
	       CPU_CLK_GATING);

	LAN_RMW(UDPHS_CTRL_PULLD_DIS(1) |
		UDPHS_CTRL_EN_UDPHS(1) |
		UDPHS_CTRL_DETACH(0),
		UDPHS_CTRL_PULLD_DIS_M |
		UDPHS_CTRL_EN_UDPHS_M |
		UDPHS_CTRL_DETACH_M,
		UDPHS_CTRL);

	LAN_WR(CPU_ULPI_RST_ULPI_RST(0), CPU_ULPI_RST);

	/* Wait at UTMI clocks to be stable */
	pause(150);

	LAN_RMW(UDPHS_IEN_EPT_X(0),
		UDPHS_IEN_EPT_X_M,
		UDPHS_IEN);
}

static void lan966x_usb_init(struct usb_wrapper *usb)
{
	unsigned long count = 0;

	lan966x_cdc_init(&usb->cdc, &usb->setup_payload,
			 (void*)UDPHS, (void*)UDPHS_RAM_ADDR);
	lan966x_serial_init();

	while (!usb->cdc.current_connection || !usb->cdc.set_line) {
		lan966x_is_configured(&usb->cdc);

		if (count == 1000)
			return;

		udelay(1000);
		count++;
	}
}

static int lan966x_serial_getc(struct udevice *dev)
{
	struct usb_wrapper *usb = dev_get_priv(dev);
	u32 val;

	lan966x_read(usb, &usb->cdc, usb->buff);
	if (usb->buff_start == usb->buff_end)
		return -EAGAIN;

	val = usb->buff[usb->buff_start];
	usb->buff_start = (usb->buff_start + 1) % BUFF_SIZE;

	return val;
}

static int lan966x_serial_putc(struct udevice *dev, const char ch)
{
	struct usb_wrapper *usb = dev_get_priv(dev);

	return lan966x_write(&usb->cdc, (u8*)&ch, 1);
}

static int lan966x_serial_pending(struct udevice *dev, bool input)
{
	struct usb_wrapper *usb = dev_get_priv(dev);

	if (!lan966x_is_configured(&usb->cdc))
		return 0;

	if (input)
		return (LAN_RD(UDPHS_EPTSTA1) & UDPHS_EPTSTA1_RXRDY_TXKL_EPTSTA1_M) ||
		       (usb->buff_start != usb->buff_end);
	else
		return LAN_RD(UDPHS_EPTSTA2) & UDPHS_EPTSTA2_TXRDY_EPTSTA2_M;
}

static int lan966x_serial_setbrg(struct udevice *dev, int baudrate)
{
	return 0;
}

static const struct dm_serial_ops lan966x_serial_ops = {
	.putc = lan966x_serial_putc,
	.getc = lan966x_serial_getc,
	.pending = lan966x_serial_pending,
	.setbrg = lan966x_serial_setbrg,
};

static int lan966x_serial_probe(struct udevice *dev)
{
	struct usb_wrapper *usb = dev_get_priv(dev);

	if ((LAN_RD(UDPHS_EPTCFG0) & UDPHS_EPTCFG0_EPT_MAPD_EPTCFG0_M) &&
	    (LAN_RD(UDPHS_EPTCFG1) & UDPHS_EPTCFG1_EPT_MAPD_EPTCFG1_M) &&
	    (LAN_RD(UDPHS_EPTCFG2) & UDPHS_EPTCFG2_EPT_MAPD_EPTCFG2_M) &&
	    (LAN_RD(UDPHS_EPTCFG3) & UDPHS_EPTCFG3_EPT_MAPD_EPTCFG3_M)) {
		lan966x_cdc_init(&usb->cdc, &usb->setup_payload,
				 (void*)UDPHS, (void*)UDPHS_RAM_ADDR);
		usb->cdc.current_configuration = 1;
		usb->cdc.current_connection = 1;
		usb->cdc.set_line = 1;
	} else {
		lan966x_usb_init(usb);
	}

	usb->buff_start = 0;
	usb->buff_end = 0;

	return 0;
}

static const struct udevice_id lan966x_serial_ids[] = {
	{
		.compatible = "mchp,lan966x-uart",
	},
	{ }
};

U_BOOT_DRIVER(serial_lan966x) = {
	.name	= "serial_lan966x",
	.id	= UCLASS_SERIAL,
	.of_match = lan966x_serial_ids,
	.probe = lan966x_serial_probe,
	.ops	= &lan966x_serial_ops,
	.priv_auto = sizeof(struct usb_wrapper),
};
