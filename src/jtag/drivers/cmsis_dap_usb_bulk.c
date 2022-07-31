/***************************************************************************
 *   Copyright (C) 2018 by Mickaël Thomas                                  *
 *   mickael9@gmail.com                                                    *
 *                                                                         *
 *   Copyright (C) 2016 by Maksym Hilliaka                                 *
 *   oter@frozen-team.com                                                  *
 *                                                                         *
 *   Copyright (C) 2016 by Phillip Pearson                                 *
 *   pp@myelin.co.nz                                                       *
 *                                                                         *
 *   Copyright (C) 2014 by Paul Fertser                                    *
 *   fercerpav@gmail.com                                                   *
 *                                                                         *
 *   Copyright (C) 2013 by mike brown                                      *
 *   mike@theshedworks.org.uk                                              *
 *                                                                         *
 *   Copyright (C) 2013 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H	
#include "config.h"
#endif

#include <helper/system.h>
#include <libusb.h>
#include <helper/log.h>
#include <helper/replacements.h>

#include "cmsis_dap.h"
struct libusb_device_handle *wlink_dev_handle=NULL;
struct cmsis_dap_backend_data {
	struct libusb_context *usb_ctx;
	struct libusb_device_handle *dev_handle;
	unsigned int ep_out;
	unsigned int ep_in;
	int interface;
};

static int cmsis_dap_usb_interface = -1;

static void cmsis_dap_usb_close(struct cmsis_dap *dap);
static int cmsis_dap_usb_alloc(struct cmsis_dap *dap, unsigned int pkt_sz);

static int cmsis_dap_usb_open(struct cmsis_dap *dap, uint16_t vids[], uint16_t pids[], const char *serial)
{
	int err;
	struct libusb_context *ctx;
	struct libusb_device **device_list;

	err = libusb_init(&ctx);
	if (err) {
		LOG_ERROR("libusb initialization failed: %s", libusb_strerror(err));
		return ERROR_FAIL;
	}

	int num_devices = libusb_get_device_list(ctx, &device_list);
	if (num_devices < 0) {
		LOG_ERROR("could not enumerate USB devices: %s", libusb_strerror(num_devices));
		libusb_exit(ctx);
		return ERROR_FAIL;
	}

	for (int i = 0; i < num_devices; i++) {
		struct libusb_device *dev = device_list[i];
		struct libusb_device_descriptor dev_desc;

		err = libusb_get_device_descriptor(dev, &dev_desc);
		if (err) {
			LOG_ERROR("could not get device descriptor for device %d: %s", i, libusb_strerror(err));
			continue;
		}

		/* Match VID/PID */

		bool id_match = false;
		bool id_filter = vids[0] || pids[0];
		for (int id = 0; vids[id] || pids[id]; id++) {
			id_match = !vids[id] || dev_desc.idVendor == vids[id];
			id_match &= !pids[id] || dev_desc.idProduct == pids[id];

			if (id_match)
				break;
		}

		if (id_filter && !id_match)
			continue;

		/* Don't continue if we asked for a serial number and the device doesn't have one */
		if (dev_desc.iSerialNumber == 0 && serial && serial[0])
			continue;

		struct libusb_device_handle *dev_handle = NULL;
		err = libusb_open(dev, &dev_handle);
		
		if (err) {
			/* It's to be expected that most USB devices can't be opened
			 * so only report an error if it was explicitly selected
			 */
			if (id_filter) {
				LOG_ERROR("could not open device 0x%04x:0x%04x: %s",
						dev_desc.idVendor, dev_desc.idProduct, libusb_strerror(err));
			} else {
				LOG_DEBUG("could not open device 0x%04x:0x%04x: %s",
						dev_desc.idVendor, dev_desc.idProduct, libusb_strerror(err));
			}
			continue;
		}
		
		/* Match serial number */

		bool serial_match = false;
		char dev_serial[256] = {0};
		if (dev_desc.iSerialNumber > 0) {
			err = libusb_get_string_descriptor_ascii(
					dev_handle, dev_desc.iSerialNumber,
					(uint8_t *)dev_serial, sizeof(dev_serial));

			if (err < 0) {
				const char *msg = "could not read serial number for device 0x%04x:0x%04x: %s";
				if (serial)
					LOG_WARNING(msg, dev_desc.idVendor, dev_desc.idProduct,
								libusb_strerror(err));
				else
					LOG_DEBUG(msg, dev_desc.idVendor, dev_desc.idProduct,
								libusb_strerror(err));
			} else if (serial && strncmp(dev_serial, serial, sizeof(dev_serial)) == 0) {
				serial_match = true;
			}
		}

		if (serial && !serial_match) {
			libusb_close(dev_handle);
			continue;
		}

		/* Find the CMSIS-DAP string in product string */

		bool cmsis_dap_in_product_str = false;
		char product_string[256] = {0};
		if (dev_desc.iProduct > 0) {
			err = libusb_get_string_descriptor_ascii(
					dev_handle, dev_desc.iProduct,
					(uint8_t *)product_string, sizeof(product_string));
			if (err < 0) {
				LOG_WARNING("could not read product string for device 0x%04x:0x%04x: %s",
						dev_desc.idVendor, dev_desc.idProduct, libusb_strerror(err));
			} else if (strstr(product_string, "CMSIS-DAP")) {
				LOG_DEBUG("found product string of 0x%04x:0x%04x '%s'",
						  dev_desc.idVendor, dev_desc.idProduct, product_string);
				cmsis_dap_in_product_str = true;
			}
		}

		bool device_identified_reliably = cmsis_dap_in_product_str
											|| serial_match || id_match;

		/* Find the CMSIS-DAP interface */

		for (int config = 0; config < dev_desc.bNumConfigurations; config++) {
			struct libusb_config_descriptor *config_desc;
			err = libusb_get_config_descriptor(dev, config, &config_desc);
			if (err) {
				LOG_ERROR("could not get configuration descriptor %d for device 0x%04x:0x%04x: %s",
						config, dev_desc.idVendor, dev_desc.idProduct, libusb_strerror(err));
				continue;
			}

			LOG_DEBUG("enumerating interfaces of 0x%04x:0x%04x",
					  dev_desc.idVendor, dev_desc.idProduct);
			int config_num = config_desc->bConfigurationValue;
			const struct libusb_interface_descriptor *intf_desc_candidate = NULL;
			const struct libusb_interface_descriptor *intf_desc_found = NULL;

			for (int interface = 0; interface < config_desc->bNumInterfaces; interface++) {
				const struct libusb_interface_descriptor *intf_desc = &config_desc->interface[interface].altsetting[0];
				int interface_num = intf_desc->bInterfaceNumber;

				/* Skip this interface if another one was requested explicitly */
				if (cmsis_dap_usb_interface != -1 && cmsis_dap_usb_interface != interface_num)
					continue;

				/* CMSIS-DAP v2 spec says:
				 *
				 * CMSIS-DAP with default V2 configuration uses WinUSB and is therefore faster.
				 * Optionally support for streaming SWO trace is provided via an additional USB endpoint.
				 *
				 * The WinUSB configuration requires custom class support with the interface setting
				 *     Class Code: 0xFF (Vendor specific)
				 *     Subclass: 0x00
				 *     Protocol code: 0x00
				 *
				 * Depending on the configuration it uses the following USB endpoints which should be configured
				 * in the interface descriptor in this order:
				 *  - Endpoint 1: Bulk Out – used for commands received from host PC.
				 *  - Endpoint 2: Bulk In – used for responses send to host PC.
				 *  - Endpoint 3: Bulk In (optional) – used for streaming SWO trace (if enabled with SWO_STREAM).
				 */

				/* Search for "CMSIS-DAP" in the interface string */
				bool cmsis_dap_in_interface_str = false;
				if (intf_desc->iInterface != 0) {

					char interface_str[256] = {0};

					err = libusb_get_string_descriptor_ascii(
							dev_handle, intf_desc->iInterface,
							(uint8_t *)interface_str, sizeof(interface_str));
					if (err < 0) {
						LOG_DEBUG("could not read interface string %d for device 0x%04x:0x%04x: %s",
								  intf_desc->iInterface,
								  dev_desc.idVendor, dev_desc.idProduct,
								  libusb_strerror(err));
					} else if (strstr(interface_str, "CMSIS-DAP")) {
						cmsis_dap_in_interface_str = true;
						LOG_DEBUG("found interface %d string '%s'",
								  interface_num, interface_str);
					}
				}

				/* Bypass the following check if this interface was explicitly requested. */
				if (cmsis_dap_usb_interface == -1) {
					if (!cmsis_dap_in_product_str && !cmsis_dap_in_interface_str)
						continue;
				}

				/* check endpoints */
				if (intf_desc->bNumEndpoints < 2) {
					LOG_DEBUG("skipping interface %d, has only %d endpoints",
							  interface_num, intf_desc->bNumEndpoints);
					continue;
				}

				if ((intf_desc->endpoint[0].bmAttributes & 3) != LIBUSB_TRANSFER_TYPE_BULK ||
						(intf_desc->endpoint[0].bEndpointAddress & 0x80) != LIBUSB_ENDPOINT_OUT) {
					LOG_DEBUG("skipping interface %d, endpoint[0] is not bulk out",
							  interface_num);
					continue;
				}

				if ((intf_desc->endpoint[1].bmAttributes & 3) != LIBUSB_TRANSFER_TYPE_BULK ||
						(intf_desc->endpoint[1].bEndpointAddress & 0x80) != LIBUSB_ENDPOINT_IN) {
					LOG_DEBUG("skipping interface %d, endpoint[1] is not bulk in",
							  interface_num);
					continue;
				}

				/* We can rely on the interface is really CMSIS-DAP if
				 * - we've seen CMSIS-DAP in the interface string
				 * - config asked explicitly for an interface number
				 * - the device has only one interface
				 * The later two cases should be honored only if we know
				 * we are on the right device */
				bool intf_identified_reliably = cmsis_dap_in_interface_str
							|| (device_identified_reliably &&
									(cmsis_dap_usb_interface != -1
									 || config_desc->bNumInterfaces == 1));

				if (intf_desc->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC ||
						intf_desc->bInterfaceSubClass != 0 || intf_desc->bInterfaceProtocol != 0) {
					/* If the interface is reliably identified
					 * then we need not insist on setting USB class, subclass and protocol
					 * exactly as the specification requires.
					 * At least KitProg3 uses class 0 contrary to the specification */
					if (intf_identified_reliably) {
						LOG_WARNING("Using CMSIS-DAPv2 interface %d with wrong class %" PRId8
								  " subclass %" PRId8 " or protocol %" PRId8,
								  interface_num,
								  intf_desc->bInterfaceClass,
								  intf_desc->bInterfaceSubClass,
								  intf_desc->bInterfaceProtocol);
					} else {
						LOG_DEBUG("skipping interface %d, class %" PRId8
								  " subclass %" PRId8 " protocol %" PRId8,
								  interface_num,
								  intf_desc->bInterfaceClass,
								  intf_desc->bInterfaceSubClass,
								  intf_desc->bInterfaceProtocol);
						continue;

					}
				}

				if (intf_identified_reliably) {
					/* That's the one! */
					intf_desc_found = intf_desc;
					break;
				}

				if (!intf_desc_candidate && device_identified_reliably) {
					/* This interface looks suitable for CMSIS-DAP. Store the pointer to it
					 * and keep searching for another one with CMSIS-DAP in interface string */
					intf_desc_candidate = intf_desc;
				}
			}

			if (!intf_desc_found) {
				/* We were not able to identify reliably which interface is CMSIS-DAP.
				 * Let's use the first suitable if we found one */
				intf_desc_found = intf_desc_candidate;
			}

			if (!intf_desc_found) {
				libusb_free_config_descriptor(config_desc);
				continue;
			}

			/* We've chosen an interface, connect to it */
			int interface_num = intf_desc_found->bInterfaceNumber;
			int packet_size = intf_desc_found->endpoint[0].wMaxPacketSize;
			int ep_out = intf_desc_found->endpoint[0].bEndpointAddress;
			int ep_in = intf_desc_found->endpoint[1].bEndpointAddress;

			libusb_free_config_descriptor(config_desc);
			libusb_free_device_list(device_list, true);

			LOG_INFO("Using CMSIS-DAPv2 interface with VID:PID=0x%04x:0x%04x, serial=%s",
					dev_desc.idVendor, dev_desc.idProduct, dev_serial);
		    
			int current_config;
			err = libusb_get_configuration(dev_handle, &current_config);
			if (err) {
				LOG_ERROR("could not find current configuration: %s", libusb_strerror(err));
				libusb_close(dev_handle);
				libusb_exit(ctx);
				return ERROR_FAIL;
			}

			if (config_num != current_config) {
				err = libusb_set_configuration(dev_handle, config_num);
				if (err) {
					LOG_ERROR("could not set configuration: %s", libusb_strerror(err));
					libusb_close(dev_handle);
					libusb_exit(ctx);
					return ERROR_FAIL;
				}
			}

			err = libusb_claim_interface(dev_handle, interface_num);
			if (err)
				LOG_WARNING("could not claim interface: %s", libusb_strerror(err));

			dap->bdata = malloc(sizeof(struct cmsis_dap_backend_data));
			if (!dap->bdata) {
				LOG_ERROR("unable to allocate memory");
				libusb_release_interface(dev_handle, interface_num);
				libusb_close(dev_handle);
				libusb_exit(ctx);
				return ERROR_FAIL;
			}

			dap->packet_size = packet_size;
			dap->packet_buffer_size = packet_size;
			dap->bdata->usb_ctx = ctx;
			dap->bdata->dev_handle = dev_handle;
			dap->bdata->ep_out = ep_out;
			dap->bdata->ep_in = ep_in;
			dap->bdata->interface = interface_num;
			
			dap->packet_buffer = malloc(dap->packet_buffer_size);
			if (!dap->packet_buffer) {
				LOG_ERROR("unable to allocate memory");
				cmsis_dap_usb_close(dap);
				return ERROR_FAIL;
			}

			dap->command = dap->packet_buffer;
			dap->response = dap->packet_buffer;
			//wlink_dev_handle=dev_handle;
			return ERROR_OK;
		}

		libusb_close(dev_handle);
	}

	libusb_free_device_list(device_list, true);

	libusb_exit(ctx);
	return ERROR_FAIL;
}

static void cmsis_dap_usb_close(struct cmsis_dap *dap)
{
	libusb_release_interface(dap->bdata->dev_handle, dap->bdata->interface);
	libusb_close(dap->bdata->dev_handle);
	libusb_exit(dap->bdata->usb_ctx);
	free(dap->bdata);
	dap->bdata = NULL;
	free(dap->packet_buffer);
	dap->packet_buffer = NULL;
}

static int cmsis_dap_usb_read(struct cmsis_dap *dap, int timeout_ms)
{
	int transferred = 0;
	int err;

	err = libusb_bulk_transfer(dap->bdata->dev_handle, dap->bdata->ep_in,
							dap->packet_buffer, dap->packet_size, &transferred, timeout_ms);
	if (err) {
		if (err == LIBUSB_ERROR_TIMEOUT) {
			return ERROR_TIMEOUT_REACHED;
		} else {
			LOG_ERROR("error reading data: %s", libusb_strerror(err));
			return ERROR_FAIL;
		}
	}

	memset(&dap->packet_buffer[transferred], 0, dap->packet_buffer_size - transferred);

	return transferred;
}

static int cmsis_dap_usb_write(struct cmsis_dap *dap, int txlen, int timeout_ms)
{
	int transferred = 0;
	int err;

	/* skip the first byte that is only used by the HID backend */
	err = libusb_bulk_transfer(dap->bdata->dev_handle, dap->bdata->ep_out,
							dap->packet_buffer, txlen, &transferred, timeout_ms);
	if (err) {
		if (err == LIBUSB_ERROR_TIMEOUT) {
			return ERROR_TIMEOUT_REACHED;
		} else {
			LOG_ERROR("error writing data: %s", libusb_strerror(err));
			return ERROR_FAIL;
		}
	}

	return transferred;
}

static int cmsis_dap_usb_alloc(struct cmsis_dap *dap, unsigned int pkt_sz)
{
	uint8_t *buf = malloc(pkt_sz);
	if (!buf) {
		LOG_ERROR("unable to allocate CMSIS-DAP packet buffer");
		return ERROR_FAIL;
	}

	dap->packet_buffer = buf;
	dap->packet_size = pkt_sz;
	dap->packet_buffer_size = pkt_sz;

	dap->command = dap->packet_buffer;
	dap->response = dap->packet_buffer;

	return ERROR_OK;
}





extern uint8_t armchip;
int timeout=300;
// extern struct libusb_device_handle *wlink_dev_handle;
extern unsigned  int  chip_type;
static const uint32_t flash_code1[] = {
	0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4603B510, 0x04C00CD8, 0x444C4C7A, 0x20006020, 0x60204C79, 0x60604879, 0x60604879, 0x62604877,
    0x62604877, 0x69C04620, 0x0004F000, 0xF245B940, 0x4C745055, 0x20066020, 0xF6406060, 0x60A070FF,
    0xBD102000, 0x486C4601, 0xF0406900, 0x4A6A0080, 0x20006110, 0x48684770, 0xF0406900, 0x49660004,
    0x46086108, 0xF0406900, 0x61080040, 0xF64AE003, 0x496420AA, 0x48606008, 0xF00068C0, 0x28000001,
    0x485DD1F5, 0xF0206900, 0x495B0004, 0x20006108, 0xB5084770, 0x20004601, 0x48579000, 0xF0406900,
    0x4A550002, 0x20016110, 0xBF009000, 0x61414852, 0xF0406900, 0x4A500040, 0xE0036110, 0x20AAF64A,
    0x60104A50, 0x68C0484C, 0x0001F000, 0xD1F52800, 0x0000F89D, 0xB2C01E40, 0x28009000, 0x4846D1E6, 
    0xF0206900, 0x4A440002, 0x20006110, 0xB5F0BD08, 0x460D4604, 0x46232608, 0x60086828, 0x40024842,
    0x2200F442, 0x6102483C, 0x483BBF00, 0xF00068C0, 0x28000001, 0xF422D1F9, 0xBF002200, 0x6018C901,
    0x6058C901, 0x6098C901, 0x60D8C901, 0x2280F442, 0x61024831, 0xBF003310, 0x68C0482F, 0x0001F000,
    0xD1F92800, 0xB2C01E70, 0xD1E71E06, 0x2280F422, 0x007FF024, 0x61784F28, 0x0240F042, 0x61024638,
    0x0240F022, 0x4824BF00, 0xF00068C0, 0x28000001, 0x4821D1F9, 0xF00068C0, 0xB1600014, 0x68C0481E,
    0x0014F040, 0x60F84F1C, 0x20FFF240, 0x46384002, 0x20016102, 0x2000BDF0, 0xE92DE7FC, 0x460641F8,
    0x4615460F, 0x0800F04F, 0xF1079600, 0xF3C0007F, 0x481118C7, 0xF4446904, 0x61043480, 0x4622BF00,
    0x98004629, 0xFF93F7FF, 0x2001B110, 0x81F8E8BD, 0x30809800, 0x35809000, 0x0001F1A8, 0xF1B0B2C0,  
    0xD1EC0800, 0x20FFF240, 0x48034004, 0x20006104, 0x0000E7EC, 0x00000004, 0x40022000, 0x45670123,
    0xCDEF89AB, 0x40003000, 0x000102FF, 0x00000000, 0x00000000, 
};

uint32_t program_code1[] = {
	0x20000021, // Init
	0x20000065, // UnInit
	0x20000077, // EraseChip
	0x200000B3, // EraseSector
	0x200001BB, // ProgramPage
	0x20000001,
	0x20000C00,
	0x20001000,
	0x20000400, // mem buffer location
	0x20000000, // location to write prog_blob in target RAM
	(uint32_t)sizeof(flash_code1),
};

static const uint32_t flash_code2[] = {
	0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
	0x4603B510, 0x04C00CD8, 0x444C4C55, 0x20006020, 0x60204C54, 0x60604854, 0x60604854, 0x62604852,
	0x62604852, 0x69C04620, 0x0004F000, 0xF245B940, 0x4C4F5055, 0x20066020, 0xF6406060, 0x60A070FF,
	0xBD102000, 0x48474601, 0xF0406900, 0x4A450080, 0x20006110, 0x48434770, 0xF0406900, 0x49410004,
	0x46086108, 0xF0406900, 0x61080040, 0xF64AE003, 0x493F20AA, 0x483B6008, 0xF00068C0, 0x28000001,
	0x4838D1F5, 0xF0206900, 0x49360004, 0x20006108, 0x46014770, 0x69004833, 0x0002F040, 0x61104A31,
	0x61414610, 0xF0406900, 0x61100040, 0xF64AE003, 0x4A2F20AA, 0x482B6010, 0xF00068C0, 0x28000001,
	0x4828D1F5, 0xF0206900, 0x4A260002, 0x20006110, 0xB5704770, 0x25004603, 0xF0232440, 0xF10103FF,
	0xF3C000FF, 0x481F2507, 0xF4406900, 0x4E1D3080, 0xBF006130, 0xE00C2440, 0x60186810, 0x1D121D1B,
	0xB2C41E60, 0x4817BF00, 0xF00068C0, 0x28000002, 0x2C00D1F9, 0x4813D1F0, 0xF4406900, 0x4E111000,
	0xBF006130, 0x68C0480F, 0x0001F000, 0xD1F92800, 0xB2C01E68, 0xD1DD0005, 0x6900480A, 0x3080F420,
	0x61304E08, 0x68C04630, 0x0010F000, 0x4630B130, 0xF04068C0, 0x60F00010, 0xBD702001, 0xE7FC2000,
	0x00000004, 0x40022000, 0x45670123, 0xCDEF89AB, 0x40003000, 0x00000000, 0x00000000};

uint32_t program_code2[] = {
	0x20000021, // Init
	0x20000065, // UnInit
	0x20000077, // EraseChip
	0x200000B3, // EraseSector
	0x200000F3, // ProgramPage

	// BKPT : start of blob + 1
	// RSB  : address to access global/static data
	// RSP  : stack pointer

	0x20000001,
	0x20000C00,
	0x20001000,
	0x20000400,			 // mem buffer location
	0x20000000,			 // location to write prog_blob in target RAM
	sizeof(flash_code2), // prog_blob size
};

void wlink_sendchip(uint8_t config)
{
	int transferred = 0;
	uint16_t rom=0;
	uint16_t ram=0;
	uint8_t buffer_code[5] = { 0x81, 0x0c, 0x02, 0x08, 0x01};
	uint8_t buffer_rcode[20];
	if (armchip == 1)
		buffer_code[3] = 0x04;
	if (armchip == 2)
		buffer_code[3] = 0x08;

	libusb_bulk_transfer(wlink_dev_handle, 0x02,buffer_code,sizeof(buffer_code),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,4,&transferred,timeout);
	buffer_code[1]=0x11;
	buffer_code[2]=0x01;
	libusb_bulk_transfer(wlink_dev_handle, 0x02,buffer_code,4,&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);	
	chip_type=((unsigned int)buffer_rcode[19]) + (((unsigned int)buffer_rcode[18])<<8) + (((unsigned int)buffer_rcode[17])<<16) +(((unsigned int) buffer_rcode[16])<<24);	
	bool type_A=false;
	bool type_B=false;
	if(chip_type==0x20700418 ||chip_type==0x20300414 ||chip_type==0x20310414 )
		type_A=true;
	if(chip_type==0x2080041c  || chip_type==0x2081041c)
		type_B=true;
	switch(config){
		case 0:
           if(type_A){
				 rom=192;
                 ram=128;
			 }
			else if(type_B){
				 rom=128;
                 ram=64;
			}else{
 				 rom=0;
                 ram=0;
			}
			break;
		case 1:
			if(type_A){
				 rom=224;
                 ram=96;
			 }
			else if(type_B){
				 rom=144;
                 ram=48;
			}else{
 				 rom=0;
                 ram=0;
			}
			break;
		case 2:
			if(type_A){
				 rom=256;
                 ram=64;
			 }
			else if(type_B){
				 rom=160;
                 ram=32;
			}else{
 				 rom=0;
                 ram=0;
			}
			break;
		case 3:
           if(type_A){
				 rom=288;
                 ram=32;
			 }
			else if(type_B){
				 rom=160;
                 ram=32;
			}else{
 				 rom=0;
                 ram=0;
			}
			break;
		default:
				 rom=0;
                 ram=0;
			  break;
	}
	if((rom!=0) && (ram!=0))
		LOG_INFO("ROM %d kbytes RAM %d kbytes" ,rom,ram);

	
}
void wlink_armversion(struct cmsis_dap *dap){
	
	int transferred = 0;
	unsigned char txbuf[4]={0x81,0x0d,0x1,0x1};
	unsigned char rxbuf[20];
	int len=7;
	char * wlink_name=NULL;
	wlink_dev_handle=dap->bdata->dev_handle;
	libusb_bulk_transfer(dap->bdata->dev_handle, 0x02,txbuf,sizeof(txbuf),&transferred,timeout);
	usleep(1000);
	libusb_bulk_transfer(dap->bdata->dev_handle, 0x83,rxbuf,len,&transferred,timeout);
	switch (rxbuf[5])
		{
		case 1:
			wlink_name="WCH-Link-CH549  mod:ARM";
			break;
		case 2:
			wlink_name="WCH-LinkE-CH32V307  mod:ARM";
			break;
		case 3:
			wlink_name="WCH-LinkS-CH32V203  mod:ARM";
			break;
		case 4:
			wlink_name="WCH-LinkB  mod:ARM";
			break;
		default:
			LOG_ERROR("unknow WCH-LINK ");	
			break;
		}
	LOG_INFO("%s version %d.%d ",wlink_name, rxbuf[3], rxbuf[4]);
}
int wlink_armcheckprotect(void)
{
	int transferred = 0;

	uint8_t buffer_clk[] = { 0x81, 0x0c, 0x02, 0x08, 0x01};
	uint8_t buffer_code[] = {0x81, 0x06, 0x01, 0x01};
	uint8_t buffer_rcode[4];
	if (armchip == 1)
		buffer_clk[3] = 0x04;
	if (armchip == 2)
		buffer_clk[3] = 0x08;	
	libusb_bulk_transfer(wlink_dev_handle, 0x02,buffer_clk,sizeof(buffer_code),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
	// hid_write(wlink_dev_handle, buffer_clk, 65);
	// hid_read_timeout(wlink_dev_handle, buffer_rcode, 65, beytime);
	if ((*(buffer_rcode + 0) == 0x82) && (*(buffer_rcode + 1) == 0x0c) && (*(buffer_rcode + 2) == 0x01)  && (*(buffer_rcode + 3 )== 0x01))
	{
		libusb_bulk_transfer(wlink_dev_handle, 0x02,buffer_code,sizeof(buffer_code),&transferred,timeout);
		libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
		// hid_write(wlink_dev_handle, buffer_code, 65);
		// hid_read(wlink_dev_handle, buffer_rcode, 65);
		if (buffer_rcode[3] == 1)
		{
			LOG_ERROR(" Please Disable R-Protect");
			return ERROR_FAIL;
		}
		return ERROR_OK;
	}
}
int wlink_armerase(void)
{
	uint8_t buffer_code[] = { 0x81, 0x02, 0x01, 0x05};
	int transferred=0;
	uint8_t buffer_rcode[4];
	uint32_t *comprogram = NULL;
	uint32_t *comflash = NULL;
	if (armchip == 1)
	{
		comprogram = program_code1;
		comflash = flash_code1;
	}

	if (armchip == 2)
	{
		comprogram = program_code2;
		comflash = flash_code2;
	}
	uint8_t i = 0;
	uint8_t *flashcode = (uint8_t *)comflash;

	int h = *(comprogram + 10);

	uint8_t txbuf[64] = {0x0};
	int loopcount = 0;
	// hid_write(wlink_dev_handle, buffer_code, 65);
	// hid_read(wlink_dev_handle, buffer_rcode, 65);
	libusb_bulk_transfer(wlink_dev_handle, 0x02,buffer_code,sizeof(buffer_code),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
	for (int f = 0; f <= 43; f++)
	{
		txbuf[f] = *(((uint8_t *)comprogram) + f);
	}
	// hid_write(wlink_dev_handle, txbuf, 65);
	libusb_bulk_transfer(wlink_dev_handle, 0x02,txbuf,44,&transferred,timeout);
	while (h > 0)
	{
		for (int j = 0; j < 64; j++)
		{
			txbuf[j] = *((uint8_t *)comflash + (j) + loopcount);
		}
		// hid_write(wlink_dev_handle, txbuf, 65);
		libusb_bulk_transfer(wlink_dev_handle, 0x02,txbuf,sizeof(txbuf),&transferred,timeout);
		h -= 64;
		loopcount += 64;
	}
	uint8_t buffer_erase[] = { 0x81, 0x02, 0x01, 0x01};
	// int retval = hid_write(wlink_dev_handle, buffer_erase, 65);
	// hid_read(wlink_dev_handle, buffer_rcode, 65);
	libusb_bulk_transfer(wlink_dev_handle, 0x02,buffer_erase,sizeof(buffer_erase),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
	if ((*(buffer_rcode + 0) == 0x82) && (*(buffer_rcode + 1) == 0x02) && (*(buffer_rcode + 2) == 0x01) && (*(buffer_rcode + 3) == 0x01))
	{
		return ERROR_OK;
	}
	LOG_ERROR(" ERASE FAILED");
	return ERROR_FAIL;
}
int wlink_armwrite(const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	int transferred = 0;
	uint8_t *addr = &offset;
	uint8_t flash_write[] = {0x81, 0x02, 0x01, 0x02};
	uint8_t buffer_rcode[4];
	uint8_t i = 0;
	uint8_t txbuf[64] = {0};
	int loopcount = 0;
	int mount = count;
	uint32_t modflag = count % 256;
	uint8_t *buffer1 = malloc(count + 256 - modflag);
	memcpy(buffer1, buffer, count);
	if (modflag)
	{
		count = count + 256 - modflag;
		memset((buffer1 + mount), 0xff, (256 - modflag));
	}

	uint8_t address[] = { 0x81, 0x01, 0x08, *(addr + 3), *(addr + 2), *(addr + 1), *addr,(count >> 24) & 0xff, (count >> 16) & 0xff, (count >> 8) & 0xff, count & 0xff};
	// hid_write(wlink_dev_handle, address, 65); 
	// hid_read_timeout(wlink_dev_handle, buffer_rcode, 65, beytime);
	// hid_write(wlink_dev_handle, countsize, 65);
	// hid_read_timeout(wlink_dev_handle, buffer_rcode, 65, beytime); 
	// hid_write(wlink_dev_handle, flash_write, 65); 
	// int retval = hid_read_timeout(wlink_dev_handle, buffer_rcode, 65, beytime);
	libusb_bulk_transfer(wlink_dev_handle, 0x02,address,sizeof(address),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
	// libusb_bulk_transfer(wlink_dev_handle, 0x02,countsize,sizeof(countsize),&transferred,timeout);
	// libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x02,flash_write,sizeof(flash_write),&transferred,timeout);
	libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
	while (count > 0)
	{
		for (int j = 0; j < 64; j++)
		{
			txbuf[j] = *(buffer1 + j  + loopcount);
		}
		// hid_write(wlink_dev_handle, txbuf, 65);
		libusb_bulk_transfer(wlink_dev_handle, 0x02,txbuf,sizeof(txbuf),&transferred,timeout);
		count -= 64;
		loopcount += 64;
		if (++i % 2 == 0)
		{
			// hid_read(wlink_dev_handle, buffer_rcode, 65);
			libusb_bulk_transfer(wlink_dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);
			if ((*(buffer_rcode + 0) == 0x41) && (*(buffer_rcode + 1) == 0x01) && (*(buffer_rcode + 2) == 0x01) && ((*(buffer_rcode + 3) == 0x02) || (*(buffer_rcode + 3) == 0x04)))
			{
			}
			else
			{
				LOG_ERROR(" PROGRAM FAILED");
				return ERROR_FAIL;
			}
		}
	}
	return ERROR_OK;
}

void wlink_armquitreset(struct cmsis_dap *dap)
{
	int transferred =0;
	uint8_t resetbuffer[] = {0x81, 0x0b, 0x01, 0x00};
	uint8_t buffer_rcode[4];
	// hid_write(wlink_dev_handle, resetbuffer, 65);
	// hid_read(wlink_dev_handle, buffer_rcode, 65);
    libusb_bulk_transfer(dap->bdata->dev_handle, 0x02,resetbuffer,sizeof(resetbuffer),&transferred,timeout);
	int ret=libusb_bulk_transfer(dap->bdata->dev_handle, 0x83,buffer_rcode,sizeof(buffer_rcode),&transferred,timeout);


}































COMMAND_HANDLER(cmsis_dap_handle_usb_interface_command)
{
	if (CMD_ARGC == 1)
		COMMAND_PARSE_NUMBER(int, CMD_ARGV[0], cmsis_dap_usb_interface);
	else
		LOG_ERROR("expected exactly one argument to cmsis_dap_usb_interface <interface_number>");

	return ERROR_OK;
}

const struct command_registration cmsis_dap_usb_subcommand_handlers[] = {
	{
		.name = "interface",
		.handler = &cmsis_dap_handle_usb_interface_command,
		.mode = COMMAND_CONFIG,
		.help = "set the USB interface number to use (for USB bulk backend only)",
		.usage = "<interface_number>",
	},
	COMMAND_REGISTRATION_DONE
};

const struct cmsis_dap_backend cmsis_dap_usb_backend = {
	.name = "usb_bulk",
	.open = cmsis_dap_usb_open,
	.close = cmsis_dap_usb_close,
	.read = cmsis_dap_usb_read,
	.write = cmsis_dap_usb_write,
	.packet_buffer_alloc = cmsis_dap_usb_alloc,
};
