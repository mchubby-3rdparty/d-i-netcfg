/*
 * IPv6-specific functions for netcfg.
 *
 * Licensed under the terms of the GNU General Public License
 */

#include "netcfg.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <debian-installer.h>

/* Examine the configuration of the given interface, and attempt to determine
 * if it has been assigned an interface via SLAAC.
 *
 * Returns 1 if we think we've got some SLAAC, and 0 otherwise.  Also set
 * interface->slaac to the appropriate boolean value.
 */
int nc_v6_get_slaac(struct netcfg_interface *interface)
{

#if defined(__FreeBSD_kernel__)
	return 0;
#else
	FILE *ipcmd;
	char l[256];
	char cmd[512];

	di_debug("Attempting to detect SLAAC for %s", interface->name);
	/* Start with the right default */
	interface->slaac = 0;

	snprintf(cmd, 512, "ip addr show %s", interface->name);
	
	if ((ipcmd = popen(cmd, "r")) != NULL) {
		while (fgets(l, 256, ipcmd) != NULL) {
			di_debug("ip line: %s", l);
			/* Aah, string manipulation in C.  What fun. */
			if (strncmp("    inet6 ", l, 10)) {
				continue;
			}
			if (!strstr(l, " scope global")) {
				continue;
			}
			if (!strstr(l, " dynamic")) {
				/* Hmm, a global address that isn't SLAAC?
				 * Strange at this point, but not what we're
				 * after.
				 */
				continue;
			}
			
			/* So, we've found a dynamically-assigned global
			 * inet6 address.  Sounds like SLAAC to me.
			 */
			di_info("Detected SLAAC is in use on %s", interface->name);
			interface->slaac = 1;
			interface->address_family = AF_INET6;
			break;
		}
	}

	pclose(ipcmd);
	return interface->slaac;
#endif
}
