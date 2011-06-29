/*
 * Interface autoconfiguration functions for netcfg.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "netcfg.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <debian-installer.h>

/* Configure the network using IPv6 router advertisements, and possibly
 * stateless DHCPv6 announcements (if appropriate).  Return 1 if all
 * went well, and 0 otherwise.
 */
static int netcfg_slaac(struct debconfclient *client, struct netcfg_interface *interface)
{
	const int SLAAC_MAX_WAIT = 5;  /* seconds */
	int count, rv = 0;
	
	/* STEP 1: Ensure the interface has finished configuring itself */

	/* Progress bar... fun! */
	debconf_capb(client, "progresscancel");
	debconf_progress_start(client, 0, SLAAC_MAX_WAIT * 4, "netcfg/slaac_wait_title");
	
	for (count = 0; count < SLAAC_MAX_WAIT * 4; count++) {
		usleep(250000);
		if (debconf_progress_step(client, 1) == 30) {
			/* User cancel */
			rv = 0;
			break;
		}
		if (nc_v6_interface_configured(interface, 0)) {
			debconf_progress_set(client, SLAAC_MAX_WAIT * 4);
			rv = 1;
			break;
		}
	}
	debconf_progress_stop(client);
	
	/* STEP 2: Stateless DHCP? */
	if (interface->v6_stateless_config) {
		FILE *cmdfd;
		char cmd[512], l[512], *p;
		int ns_idx, ntp_idx = 0;
		
		di_debug("Stateless DHCPv6 requested");

		/* Append any nameservers obtained via DHCP to the list of
		 * nameservers in the RA, rather than overwriting them
		 */
		ns_idx = nameserver_count(interface);
		
#if defined(__FreeBSD_kernel__)
		/* Sigh... wide (dhcp6c) is Linux-only, and dhclient is
		 * freaking huge...  so we have to use what's best where
		 * it's available.
		 */
		snprintf(cmd, sizeof(cmd), "dhclient -6 -S -sf /lib/netcfg/print-dhcpv6-info %s", interface->name);
#else
		snprintf(cmd, sizeof(cmd), "/lib/netcfg/dhcp6c-stateless %s", interface->name);
#endif
		if ((cmdfd = popen(cmd, "r")) != NULL) {
			while (fgets(l, sizeof(l), cmdfd) != NULL) {
				rtrim(l);
				di_debug("dhcp6c line: %s", l);
				
				if (!strncmp("nameserver[", l, 11) && ns_idx < NETCFG_NAMESERVERS_MAX) {
					p = strstr(l, "] ") + 2;
					strncpy(interface->nameservers[ns_idx], p, sizeof(interface->nameservers[ns_idx]));
					ns_idx++;
				} else if (!strncmp("NTP server[", l, 11) && ntp_idx < NETCFG_NTPSERVERS_MAX) {
					p = strstr(l, "] ") + 2;
					strncpy(interface->ntp_servers[ns_idx++], p, sizeof(interface->ntp_servers[ntp_idx]));
					ntp_idx++;
				} else if (!strncmp("Domain search list[0] ", l, 21)) {
					p = strstr(l, "] ") + 2;
					strncpy(domain, p, sizeof(domain));
					/* Strip trailing . */
					if (domain[strlen(domain)-1] == '.') {
						domain[strlen(domain)-1] = '\0';
					}
					have_domain = 1;
				}
			}
			
			pclose(cmdfd);
			/* Empty any other nameservers/NTP servers that might
			 * have been left over from a previous config run
			 */
			for (; ns_idx < NETCFG_NAMESERVERS_MAX; ns_idx++) {
				*(interface->nameservers[ns_idx]) = '\0';
			}
			for (; ntp_idx < NETCFG_NTPSERVERS_MAX; ntp_idx++) {
				*(interface->ntp_servers[ntp_idx]) = '\0';
			}
		}
	}

	return rv;
}

/* Configure the interface using stateful DHCPv6.
 * FIXME: Not yet implemented.
 */
static int netcfg_dhcpv6(struct debconfclient *client, struct netcfg_interface *interface)
{
	(void) client;
	(void) interface;
	
	di_warning("Stateful DHCPv6 is not yet supported");
	
	return 0;
}

/* This function handles all of the autoconfiguration for the given interface.
 *
 * Autoconfiguration of an interface in netcfg has grown significantly
 * in recent times.  From humble beginnings that started with "yeah, just
 * fire up udhcpc and see what happens", the scope has expanded to
 * include all manner of IPv6 gubbins.
 *
 * Hence, this function exists to wrap all of that into a single neat
 * package.  If you want to autoconfigure an interface, just run it through
 * this, and if autoconfiguration was successful to at least the point of
 * assigning an IP address, we will return a healthy bouncing baby '1' to
 * you.  Otherwise, we'll give you the bad news with a '0' -- and you'll
 * either have to try another interface, or manually configure it.
 *
 * Note that we only guarantee that you'll have an IP address as a result
 * of successful completion.  You'll need to check what else has been
 * configured (gateway, hostname, etc) and respond to the user appropriately.
 * Also, the fields in +interface+ that deal directly with IP address,
 * gateway, etc will *not* be populated -- just the flags that talk about
 * what sort of autoconfiguration was completed.
 */
int netcfg_autoconfig(struct debconfclient *client, struct netcfg_interface *interface)
{
	int ipv6, rv;

	di_debug("Want link on %s", interface->name);
	netcfg_detect_link(client, interface);

	di_debug("Commencing network autoconfiguration on %s", interface->name);
	
	/* We need to start rdnssd before anything else, because it never
	 * sends it's own ND packets, it just watches for ones already
	 * on the wire.  Thankfully, the use of rdisc6 in
	 * nc_v6_get_config_flags() will send NDs for us.
	 */
	start_rdnssd(client);

	/* Now we prod the network to see what is available */
	ipv6 = nc_v6_get_config_flags(client, interface);

	/* And now we cleanup from rdnssd */
	if (ipv6) {
		read_rdnssd_nameservers(interface);
		if (nameserver_count(interface) > 0) {
			di_exec_shell_log("apt-install rdnssd");
		}
	}
	
	stop_rdnssd();

	if (!ipv6) {
		/* No RA was received; assuming that IPv6 is not available
		 * on this network and falling back to IPv4
		 */
		di_debug("No RA received; attempting IPv4 autoconfig");
		rv = netcfg_dhcp(client, interface);
		if (rv) {
			interface->dhcp = 1;
			interface->slaac = 0;
			interface->dhcpv6 = 0;
		}
	} else {
		di_debug("IPv6 found");
		if (interface->v6_stateful_config == 1) {
			di_debug("IPv6 stateful autoconfig requested");
			rv = netcfg_dhcpv6(client, interface);
			if (rv) {
				interface->dhcp = 0;
				interface->slaac = 0;
				interface->dhcpv6 = 1;
			}
		} else {
			di_debug("IPv6 stateless autoconfig requested");
			rv = netcfg_slaac(client, interface);
			if (rv) {
				interface->dhcp = 0;
				interface->slaac = 1;
				interface->dhcpv6 = 0;
			}
		}
	}
	
	return rv;
}
