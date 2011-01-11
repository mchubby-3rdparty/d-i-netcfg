/* Static network configurator module for netcfg.
 *
 * Licensed under the terms of the GNU General Public License
 */

#include "netcfg.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <debian-installer.h>
#include <assert.h>

static void netcfg_calculate_network_address(struct in_addr *network,
                                             const struct in_addr ipaddress,
                                             const struct in_addr netmask)
{
    network->s_addr = ipaddress.s_addr & netmask.s_addr;
}

static void netcfg_calculate_broadcast_address(struct in_addr *broadcast,
                                               const struct in_addr network,
                                               const struct in_addr netmask)
{
    broadcast->s_addr = (network.s_addr | ~netmask.s_addr);
}

/* Validate that the given gateway address actually lies within the given
 * network.  Standard boolean return.
 */
static int netcfg_gateway_reachable(const struct in_addr network,
                                    const struct in_addr netmask,
                                    const char *gateway)
{
    struct in_addr gw_addr;
    
    inet_pton(AF_INET, gateway, &gw_addr);

    return (gw_addr.s_addr && ((gw_addr.s_addr & netmask.s_addr) == network.s_addr));
}

int netcfg_get_ipaddress(struct debconfclient *client, struct in_addr *ipaddress)
{
    int ret, ok = 0;

    while (!ok) {
        debconf_input (client, "critical", "netcfg/get_ipaddress");
        ret = debconf_go (client);

        if (ret)
            return ret;

        debconf_get(client, "netcfg/get_ipaddress");
        ok = inet_pton (AF_INET, client->value, ipaddress);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_capb(client, "backup");
            debconf_go (client);
        }
    }

    return 0;
}

int netcfg_get_pointopoint(struct debconfclient *client, struct in_addr *pointopoint)
{
    int ret, ok = 0;

    while (!ok) {
        debconf_input(client, "critical", "netcfg/get_pointopoint");
        ret = debconf_go(client);

        if (ret)
            return ret;

        debconf_get(client, "netcfg/get_pointopoint");

        if (empty_str(client->value)) {           /* No P-P is ok */
            memset(pointopoint, 0, sizeof(struct in_addr));
            return 0;
        }

        ok = inet_pton (AF_INET, client->value, pointopoint);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_go (client);
            debconf_capb(client, "backup");
        }
    }

    return 0;
}

int netcfg_get_netmask(struct debconfclient *client, struct in_addr *netmask)
{
    int ret, ok = 0;

    while (!ok) {
        debconf_input (client, "critical", "netcfg/get_netmask");
        ret = debconf_go(client);

        if (ret)
            return ret;

        debconf_get (client, "netcfg/get_netmask");

        ok = inet_pton (AF_INET, client->value, netmask);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_go (client);
            debconf_capb(client, "backup");
        }
    }

    return 0;
}

static void netcfg_preseed_gateway(struct debconfclient *client,
                                   struct in_addr ipaddress,
                                   struct in_addr netmask)
{
    char ptr1[INET_ADDRSTRLEN];
    struct in_addr gw_addr;
    
    /* Calculate a potentially-sensible 'default' default gateway,
     * based on 'the first IP in the subnet' */
    gw_addr.s_addr = ipaddress.s_addr & netmask.s_addr;
    gw_addr.s_addr |= htonl(1);

    inet_ntop (AF_INET, &gw_addr, ptr1, sizeof (ptr1));

    /* if your chosen static IP address happens to be what we calculated for
     * the 'default' gateway, obviously that isn't going to work, so stop
     * guessing, just chop off the last octet, and let the user fill in the blank.
     *
     * This won't quite work with anything shorter than a /24; such is life.
     */
    if (gw_addr.s_addr == ipaddress.s_addr) {
        char* ptr = strrchr(ptr1, '.');
        assert (ptr); /* if there's no dot in ptr1 we're in deep shit */
        ptr[1] = '\0';
    }

    debconf_get(client, "netcfg/get_gateway");
    if (empty_str(client->value))
        debconf_set(client, "netcfg/get_gateway", ptr1);
}

int netcfg_get_gateway(struct debconfclient *client, char *gateway)
{
    struct in_addr gw_addr;
    int ret, ok = 0;
    char *ptr;

    while (!ok) {
        debconf_input (client, "critical", "netcfg/get_gateway");
        ret = debconf_go(client);

        if (ret)
            return ret;

        debconf_get(client, "netcfg/get_gateway");
        ptr = client->value;

        if (empty_str(ptr) || /* No gateway, that's fine */
            (strcmp(ptr, "none") == 0)) /* special case for preseeding */ {
            /* clear existing gateway setting */
            gateway[0] = '\0';
            return 0;
        }

        ok = inet_pton (AF_INET, ptr, &gw_addr);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_go (client);
            debconf_capb(client, "backup");
        } else {
            /* Double conversion to ensure that the address is in a normalised,
             * more readable form, in case the user entered something weird
             * looking.
             */
            inet_ntop(AF_INET, &gw_addr, gateway, INET_ADDRSTRLEN);
        }
    }

    return 0;
}

static int netcfg_write_static(char *domain,
                               struct in_addr ipaddress,
                               struct in_addr pointopoint,
                               char *gateway,
                               struct in_addr netmask,
                               char nameservers[][INET_ADDRSTRLEN],
                               unsigned int ns_size)
{
    char ptr1[INET_ADDRSTRLEN];
    FILE *fp;
    struct in_addr network;
    struct in_addr broadcast;

    netcfg_calculate_network_address(&network, ipaddress, netmask);
    netcfg_calculate_broadcast_address(&broadcast, network, netmask);

    if ((fp = file_open(NETWORKS_FILE, "w"))) {
        fprintf(fp, "default\t\t0.0.0.0\n");
        fprintf(fp, "loopback\t127.0.0.0\n");
        fprintf(fp, "link-local\t169.254.0.0\n");
        fprintf(fp, "localnet\t%s\n", inet_ntop (AF_INET, &network, ptr1, sizeof (ptr1)));
        fclose(fp);
    } else
        goto error;

    if ((fp = file_open(INTERFACES_FILE, "a"))) {
        fprintf(fp, "\n# The primary network interface\n");
        if (!iface_is_hotpluggable(interface) && !find_in_stab(interface))
            fprintf(fp, "auto %s\n", interface);
        else
            fprintf(fp, "allow-hotplug %s\n", interface);
        fprintf(fp, "iface %s inet static\n", interface);
        fprintf(fp, "\taddress %s\n", inet_ntop (AF_INET, &ipaddress, ptr1, sizeof (ptr1)));
        fprintf(fp, "\tnetmask %s\n", pointopoint.s_addr ? "255.255.255.255" : inet_ntop (AF_INET, &netmask, ptr1, sizeof (ptr1)));
        fprintf(fp, "\tnetwork %s\n", inet_ntop (AF_INET, &network, ptr1, sizeof (ptr1)));
        fprintf(fp, "\tbroadcast %s\n", inet_ntop (AF_INET, &broadcast, ptr1, sizeof (ptr1)));
        if (!empty_str(gateway))
            fprintf(fp, "\tgateway %s\n", pointopoint.s_addr ? inet_ntop (AF_INET, &pointopoint, ptr1, sizeof (ptr1)) : gateway);
        if (pointopoint.s_addr)
            fprintf(fp, "\tpointopoint %s\n", inet_ntop (AF_INET, &pointopoint, ptr1, sizeof (ptr1)));
        /*
         * Write wireless-tools options
         */
        if (is_wireless_iface(interface)) {
            fprintf(fp, "\t# wireless-* options are implemented by the wireless-tools package\n");
            fprintf(fp, "\twireless-mode %s\n",
                    (mode == MANAGED) ? "managed" : "ad-hoc");
            fprintf(fp, "\twireless-essid %s\n",
                    (essid && *essid) ? essid : "any");

            if (wepkey != NULL)
                fprintf(fp, "\twireless-key1 %s\n", wepkey);
        }
        /*
         * Write resolvconf options
         *
         * This is useful for users who intend to install resolvconf
         * after the initial installation.
         *
         * This code should be kept in sync with the code that writes
         * this information to the /etc/resolv.conf file.  If netcfg
         * becomes capable of configuring multiple network interfaces
         * then the user should be asked for dns information on a
         * per-interface basis so that per-interface dns options
         * can be written here.
         */
        if (nameservers[0][0] || (domain && !empty_str(domain))) {
            unsigned int i = 0;
            fprintf(fp, "\t# dns-* options are implemented by the resolvconf package, if installed\n");
            if (nameservers[0][0]) {
                fprintf(fp, "\tdns-nameservers");
                for (i = 0; i < ns_size; i++) {
                    if (nameservers[i][0]) {
                        fprintf(fp, " %s", nameservers[i]);
                    }
                }
                fprintf(fp, "\n");
            }
            if (domain && !empty_str(domain))
                fprintf(fp, "\tdns-search %s\n", domain);
        }
        fclose(fp);
    } else
        goto error;

    if (netcfg_write_resolv(domain, nameservers, ns_size))
        goto error;

    return 0;
error:
    return -1;
}

int netcfg_write_resolv (char* domain, char nameservers[][INET_ADDRSTRLEN], unsigned int ns_size)
{
    FILE* fp = NULL;

    if ((fp = file_open(RESOLV_FILE, "w"))) {
        unsigned int i = 0;
        if (domain && !empty_str(domain))
            fprintf(fp, "search %s\n", domain);

        for (i = 0; i < ns_size; i++)
            if (nameservers[i][0])
                fprintf(fp, "nameserver %s\n", nameservers[i]);

        fclose(fp);
        return 0;
    }
    else
        return 1;
}

int netcfg_activate_static(struct debconfclient *client,
                           struct in_addr ipaddress,
                           const char *gateway,
                           struct in_addr pointopoint,
                           struct in_addr netmask)
{
    int rv = 0, masksize;
    char buf[256];
    char ptr1[INET_ADDRSTRLEN];
    struct in_addr network;
    struct in_addr broadcast;

    netcfg_calculate_network_address(&network, ipaddress, netmask);
    netcfg_calculate_broadcast_address(&broadcast, network, netmask);

#ifdef __GNU__
    snprintf(buf, sizeof(buf),
             "settrans -fgap /servers/socket/2 /hurd/pfinet --interface=%s --address=%s",
             interface, inet_ntop (AF_INET, &ipaddress, ptr1, sizeof (ptr1)));
    di_snprintfcat(buf, sizeof(buf), " --netmask=%s",
                   inet_ntop (AF_INET, &netmask, ptr1, sizeof (ptr1)));

    if (!empty_str(gateway))
        di_snprintfcat(buf, sizeof(buf), " --gateway=%s", gateway);

    buf[sizeof(buf) - 1] = '\0';

    /* NB: unfortunately we cannot use di_exec_shell_log() here, as the active
     * translator would capture its pipe and make it hang forever. */
    rv |= di_exec_shell(buf);

#elif defined(__FreeBSD_kernel__)
    deconfigure_network();
    
    loop_setup();
    interface_up(interface);
    
    /* Flush all previous addresses, routes */
    snprintf(buf, sizeof(buf), "ifconfig %s inet 0 down", interface);
    rv |= di_exec_shell_log(buf);
    
    snprintf(buf, sizeof(buf), "ifconfig %s up", interface);
    rv |= di_exec_shell_log(buf);
    
    snprintf(buf, sizeof(buf), "ifconfig %s %s",
             interface,
             inet_ntop (AF_INET, &ipaddress, ptr1, sizeof (ptr1)));
    
    /* avoid using a second buffer */
    di_snprintfcat(buf, sizeof(buf), " netmask %s",
                   pointopoint.s_addr ? "255.255.255.255" : inet_ntop (AF_INET, &netmask, ptr1, sizeof (ptr1)));

    /* avoid using a third buffer */
    di_snprintfcat(buf, sizeof(buf), " broadcast %s",
                   inet_ntop (AF_INET, &broadcast, ptr1, sizeof (ptr1)));
    
    di_info("executing: %s", buf);
    rv |= di_exec_shell_log(buf);
    
    if (pointopoint.s_addr) {
        snprintf(buf, sizeof(buf), "route add %s", 
                 inet_ntop (AF_INET, &pointopoint, ptr1, sizeof (ptr1)));
        /* avoid using a second buffer */
        di_snprintfcat(buf, sizeof(buf), "%s",
                       inet_ntop (AF_INET, &ipaddress, ptr1, sizeof (ptr1)));
        rv |= di_exec_shell_log(buf);
    } else if (!empty_str(gateway)) {
        snprintf(buf, sizeof(buf), "route add default %s", gateway);
        rv |= di_exec_shell_log(buf);
    }
#else
    deconfigure_network();

    loop_setup();
    interface_up(interface);

    /* Flush all previous addresses, routes */
    snprintf(buf, sizeof(buf), "ip -f inet addr flush dev %s", interface);
    rv |= di_exec_shell_log(buf);

    snprintf(buf, sizeof(buf), "ip -f inet route flush dev %s", interface);
    rv |= di_exec_shell_log(buf);

    rv |= !inet_ptom (NULL, &masksize, &netmask);

    /* Add the new IP address, P-t-P peer (if necessary) and netmask */
    snprintf(buf, sizeof(buf), "ip addr add %s/%d ",
             inet_ntop (AF_INET, &ipaddress, ptr1, sizeof (ptr1)),
             masksize);

    /* avoid using a second buffer */
    di_snprintfcat(buf, sizeof(buf), "broadcast %s dev %s",
                   inet_ntop (AF_INET, &broadcast, ptr1, sizeof (ptr1)),
                   interface);

    if (pointopoint.s_addr)
        di_snprintfcat(buf, sizeof(buf), " peer %s",
                       inet_ntop (AF_INET, &pointopoint, ptr1, sizeof (ptr1)));

    di_info("executing: %s", buf);
    rv |= di_exec_shell_log(buf);

    if (pointopoint.s_addr)
    {
        snprintf(buf, sizeof(buf), "ip route add default dev %s", interface);
        rv |= di_exec_shell_log(buf);
    }
    else if (!empty_str(gateway)) {
        snprintf(buf, sizeof(buf), "ip route add default via %s", gateway);
        rv |= di_exec_shell_log(buf);
    }
#endif

    if (rv != 0) {
        debconf_capb(client);
        debconf_input(client, "high", "netcfg/error");
        debconf_go(client);
        debconf_capb(client, "backup");
        return -1;
    }

    /* Wait to detect link.  Don't error out if we fail, though; link detection
     * may not work on this NIC or something.
     */
    netcfg_detect_link(client, interface, gateway);

    return 0;
}

int netcfg_get_static(struct debconfclient *client)
{
    char *nameservers = NULL;
    char gateway[INET_ADDRSTRLEN] = "";
    char ptr1[INET_ADDRSTRLEN];
    char nameserver_array[4][INET_ADDRSTRLEN];
    char *none;
    struct in_addr ipaddress;
    struct in_addr netmask;
    struct in_addr pointopoint;
    struct in_addr network;

    enum { BACKUP, GET_HOSTNAME, GET_IPADDRESS, GET_POINTOPOINT, GET_NETMASK,
           GET_GATEWAY, GATEWAY_UNREACHABLE, GET_NAMESERVERS, CONFIRM,
           GET_DOMAIN, QUIT }
    state = GET_IPADDRESS;

    ipaddress.s_addr = network.s_addr = netmask.s_addr = pointopoint.s_addr = 0;

    debconf_metaget(client,  "netcfg/internal-none", "description");
    none = client->value ? strdup(client->value) : strdup("<none>");

    for (;;) {
        switch (state) {
        case BACKUP:
            return 10; /* Back to main */
            break;

        case GET_IPADDRESS:
            if (netcfg_get_ipaddress (client, &ipaddress)) {
                state = BACKUP;
            } else {
                if (strncmp(interface, "plip", 4) == 0
                    || strncmp(interface, "slip", 4) == 0
                    || strncmp(interface, "ctc", 3) == 0
                    || strncmp(interface, "escon", 5) == 0
                    || strncmp(interface, "iucv", 4) == 0)
                    state = GET_POINTOPOINT;
                else
                    state = GET_NETMASK;
            }
            break;

        case GET_POINTOPOINT:
            state = netcfg_get_pointopoint(client, &pointopoint) ?
                GET_IPADDRESS : GET_NAMESERVERS;
            break;

        case GET_NETMASK:
            state = netcfg_get_netmask(client, &netmask) ?
                GET_IPADDRESS : GET_GATEWAY;
            break;

        case GET_GATEWAY:
            netcfg_preseed_gateway(client, ipaddress, netmask);
            if (netcfg_get_gateway(client, gateway))
                state = GET_NETMASK;
            else
                netcfg_calculate_network_address(&network, ipaddress, netmask);
                if (!netcfg_gateway_reachable(network, netmask, gateway))
                    state = GATEWAY_UNREACHABLE;
                else
                    state = GET_NAMESERVERS;
            break;
        case GATEWAY_UNREACHABLE:
            debconf_capb(client); /* Turn off backup */
            debconf_input(client, "high", "netcfg/gateway_unreachable");
            debconf_go(client);
            state = GET_GATEWAY;
            debconf_capb(client, "backup");
            break;
        case GET_NAMESERVERS:
            state = (netcfg_get_nameservers (client, &nameservers, gateway)) ?
                GET_GATEWAY : CONFIRM;
            break;
        case GET_HOSTNAME:
            seed_hostname_from_dns(client, &ipaddress);
            state = (netcfg_get_hostname(client, "netcfg/get_hostname", &hostname, 1)) ?
                GET_NAMESERVERS : GET_DOMAIN;
            break;
        case GET_DOMAIN:
            if (!have_domain) {
                state = (netcfg_get_domain (client, &domain)) ?
                    GET_HOSTNAME : QUIT;
            } else {
                di_info("domain = %s", domain);
                state = QUIT;
            }
            break;

        case CONFIRM:
            debconf_subst(client, "netcfg/confirm_static", "interface", interface);
            debconf_subst(client, "netcfg/confirm_static", "ipaddress",
                          (ipaddress.s_addr ? inet_ntop (AF_INET, &ipaddress, ptr1, sizeof (ptr1)) : none));
            debconf_subst(client, "netcfg/confirm_static", "pointopoint",
                          (pointopoint.s_addr ? inet_ntop (AF_INET, &pointopoint, ptr1, sizeof (ptr1)) : none));
            debconf_subst(client, "netcfg/confirm_static", "netmask",
                          (netmask.s_addr ? inet_ntop (AF_INET, &netmask, ptr1, sizeof (ptr1)) : none));
            debconf_subst(client, "netcfg/confirm_static", "gateway",
                          (empty_str(gateway) ? none : gateway));
            debconf_subst(client, "netcfg/confirm_static", "nameservers",
                          (nameservers ? nameservers : none));
            netcfg_nameservers_to_array(nameservers, nameserver_array, ARRAY_SIZE(nameserver_array));

            debconf_capb(client); /* Turn off backup for yes/no confirmation */

            debconf_input(client, "medium", "netcfg/confirm_static");
            debconf_go(client);
            debconf_get(client, "netcfg/confirm_static");
            if (strstr(client->value, "true")) {
                state = GET_HOSTNAME;
                netcfg_write_resolv(domain, nameserver_array, ARRAY_SIZE(nameserver_array));
                netcfg_activate_static(client, ipaddress, gateway, pointopoint, netmask);
            }
            else
                state = GET_IPADDRESS;

            debconf_capb(client, "backup");

            break;

        case QUIT:
            netcfg_write_common(ipaddress, hostname, domain);
            netcfg_write_static(domain, ipaddress, pointopoint, gateway, netmask, nameserver_array, ARRAY_SIZE(nameserver_array));
            return 0;
            break;
        }
    }
    return 0;
}
