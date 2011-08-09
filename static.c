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

static int netcfg_get_ipaddress(struct debconfclient *client, struct netcfg_interface *interface)
{
    int ret, ok = 0;

    while (!ok) {
        debconf_input (client, "critical", "netcfg/get_ipaddress");
        ret = debconf_go (client);

        if (ret)
            return ret;

        debconf_get(client, "netcfg/get_ipaddress");
        ok = netcfg_parse_cidr_address(client->value, interface);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_capb(client, "backup");
            debconf_go (client);
        }
    }

    return 0;
}

static int netcfg_get_pointopoint(struct debconfclient *client, struct netcfg_interface *interface)
{
    int ret, ok = 0;
    union inX_addr addr;
    
    while (!ok) {
        debconf_input(client, "critical", "netcfg/get_pointopoint");
        ret = debconf_go(client);

        if (ret)
            return ret;

        debconf_get(client, "netcfg/get_pointopoint");

        if (empty_str(client->value)) {           /* No P-P is ok */
            interface->pointopoint[0] = '\0';
            return 0;
        }

        ok = inet_pton (interface->address_family, client->value, &addr);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_go (client);
            debconf_capb(client, "backup");
        }
    }

    inet_ntop(interface->address_family, &addr, interface->pointopoint, NETCFG_ADDRSTRLEN);
    return 0;
}

static int netcfg_get_netmask(struct debconfclient *client, struct netcfg_interface *interface)
{
    int ret, ok = 0;
    union inX_addr addr;

    /* Preseed a vaguely sensible looking default netmask if one wasn't
     * provided.
     */
    debconf_get (client, "netcfg/get_netmask");
    if (empty_str(client->value)) {
        if (interface->address_family == AF_INET) {
            debconf_set(client, "netcfg/get_netmask", "255.255.255.0");
        } else if (interface->address_family == AF_INET6) {
            debconf_set(client, "netcfg/get_netmask", "ffff:ffff:ffff:ffff::");
        }
    }
    
    while (!ok) {
        debconf_input (client, "critical", "netcfg/get_netmask");
        ret = debconf_go(client);

        if (ret)
            return ret;

        debconf_get (client, "netcfg/get_netmask");

        ok = inet_pton (interface->address_family, client->value, &addr);

        if (!ok) {
            debconf_capb(client);
            debconf_input (client, "critical", "netcfg/bad_ipaddress");
            debconf_go (client);
            debconf_capb(client, "backup");
        }
    }

    inet_ptom(interface->address_family, client->value, &(interface->masklen));
    return 0;
}

static void netcfg_preseed_gateway(struct debconfclient *client,
                                   struct netcfg_interface *iface)
{
    char ptr1[NETCFG_ADDRSTRLEN];
    union inX_addr gw_addr, ipaddr, mask;
    
    inet_pton(iface->address_family, iface->ipaddress, &ipaddr);
    inet_mton(iface->address_family, iface->masklen, &mask);
    
    /* Calculate a potentially-sensible 'default' default gateway,
     * based on 'the first IP in the subnet' */
    if (iface->address_family == AF_INET) {
        gw_addr.in4.s_addr = ipaddr.in4.s_addr & mask.in4.s_addr;
        gw_addr.in4.s_addr |= htonl(1);
    } else if (iface->address_family == AF_INET6) {
        int i;
        for (i = 0; i < 4; i++) {
            gw_addr.in6.s6_addr32[i] = ipaddr.in6.s6_addr32[i] & mask.in6.s6_addr32[i];
        }
        gw_addr.in6.s6_addr32[3] |= htonl(1);
    }

    inet_ntop (iface->address_family, &gw_addr, ptr1, NETCFG_ADDRSTRLEN);

    /* if your chosen static IP address happens to be what we calculated for
     * the 'default' gateway, obviously that isn't going to work, so stop
     * guessing, just chop off the last octet, and let the user fill in the blank.
     *
     * This won't *quite* work with anything shorter than a /24; such is life.
     */
    if (!strcmp(iface->ipaddress, ptr1)) {
        char *ptr = strrchr(ptr1, iface->address_family == AF_INET6 ? ':' : '.');
        assert (ptr); /* if there's no separator in ptr1 we're in deep shit */
        ptr[1] = '\0';
    }

    debconf_get(client, "netcfg/get_gateway");
    if (empty_str(client->value))
        debconf_set(client, "netcfg/get_gateway", ptr1);
}

static int netcfg_get_gateway(struct debconfclient *client, struct netcfg_interface *interface)
{
    union inX_addr gw_addr;
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
            interface->gateway[0] = '\0';
            return 0;
        }

        ok = inet_pton (interface->address_family, ptr, &gw_addr);

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
            inet_ntop(interface->address_family, &gw_addr, interface->gateway, NETCFG_ADDRSTRLEN);
        }
    }

    return 0;
}

static int netcfg_write_etc_networks(char *network)
{
    FILE *fp;
    
    if ((fp = file_open(NETWORKS_FILE, "w"))) {
        fprintf(fp, "default\t\t0.0.0.0\n");
        fprintf(fp, "loopback\t127.0.0.0\n");
        fprintf(fp, "link-local\t169.254.0.0\n");
        if (network) {
            fprintf(fp, "localnet\t%s\n", network);
        }
        fclose(fp);
        return 1;
    } else {
        return 0;
    }
}

static int netcfg_write_wireless_options(const struct netcfg_interface *interface)
{
    FILE *fp;

    /*
     * Write wireless-tools options
     */
    if (is_wireless_iface(interface->name)) {
        if (!(fp = file_open(INTERFACES_FILE, "a"))) {
            return 0;
        }
        fprintf(fp, "\t# wireless-* options are implemented by the wireless-tools package\n");
        fprintf(fp, "\twireless-mode %s\n",
                (interface->mode == MANAGED) ? "managed" : "ad-hoc");
        fprintf(fp, "\twireless-essid %s\n",
                (interface->essid && *interface->essid) ? interface->essid : "any");

        if (interface->wepkey != NULL)
            fprintf(fp, "\twireless-key1 %s\n", interface->wepkey);
        
        fclose(fp);
    }

    return 1;
}

static int netcfg_write_resolvconf_options(const char *domain,
                                           char nameservers[][NETCFG_ADDRSTRLEN],
                                           const unsigned int ns_size
                                          )
{
    FILE *fp;

    if (!(fp = file_open(INTERFACES_FILE, "a"))) {
        return 0;
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
    if (!empty_str(nameservers[0]) || (domain && !empty_str(domain))) {
        unsigned int i = 0;
        fprintf(fp, "\t# dns-* options are implemented by the resolvconf package, if installed\n");
        if (!empty_str(nameservers[0])) {
            fprintf(fp, "\tdns-nameservers");
            for (i = 0; i < ns_size; i++) {
                if (!empty_str(nameservers[i])) {
                    fprintf(fp, " %s", nameservers[i]);
                }
            }
            fprintf(fp, "\n");
        }
        if (domain && !empty_str(domain))
            fprintf(fp, "\tdns-search %s\n", domain);
    }

    fclose(fp);
    
    return 1;
}

static int netcfg_write_static_ipv4(char *domain,
                                    const struct netcfg_interface *interface,
                                    char nameservers[][NETCFG_ADDRSTRLEN],
                                    const unsigned int ns_size)
{
    FILE *fp;
    char network[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];

    netcfg_network_address(interface, network);
    netcfg_broadcast_address(interface, broadcast);
    inet_mtop(AF_INET, interface->masklen, netmask, INET_ADDRSTRLEN);

    if (!netcfg_write_etc_networks(network))
        goto error;

    if ((fp = file_open(INTERFACES_FILE, "a"))) {
        fprintf(fp, "\n# The primary network interface\n");
        if (!iface_is_hotpluggable(interface->name) && !find_in_stab(interface->name))
            fprintf(fp, "auto %s\n", interface->name);
        else
            fprintf(fp, "allow-hotplug %s\n", interface->name);
        fprintf(fp, "iface %s inet static\n", interface->name);
        fprintf(fp, "\taddress %s\n", interface->ipaddress);
        fprintf(fp, "\tnetmask %s\n", empty_str(interface->pointopoint) ? netmask : "255.255.255.255");
        fprintf(fp, "\tnetwork %s\n", network);
        fprintf(fp, "\tbroadcast %s\n", broadcast);
        if (!empty_str(interface->gateway))
            fprintf(fp, "\tgateway %s\n",
                    empty_str(interface->pointopoint) ? interface->gateway : interface->pointopoint);
        if (!empty_str(interface->pointopoint))
            fprintf(fp, "\tpointopoint %s\n", interface->pointopoint);

        fclose(fp);

        if (!netcfg_write_wireless_options(interface)) {
            goto error;
        }
        
        if (!netcfg_write_resolvconf_options(domain, nameservers, ns_size)) {
	    goto error;
        }
    } else
        goto error;

    if (!netcfg_write_resolv(domain, nameservers, ns_size))
        goto error;

    return 0;
error:
    return -1;
}

static int netcfg_write_static_ipv6(char *domain,
                                    const struct netcfg_interface *interface,
                                    char nameservers[][NETCFG_ADDRSTRLEN],
                                    const unsigned int ns_size)
{
    FILE *fp;

    if (!netcfg_write_etc_networks(NULL))
        goto error;

    if ((fp = file_open(INTERFACES_FILE, "a"))) {
        fprintf(fp, "\n# The primary network interface\n");
        if (!iface_is_hotpluggable(interface->name) && !find_in_stab(interface->name))
            fprintf(fp, "auto %s\n", interface->name);
        else
            fprintf(fp, "allow-hotplug %s\n", interface->name);
        fprintf(fp, "iface %s inet6 static\n", interface->name);
        fprintf(fp, "\taddress %s\n", interface->ipaddress);
        fprintf(fp, "\tnetmask %i\n", interface->masklen);
        if (!empty_str(interface->gateway))
            fprintf(fp, "\tgateway %s\n", interface->gateway);

        fclose(fp);

        if (!netcfg_write_wireless_options(interface)) {
            goto error;
        }
        
        if (!netcfg_write_resolvconf_options(domain, nameservers, ns_size)) {
	    goto error;
        }
    } else
        goto error;

    if (netcfg_write_resolv(domain, nameservers, ns_size))
        goto error;

    return 0;
error:
    return -1;
}

static int netcfg_write_static(char *domain,
                               const struct netcfg_interface *interface,
                               char nameservers[][NETCFG_ADDRSTRLEN],
                               const unsigned int ns_size)
{
    if (interface->address_family == AF_INET) {
        return netcfg_write_static_ipv4(domain, interface, nameservers, ns_size);
    } else if (interface->address_family == AF_INET6) {
        return netcfg_write_static_ipv6(domain, interface, nameservers, ns_size);
    } else {
        fprintf(stderr, "Can't happen: unknown address family\n");
        return -1;
    }
}

int netcfg_write_resolv (const char *domain, char nameservers[][NETCFG_ADDRSTRLEN], const unsigned int ns_size)
{
    FILE* fp = NULL;

    if ((fp = file_open(RESOLV_FILE, "w"))) {
        unsigned int i = 0;
        if (domain && !empty_str(domain))
            fprintf(fp, "search %s\n", domain);

        for (i = 0; i < ns_size; i++)
            if (!empty_str(nameservers[i]))
                fprintf(fp, "nameserver %s\n", nameservers[i]);

        fclose(fp);
        return 1;
    }
    else
        return 0;
}

static int netcfg_activate_static_ipv4(struct debconfclient *client,
                                       const struct netcfg_interface *interface)
{
    int rv = 0;
    char buf[256];
    char network[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];

    netcfg_network_address(interface, network);
    netcfg_broadcast_address(interface, broadcast);
    inet_mtop(AF_INET, interface->masklen, netmask, INET_ADDRSTRLEN);

#ifdef __GNU__
    snprintf(buf, sizeof(buf),
             "settrans -fgap /servers/socket/2 /hurd/pfinet --interface=%s --address=%s",
             interface->name, interface->ipaddress);
    di_snprintfcat(buf, sizeof(buf), " --netmask=%s", netmask);

    if (!empty_str(interface->gateway))
        di_snprintfcat(buf, sizeof(buf), " --gateway=%s", interface->gateway);

    buf[sizeof(buf) - 1] = '\0';

    /* NB: unfortunately we cannot use di_exec_shell_log() here, as the active
     * translator would capture its pipe and make it hang forever. */
    rv |= di_exec_shell(buf);

#elif defined(__FreeBSD_kernel__)
    deconfigure_network();

    loop_setup();
    interface_up(interface->name);

    /* Flush all previous addresses, routes */
    snprintf(buf, sizeof(buf), "ifconfig %s inet 0 down", interface->name);
    rv |= di_exec_shell_log(buf);

    snprintf(buf, sizeof(buf), "ifconfig %s up", interface->name);
    rv |= di_exec_shell_log(buf);

    snprintf(buf, sizeof(buf), "ifconfig %s %s",
             interface->name, interface->ipaddress);
    
    /* avoid using a second buffer */
    di_snprintfcat(buf, sizeof(buf), " netmask %s",
                   empty_str(interface->pointopoint) ? netmask : "255.255.255.255");

    /* avoid using a third buffer */
    di_snprintfcat(buf, sizeof(buf), " broadcast %s", broadcast);
    
    di_info("executing: %s", buf);
    rv |= di_exec_shell_log(buf);
    
    if (!empty_str(interface->pointopoint)) {
        snprintf(buf, sizeof(buf), "route add %s", interface->pointopoint);
        /* avoid using a second buffer */
        di_snprintfcat(buf, sizeof(buf), "%s", interface->ipaddress);
        rv |= di_exec_shell_log(buf);
    } else if (!empty_str(interface->gateway)) {
        snprintf(buf, sizeof(buf), "route add default %s", interface->gateway);
        rv |= di_exec_shell_log(buf);
    }
#else
    deconfigure_network(NULL);

    loop_setup();
    interface_up(interface->name);

    /* Flush all previous addresses, routes */
    snprintf(buf, sizeof(buf), "ip -f inet addr flush dev %s", interface->name);
    rv |= di_exec_shell_log(buf);

    snprintf(buf, sizeof(buf), "ip -f inet route flush dev %s", interface->name);
    rv |= di_exec_shell_log(buf);

    /* Add the new IP address, P-t-P peer (if necessary) and netmask */
    snprintf(buf, sizeof(buf), "ip addr add %s/%d ", interface->ipaddress, interface->masklen);

    /* avoid using a second buffer */
    di_snprintfcat(buf, sizeof(buf), "broadcast %s dev %s", broadcast, interface->name);

    if (!empty_str(interface->pointopoint))
        di_snprintfcat(buf, sizeof(buf), " peer %s", interface->pointopoint);

    di_info("executing: %s", buf);
    rv |= di_exec_shell_log(buf);

    if (!empty_str(interface->pointopoint))
    {
        snprintf(buf, sizeof(buf), "ip route add default dev %s", interface->name);
        rv |= di_exec_shell_log(buf);
    }
    else if (!empty_str(interface->gateway)) {
        snprintf(buf, sizeof(buf), "ip route add default via %s", interface->gateway);
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
    netcfg_detect_link(client, interface);

    return 0;
}

static int netcfg_activate_static_ipv6(struct debconfclient *client,
                                       const struct netcfg_interface *interface)
{
    int rv = 0;
    char buf[1024];

#ifdef __GNU__
    snprintf(buf, sizeof(buf),
             "settrans -fgap /servers/socket/2 /hurd/pfinet --interface=%s -A %s/%i",
             interface->name, interface->ipaddress, interface->masklen);

    if (!empty_str(interface->gateway))
        di_snprintfcat(buf, sizeof(buf), " -G %s", interface->gateway);

    buf[sizeof(buf) - 1] = '\0';

    /* NB: unfortunately we cannot use di_exec_shell_log() here, as the active
     * translator would capture its pipe and make it hang forever. */
    rv |= di_exec_shell(buf);

    /* Apparently you need to setup the same thing on two separate sockets
     * if you're doing IPv6.  No wonder nobody uses Hurd.
     */
    snprintf(buf, sizeof(buf),
             "settrans -fgap /servers/socket/26 /hurd/pfinet --interface=%s -A %s/%i",
             interface->name, interface->ipaddress, interface->masklen);

    if (!empty_str(interface->gateway))
        di_snprintfcat(buf, sizeof(buf), " -G %s", interface->gateway);

    buf[sizeof(buf) - 1] = '\0';

    rv |= di_exec_shell(buf);

#elif defined(__FreeBSD_kernel__)
    deconfigure_network(NULL);
    
    loop_setup();
    interface_up(interface->name);
    
    /* Flush all previous addresses, routes */
    snprintf(buf, sizeof(buf), "ifconfig %s inet 0 down", interface->name);
    rv |= di_exec_shell_log(buf);
    
    snprintf(buf, sizeof(buf), "ifconfig %s up", interface->name);
    rv |= di_exec_shell_log(buf);
    
    snprintf(buf, sizeof(buf), "ifconfig %s inet6 %s prefixlen %i",
             interface->name, interface->ipaddress, interface->masklen);
    
    di_info("executing: %s", buf);
    rv |= di_exec_shell_log(buf);
    
    if (!empty_str(interface->gateway)) {
        snprintf(buf, sizeof(buf), "/lib/freebsd/route add -inet6 default %s", interface->gateway);
        rv |= di_exec_shell_log(buf);
    }
#else
    deconfigure_network(NULL);

    loop_setup();
    interface_up(interface->name);

    /* Flush all previous addresses, routes */
    snprintf(buf, sizeof(buf), "ip -f inet6 addr flush dev %s", interface->name);
    rv |= di_exec_shell_log(buf);

    snprintf(buf, sizeof(buf), "ip -f inet6 route flush dev %s", interface->name);
    rv |= di_exec_shell_log(buf);

    /* Now down and up the interface, to get LL and SLAAC addresses back,
     * since flushing the addresses and routes gets rid of all that
     * sort of thing. */
    interface_down(interface->name);
    interface_up(interface->name);

    /* Add the new IP address and netmask */
    snprintf(buf, sizeof(buf), "ip addr add %s/%d dev %s",
                               interface->ipaddress,
                               interface->masklen,
                               interface->name);

    di_info("executing: %s", buf);
    rv |= di_exec_shell_log(buf);

    if (!empty_str(interface->gateway)) {
        snprintf(buf, sizeof(buf), "ip route add default via %s", interface->gateway);
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

    return 0;
}

static int netcfg_activate_static(struct debconfclient *client,
                                  const struct netcfg_interface *interface)
{
    if (interface->address_family == AF_INET) {
        return netcfg_activate_static_ipv4(client, interface);
    } else if (interface->address_family == AF_INET6) {
        return netcfg_activate_static_ipv6(client, interface);
    } else {
        fprintf(stderr, "Can't happen: unknown address family");
        return -1;
    }
}

int netcfg_get_static(struct debconfclient *client, struct netcfg_interface *iface)
{
    char *nameservers = NULL;
    char nameserver_array[4][NETCFG_ADDRSTRLEN];
    char *none;
    char netmask[INET_ADDRSTRLEN];

    enum { BACKUP, GET_HOSTNAME, GET_IPADDRESS, GET_POINTOPOINT, GET_NETMASK,
           GET_GATEWAY, GATEWAY_UNREACHABLE, GET_NAMESERVERS, CONFIRM,
           GET_DOMAIN, QUIT }
    state = GET_IPADDRESS;

    debconf_metaget(client,  "netcfg/internal-none", "description");
    none = client->value ? strdup(client->value) : strdup("<none>");

    for (;;) {
        switch (state) {
        case BACKUP:
            return RETURN_TO_MAIN;
            break;

        case GET_IPADDRESS:
            if (netcfg_get_ipaddress (client, iface)) {
                state = BACKUP;
            } else {
                if (strncmp(iface->name, "plip", 4) == 0
                    || strncmp(iface->name, "slip", 4) == 0
                    || strncmp(iface->name, "ctc", 3) == 0
                    || strncmp(iface->name, "escon", 5) == 0
                    || strncmp(iface->name, "iucv", 4) == 0)
                    state = GET_POINTOPOINT;
                else if (iface->masklen == 0) {
                    state = GET_NETMASK;
                } else {
                    state = GET_GATEWAY;
                }
            }
            break;

        case GET_POINTOPOINT:
            if (iface->address_family == AF_INET6) {
                debconf_capb(client); /* Turn off backup */
                debconf_input(client, "high", "netcfg/no_ipv6_pointopoint");
                debconf_go(client);
                state = GET_IPADDRESS;
                debconf_capb(client, "backup");
                break;
            }
            state = netcfg_get_pointopoint(client, iface) ?
                GET_IPADDRESS : GET_NAMESERVERS;
            break;

        case GET_NETMASK:
            state = netcfg_get_netmask(client, iface) ?
                GET_IPADDRESS : GET_GATEWAY;
            break;

        case GET_GATEWAY:
            netcfg_preseed_gateway(client, iface);
            if (netcfg_get_gateway(client, iface))
                state = GET_NETMASK;
            else
                if (!netcfg_gateway_reachable(iface))
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
            state = (netcfg_get_nameservers (client, &nameservers, iface->gateway)) ?
                GET_GATEWAY : CONFIRM;
            break;
        case GET_HOSTNAME:
            seed_hostname_from_dns(client, iface->ipaddress);
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
            inet_mtop(AF_INET, iface->masklen, netmask, INET_ADDRSTRLEN);
            debconf_subst(client, "netcfg/confirm_static", "interface", iface->name);
            debconf_subst(client, "netcfg/confirm_static", "ipaddress", empty_str(iface->ipaddress) ? none : iface->ipaddress);
            debconf_subst(client, "netcfg/confirm_static", "pointopoint", empty_str(iface->pointopoint) ? none : iface->pointopoint);
            debconf_subst(client, "netcfg/confirm_static", "netmask", empty_str(netmask) ? none : netmask);
            debconf_subst(client, "netcfg/confirm_static", "gateway", empty_str(iface->gateway) ? none : iface->gateway);
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
                netcfg_activate_static(client, iface);
            }
            else
                state = GET_IPADDRESS;

            debconf_capb(client, "backup");

            break;

        case QUIT:
            netcfg_write_common(iface->ipaddress, hostname, domain);
            netcfg_write_static(domain, iface, nameserver_array, ARRAY_SIZE(nameserver_array));
            return 0;
            break;
        }
    }

    return 0;
}
