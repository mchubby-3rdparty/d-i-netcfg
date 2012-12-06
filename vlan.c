#include <stdio.h>
#include <cdebconf/debconfclient.h>
#include <debian-installer.h>
#include "netcfg.h"

#define VLAN_SUCESSED 0
#define VLAN_FAILED 1
int netcfg_set_vlan(struct netcfg_interface *interface, struct debconfclient *client){
    char *vlaniface = NULL, *vlanid = NULL, *vlancmd = NULL;
    int vlaniface_len, vlancmd_len;

/*kfreebsd or hurd has different cmd to set vlan*/
#if defined(__linux__)
    char vlancmd_template[] = "ip link add link %s name %s type vlan id %s";
#elif defined(__FreeBSD_kernel__)
    /*export 2 more to make it the same formt with Linux*/
    char vlancmd_tmplate[] = "export NIC=%s; export VNIC=%s; export VLANID=%s;"
                             " ifconfig $VNIC create";
#endif
    int vlancmd_template_len = sizeof(vlancmd_template);

    vlancmd = malloc(256);
    if(! vlancmd){
        free(vlaniface);
        goto error;
    }

    debconf_input(client, "medium", "netcfg/use_vlan");

    if (debconf_go(client) == CMD_GOBACK)
       return GO_BACK;
    debconf_get(client, "netcfg/use_vlan");

    if (!strcmp(client->value, "false")){
       goto error;
    }

    debconf_input(client, "critical", "netcfg/vlan_id");
    debconf_get(client, "netcfg/vlan_id");
    vlanid = client -> value;

    vlaniface_len = strlen(interface->name)+strlen(vlanid)+2;
    vlaniface = malloc(vlaniface_len);
    if(! vlaniface){
       goto error;
    }
    snprintf(vlaniface, vlaniface_len, "%s.%s", interface->name, vlanid);
    vlancmd_len = vlancmd_template_len + vlaniface_len*2 +1;
    vlancmd = malloc(vlancmd_len);
    if(! vlancmd){
       goto error;
    }
    snprintf(vlancmd, vlancmd_len, vlancmd_template, interface->name, vlaniface, vlanid);
    if(di_exec_shell_log(vlancmd)){
       di_warning("^ Setting VLAN error: the command is \n%s", vlancmd);
       debconf_capb(client);
       debconf_input(client, "critical", "netcfg/vlan_cmderror");
       debconf_go(client);
       debconf_capb(client, "backup");
       goto error;
    }
    if(interface->name){
         free(interface->name);
         interface->name = vlaniface;
    }
    free(vlancmd);
    return VLAN_SUCESSED;

error:
    if(vlaniface) free(vlaniface);
    if(vlancmd) free(vlancmd);
    return VLAN_FAILED;
}
