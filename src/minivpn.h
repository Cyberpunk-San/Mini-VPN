#ifndef MINIVPN_H
#define MINIVPN_H

#include <stdint.h>

#include "crypto.h"
#include "proto.h"

#define MINIVPN_VERSION "2.0.0"
#define MAX_ROUTES      16

#define DEFAULT_SERVER_CONFIG  "/etc/minivpn/server.conf"
#define DEFAULT_DEVICES_PATH   "/etc/minivpn/devices"
#define DEFAULT_LICENSE_PATH   "/etc/minivpn/license.key"
#define DEFAULT_CONTROL_SOCKET "/run/minivpn/control.sock"

typedef struct {
    const char *listen_addr; /* NULL = all interfaces */
    uint16_t port;
    uint32_t subnet; /* host order */
    uint32_t netmask;
    int mtu;
    const char *dev;
    int client_to_client;
    const char *user; /* drop privileges to this user after setup */
    const char *devices_path;
    const char *license_path;
    const char *control_path; /* "" disables the control socket */
} server_config;

typedef struct {
    uint8_t device_id[DEVICE_ID_LEN];
    uint8_t psk[KEY_LEN];
    const char *server_host;
    uint16_t port;
    const char *dev;
    uint32_t route_net[MAX_ROUTES];
    uint32_t route_mask[MAX_ROUTES];
    int nroutes;
    int redirect_gateway;
    int rekey_interval;
} client_config;

int server_run(const server_config *cfg);
int client_run(const client_config *cfg);

#endif
