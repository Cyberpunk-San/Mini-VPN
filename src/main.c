#include "minivpn.h"

#include "config.h"
#include "crypto.h"
#include "license.h"
#include "log.h"
#include "proto.h"
#include "util.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *out)
{
    fprintf(out,
        "minivpn %s - self-hosted team VPN\n"
        "\n"
        "usage:\n"
        "  minivpn server [--config FILE] [options]    run the VPN server\n"
        "  minivpn client --config FILE [options]      connect a device\n"
        "  minivpn license-info [--license FILE]       show edition and limits (JSON)\n"
        "  minivpn version\n"
        "\n"
        "Devices, keys and licenses are managed with `minivpn-admin`.\n"
        "\n"
        "server options (override %s):\n"
        "  -c, --config FILE       server configuration file\n"
        "  -l, --listen ADDR       local address to bind (default all)\n"
        "  -p, --port PORT         UDP port (default %d)\n"
        "  -s, --subnet CIDR       tunnel network, server takes .1 (default 10.8.0.0/24)\n"
        "  -m, --mtu N             tunnel MTU pushed to clients (default %d)\n"
        "  -d, --dev NAME          TUN device name (default mvpn%%d)\n"
        "  -u, --user NAME         drop root privileges to NAME after setup\n"
        "      --devices FILE      device registry (default %s)\n"
        "      --license FILE      license file (default %s)\n"
        "      --control PATH      control socket (default %s, \"\" = off)\n"
        "      --no-client-to-client   block traffic between devices\n"
        "\n"
        "client options (override the config file):\n"
        "  -c, --config FILE       device configuration from `minivpn-admin add`\n"
        "  -d, --dev NAME          TUN device name\n"
        "  -r, --route CIDR        send this network through the tunnel (repeatable)\n"
        "  -g, --redirect-gateway  send all IPv4 traffic through the tunnel\n"
        "      --rekey SECONDS     renegotiate keys this often (default %d, 0 = never)\n"
        "\n"
        "  -v, --verbose / -q, --quiet   logging detail\n"
        "\n"
        "Signals: SIGHUP reloads devices and license (server), SIGUSR1 prints status.\n",
        MINIVPN_VERSION, DEFAULT_SERVER_CONFIG, DEFAULT_PORT, DEFAULT_MTU, DEFAULT_DEVICES_PATH,
        DEFAULT_LICENSE_PATH, DEFAULT_CONTROL_SOCKET, DEFAULT_REKEY);
}

static int parse_long(const char *s, long min, long max, long *out)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

/* Strings read from config files live until the command returns. */
static char *owned[64];
static size_t nowned;

static char *xstrdup(const char *s)
{
    char *p = strdup(s);
    if (!p || nowned == sizeof owned / sizeof owned[0]) {
        log_error("out of memory or too many settings");
        exit(1);
    }
    return owned[nowned++] = p;
}

static void free_owned(void)
{
    while (nowned)
        free(owned[--nowned]);
}

/* Finds -c/--config before regular option parsing so the file can be applied
 * first and command-line flags override it. */
static const char *find_config_arg(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc)
            return argv[i + 1];
        if (!strncmp(argv[i], "--config=", 9))
            return argv[i] + 9;
    }
    return NULL;
}

/* ---- server ------------------------------------------------------------ */

static int set_port(uint16_t *port, const char *v)
{
    long n;
    if (parse_long(v, 1, 65535, &n)) {
        log_error("invalid port '%s'", v);
        return -1;
    }
    *port = (uint16_t)n;
    return 0;
}

static int set_subnet(server_config *cfg, const char *v)
{
    int prefix = parse_cidr(v, &cfg->subnet, &cfg->netmask);
    if (prefix < 16 || prefix > 29) {
        log_error("invalid subnet '%s' (use a /16 to /29 network, e.g. 10.8.0.0/24)", v);
        return -1;
    }
    return 0;
}

static int set_mtu(int *mtu, const char *v)
{
    long n;
    if (parse_long(v, MIN_MTU, MAX_MTU, &n)) {
        log_error("MTU must be between %d and %d", MIN_MTU, MAX_MTU);
        return -1;
    }
    *mtu = (int)n;
    return 0;
}

static int server_conf_cb(void *ctx, const char *key, const char *v, const char *path, int line)
{
    server_config *cfg = ctx;
    int b;

    if (!strcmp(key, "listen"))
        cfg->listen_addr = xstrdup(v);
    else if (!strcmp(key, "port"))
        return set_port(&cfg->port, v);
    else if (!strcmp(key, "subnet"))
        return set_subnet(cfg, v);
    else if (!strcmp(key, "mtu"))
        return set_mtu(&cfg->mtu, v);
    else if (!strcmp(key, "interface"))
        cfg->dev = xstrdup(v);
    else if (!strcmp(key, "user"))
        cfg->user = xstrdup(v);
    else if (!strcmp(key, "devices"))
        cfg->devices_path = xstrdup(v);
    else if (!strcmp(key, "license"))
        cfg->license_path = xstrdup(v);
    else if (!strcmp(key, "control_socket"))
        cfg->control_path = xstrdup(v);
    else if (!strcmp(key, "client_to_client")) {
        if ((b = config_bool(v)) < 0) {
            log_error("%s:%d: client_to_client must be yes or no", path, line);
            return -1;
        }
        cfg->client_to_client = b;
    } else if (!strcmp(key, "endpoint")) {
        /* public address written into device configs by minivpn-admin */
    } else {
        log_error("%s:%d: unknown setting '%s'", path, line, key);
        return -1;
    }
    return 0;
}

enum { OPT_NO_C2C = 256, OPT_REKEY, OPT_DEVICES, OPT_LICENSE, OPT_CONTROL };

static int cmd_server(int argc, char **argv)
{
    static const struct option opts[] = {
        { "config", required_argument, NULL, 'c' },
        { "port", required_argument, NULL, 'p' },
        { "dev", required_argument, NULL, 'd' },
        { "listen", required_argument, NULL, 'l' },
        { "subnet", required_argument, NULL, 's' },
        { "mtu", required_argument, NULL, 'm' },
        { "user", required_argument, NULL, 'u' },
        { "devices", required_argument, NULL, OPT_DEVICES },
        { "license", required_argument, NULL, OPT_LICENSE },
        { "control", required_argument, NULL, OPT_CONTROL },
        { "no-client-to-client", no_argument, NULL, OPT_NO_C2C },
        { "verbose", no_argument, NULL, 'v' },
        { "quiet", no_argument, NULL, 'q' },
        { "help", no_argument, NULL, 'h' },
        { 0 },
    };
    server_config cfg;
    int opt;

    memset(&cfg, 0, sizeof cfg);
    cfg.port = DEFAULT_PORT;
    cfg.mtu = DEFAULT_MTU;
    cfg.dev = "mvpn%d";
    cfg.client_to_client = 1;
    cfg.devices_path = DEFAULT_DEVICES_PATH;
    cfg.license_path = DEFAULT_LICENSE_PATH;
    cfg.control_path = DEFAULT_CONTROL_SOCKET;
    parse_cidr("10.8.0.0/24", &cfg.subnet, &cfg.netmask);

    const char *conf = find_config_arg(argc, argv);
    if (!conf && access(DEFAULT_SERVER_CONFIG, R_OK) == 0)
        conf = DEFAULT_SERVER_CONFIG;
    if (conf && config_parse(conf, server_conf_cb, &cfg))
        return 1;

    while ((opt = getopt_long(argc, argv, "c:p:d:l:s:m:u:vqh", opts, NULL)) != -1) {
        switch (opt) {
        case 'c': break; /* already applied */
        case 'p': if (set_port(&cfg.port, optarg)) return 2; break;
        case 'd': cfg.dev = optarg; break;
        case 'l': cfg.listen_addr = optarg; break;
        case 's': if (set_subnet(&cfg, optarg)) return 2; break;
        case 'm': if (set_mtu(&cfg.mtu, optarg)) return 2; break;
        case 'u': cfg.user = optarg; break;
        case OPT_DEVICES: cfg.devices_path = optarg; break;
        case OPT_LICENSE: cfg.license_path = optarg; break;
        case OPT_CONTROL: cfg.control_path = optarg; break;
        case OPT_NO_C2C: cfg.client_to_client = 0; break;
        case 'v': log_level = LVL_DEBUG; break;
        case 'q': log_level = LVL_WARN; break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        log_error("unexpected argument '%s'", argv[optind]);
        return 2;
    }
    int rc = server_run(&cfg);
    free_owned();
    return rc;
}

/* ---- client ------------------------------------------------------------ */

typedef struct {
    client_config *cfg;
    int have_id, have_key;
} client_conf_ctx;

static int add_route(client_config *cfg, const char *v)
{
    if (cfg->nroutes == MAX_ROUTES) {
        log_error("at most %d routes", MAX_ROUTES);
        return -1;
    }
    if (parse_cidr(v, &cfg->route_net[cfg->nroutes], &cfg->route_mask[cfg->nroutes]) < 0) {
        log_error("invalid route '%s' (expected CIDR like 192.168.50.0/24)", v);
        return -1;
    }
    cfg->nroutes++;
    return 0;
}

static int set_server(client_config *cfg, const char *v)
{
    char *host = xstrdup(v);
    char *colon = strrchr(host, ':');
    if (colon) {
        *colon = '\0';
        if (set_port(&cfg->port, colon + 1))
            return -1;
    }
    cfg->server_host = host;
    return 0;
}

static int set_rekey(client_config *cfg, const char *v)
{
    long n;
    if (parse_long(v, 0, 86400, &n) || (n > 0 && n < 5)) {
        log_error("rekey must be 0 (off) or 5..86400 seconds");
        return -1;
    }
    cfg->rekey_interval = (int)n;
    return 0;
}

static int client_conf_cb(void *ctx, const char *key, const char *v, const char *path, int line)
{
    client_conf_ctx *c = ctx;
    client_config *cfg = c->cfg;
    int b;

    if (!strcmp(key, "server"))
        return set_server(cfg, v);
    if (!strcmp(key, "port"))
        return set_port(&cfg->port, v);
    if (!strcmp(key, "device_id")) {
        if (hex_decode(v, cfg->device_id, DEVICE_ID_LEN)) {
            log_error("%s:%d: device_id must be 32 hex characters", path, line);
            return -1;
        }
        c->have_id = 1;
    } else if (!strcmp(key, "key")) {
        if (hex_decode(v, cfg->psk, KEY_LEN)) {
            log_error("%s:%d: key must be 64 hex characters", path, line);
            return -1;
        }
        c->have_key = 1;
    } else if (!strcmp(key, "interface")) {
        cfg->dev = xstrdup(v);
    } else if (!strcmp(key, "route")) {
        return add_route(cfg, v);
    } else if (!strcmp(key, "redirect_gateway")) {
        if ((b = config_bool(v)) < 0) {
            log_error("%s:%d: redirect_gateway must be yes or no", path, line);
            return -1;
        }
        cfg->redirect_gateway = b;
    } else if (!strcmp(key, "rekey")) {
        return set_rekey(cfg, v);
    } else if (!strcmp(key, "name")) {
        /* informational */
    } else {
        log_error("%s:%d: unknown setting '%s'", path, line, key);
        return -1;
    }
    return 0;
}

static int cmd_client(int argc, char **argv)
{
    static const struct option opts[] = {
        { "config", required_argument, NULL, 'c' },
        { "dev", required_argument, NULL, 'd' },
        { "route", required_argument, NULL, 'r' },
        { "redirect-gateway", no_argument, NULL, 'g' },
        { "rekey", required_argument, NULL, OPT_REKEY },
        { "verbose", no_argument, NULL, 'v' },
        { "quiet", no_argument, NULL, 'q' },
        { "help", no_argument, NULL, 'h' },
        { 0 },
    };
    client_config cfg;
    client_conf_ctx ctx = { .cfg = &cfg };
    int opt, rc;

    memset(&cfg, 0, sizeof cfg);
    cfg.port = DEFAULT_PORT;
    cfg.dev = "mvpn%d";
    cfg.rekey_interval = DEFAULT_REKEY;

    const char *conf = find_config_arg(argc, argv);
    if (!conf) {
        if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
            usage(stdout);
            return 0;
        }
        log_error("--config is required (create one with: minivpn-admin add <device-name>)");
        return 2;
    }
    warn_if_world_readable(conf, 0);
    if (config_parse(conf, client_conf_cb, &ctx))
        return 1;
    if (!ctx.have_id || !ctx.have_key || !cfg.server_host) {
        log_error("%s must define server, device_id and key", conf);
        return 1;
    }

    while ((opt = getopt_long(argc, argv, "c:d:r:gvqh", opts, NULL)) != -1) {
        switch (opt) {
        case 'c': break;
        case 'd': cfg.dev = optarg; break;
        case 'r': if (add_route(&cfg, optarg)) return 2; break;
        case 'g': cfg.redirect_gateway = 1; break;
        case OPT_REKEY: if (set_rekey(&cfg, optarg)) return 2; break;
        case 'v': log_level = LVL_DEBUG; break;
        case 'q': log_level = LVL_WARN; break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        log_error("unexpected argument '%s'", argv[optind]);
        return 2;
    }
    rc = client_run(&cfg);
    secure_zero(cfg.psk, sizeof cfg.psk);
    free_owned();
    return rc;
}

/* ---- license-info ------------------------------------------------------ */

static int cmd_license_info(int argc, char **argv)
{
    const char *path = DEFAULT_LICENSE_PATH;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--license") && i + 1 < argc)
            path = argv[++i];
        else if (!strncmp(argv[i], "--license=", 10))
            path = argv[i] + 10;
        else {
            log_error("usage: minivpn license-info [--license FILE]");
            return 2;
        }
    }
    license_info li;
    log_level = LVL_ERROR;
    license_load(path, &li);
    license_write_json(&li, stdout);
    fputc('\n', stdout);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stderr, NULL, _IOLBF, 0);
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "server"))
        return cmd_server(argc - 1, argv + 1);
    if (!strcmp(cmd, "client"))
        return cmd_client(argc - 1, argv + 1);
    if (!strcmp(cmd, "license-info"))
        return cmd_license_info(argc - 1, argv + 1);
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
        usage(stdout);
        return 0;
    }
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
        printf("minivpn %s\n", MINIVPN_VERSION);
        return 0;
    }
    log_error("unknown command '%s' (try: minivpn --help)", cmd);
    return 2;
}
