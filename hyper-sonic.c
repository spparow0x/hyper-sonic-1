/*

 *          H Y P E R - S O N I C  v1 (SECURE)          
 *     Unified Recon Tool: NMAP + DIRB Real Parser        
 *
 * Compile: gcc hyper-sonic.c -o hyper-sonic
 * Usage:   ./hyper-sonic [options] <target>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>

#define RESET    "\033[0m"
#define BOLD     "\033[1m"
#define RED      "\033[91m"
#define GREEN    "\033[92m"
#define YELLOW   "\033[93m"
#define CYAN     "\033[96m"
#define MAGENTA  "\033[95m"
#define DIM      "\033[2m"
#define ORANGE   "\033[38;5;208m"
#define WHITE    "\033[97m"

#define MAX_TARGET    256
#define MAX_WORDLIST  512
#define MAX_PORTS     128
#define MAX_PORTS_N   1024
#define MAX_DIRS_N    4096
#define MAX_LINE      1024
#define VERSION       "2.1 Secure"
typedef struct {
    int    number;
    char   protocol[8];
    char   state[16];
    char   service[64];
    char   version[128];
} PortEntry;

typedef struct {
    char   url[512];
    int    code;
    int    size;
} DirbEntry;

typedef struct {
    char       target[MAX_TARGET];
    char       wordlist[MAX_WORDLIST];
    char       ports[MAX_PORTS];
    int        run_nmap;
    int        run_dirb;
    int        aggressive;
    int        stealth;
    int        save_output;
    char       output_dir[256];
    PortEntry  ports_found[MAX_PORTS_N];
    int        port_count;
    char       os_guess[256];
    char       nmap_elapsed[32];
    int        hosts_up;
    DirbEntry  dirs_found[MAX_DIRS_N];
    int        dir_count;
    char       dirb_wordlist_used[MAX_WORDLIST];
} Config;

// ─── Helpers
void print_info(const char *msg) { printf("  %s[%s*%s]%s %s\n", BOLD, CYAN, BOLD, RESET, msg); }
void print_ok(const char *msg)   { printf("  %s[%s+%s]%s %s%s%s\n", BOLD, GREEN, BOLD, RESET, GREEN, msg, RESET); }
void print_warn(const char *msg) { printf("  %s[%s!%s]%s %s%s%s\n", BOLD, YELLOW, BOLD, RESET, YELLOW, msg, RESET); }
void print_err(const char *msg)  { printf("  %s[%sx%s]%s %s%s%s\n", BOLD, RED, BOLD, RESET, RED, msg, RESET); }

void print_banner(void) {
    printf("\n" CYAN BOLD
    "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ \n"
    "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗\n"
    "  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝\n"
    "  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗\n"
    "  ██║  ██║   ██║   ██║     ███████╗██║  ██║\n"
    "  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝\n"
    RESET MAGENTA BOLD
    "  ███████╗ ██████╗ ███╗   ██╗██╗ ██████╗  \n"
    "  ██╔════╝██╔═══██╗████╗  ██║██║██╔════╝  \n"
    "  ███████╗██║   ██║██╔██╗ ██║██║██║       \n"
    "  ╚════██║██║   ██║██║╚██╗██║██║██║       \n"
    "  ███████║╚██████╔╝██║ ╚████║██║╚██████╗  \n"
    "  ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝  \n"
    RESET DIM CYAN
    "  ══════════════════════════════════════════\n"
    "   v" VERSION:1 " | By:spparow0x\n"
    "  ══════════════════════════════════════════\n"
    RESET "\n");
}

void print_section(const char *title, const char *color) {
    printf("\n%s%s+-- %s ", BOLD, color, title);
    int len = 42 - (int)strlen(title) - 4;
    for (int i = 0; i < len && i < 60; i++) printf("-");
    printf("+%s\n\n", RESET);
}
void print_section_end(const char *color) {
    printf("%s%s+------------------------------------------+%s\n\n", BOLD, color, RESET);
}
void print_kv(const char *label, const char *value, const char *col) {
    printf("  %s%-20s%s %s%s%s\n", DIM, label, RESET, col, value, RESET);
}

void usage(const char *prog) {
    print_banner();
    printf(BOLD WHITE "  USAGE:\n" RESET);
    printf("  %s%s%s [OPTIONS] <target>\n\n", CYAN, prog, RESET);
    printf(BOLD WHITE "  OPTIONS:\n" RESET);
    printf("    %s-n%s              NMAP scan only\n",            YELLOW, RESET);
    printf("    %s-d%s              DIRB scan only\n",            YELLOW, RESET);
    printf("    %s-a%s              Aggressive mode (NMAP -A)\n", YELLOW, RESET);
    printf("    %s-s%s              Stealth SYN scan (needs root)\n", YELLOW, RESET);
    printf("    %s-p <ports>%s      Ports: 80,443 or 1-1000\n",  YELLOW, RESET);
    printf("    %s-w <wordlist>%s   Wordlist path for DIRB\n",   YELLOW, RESET);
    printf("    %s-o <dir>%s        Save outputs to directory\n", YELLOW, RESET);
    printf("    %s-h%s              Show this help\n\n",          YELLOW, RESET);
    printf(BOLD WHITE "  EXAMPLES:\n" RESET);
    printf("  %s  %s -n 192.168.1.1\n", DIM, prog);
    printf("    %s -a -o ./results scanme.nmap.org\n", prog);
    printf("    %s -d -w /usr/share/dirb/wordlists/big.txt 10.0.0.1\n", prog);
    printf("    %s -p 22,80,443,8080 -o ./out 10.0.0.1\n\n" RESET, prog);
}

int check_tool(const char *tool) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "which %s > /dev/null 2>&1", tool);
    return system(cmd) == 0;
}

void get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", t);
}

int copy_file(const char *src, const char *dst) {
    int fsrc = open(src, O_RDONLY);
    if (fsrc < 0) return -1;
    int fdst = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fdst < 0) { close(fsrc); return -1; }
    char buf[4096];
    ssize_t bytes;
    while ((bytes = read(fsrc, buf, sizeof(buf))) > 0) {
        if (write(fdst, buf, bytes) != bytes) {
            close(fsrc); close(fdst); return -1;
        }
    }
    close(fsrc); close(fdst);
    return 0;
}
 // INPUT VALIDATION

/* Returns 1 if char is safe for hostnames/IPs, 0 otherwise */
static int is_safe_hostname_char(char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_';
}

static int is_safe_port_char(char c) {
    return isdigit((unsigned char)c) || c == ',' || c == '-';
}

static int is_safe_path_char(char c) {
    return isalnum((unsigned char)c) || c == '/' || c == '.' ||
           c == '-' || c == '_' || c == '~';
}


int validate_target(const char *target) {
    if (!target || strlen(target) == 0) {
        print_err("Target cannot be empty.");
        return 0;
    }
    if (strlen(target) >= MAX_TARGET) {
        print_err("Target too long.");
        return 0;
    }

    const char *t = target;
    if (strncmp(t, "http://",  7) == 0) t += 7;
    else if (strncmp(t, "https://", 8) == 0) t += 8;
    const char *blacklist = ";|&`$(){}[]<>!\\\"'\n\r\t ";
    for (size_t i = 0; i < strlen(t); i++) {
        if (strchr(blacklist, t[i])) {
            print_err("Target contains illegal character — possible injection attempt.");
            fprintf(stderr, "  %s  Rejected char: '%c' (0x%02x)%s\n",
                    RED, t[i], (unsigned char)t[i], RESET);
            return 0;
        }
    }

    for (size_t i = 0; i < strlen(t); i++) {
        if (!is_safe_hostname_char(t[i]) && t[i] != ':') {
            print_err("Target contains invalid character for hostname/IP.");
            return 0;
        }
    }

    // Must not start or end with a dash or dot
    if (t[0] == '-' || t[0] == '.') {
        print_err("Target must not start with '-' or '.'");
        return 0;
    }
    size_t tlen = strlen(t);
    if (t[tlen-1] == '-' || t[tlen-1] == '.') {
        print_err("Target must not end with '-' or '.'");
        return 0;
    }

    return 1;
}
 // validate_ports: accepts "80", "80,443", "1-1000", "22,80,443-8080"
 //Rejects anything non-numeric / non-comma / non-dash.
int validate_ports(const char *ports) {
    if (!ports || strlen(ports) == 0) return 1; /* empty = default, ok */
    if (strlen(ports) >= MAX_PORTS) {
        print_err("Ports string too long.");
        return 0;
    }
    for (size_t i = 0; i < strlen(ports); i++) {
        if (!is_safe_port_char(ports[i])) {
            print_err("Ports contain invalid character — only digits, commas, and dashes allowed.");
            return 0;
        }
    }
    int has_digit = 0;
    for (size_t i = 0; i < strlen(ports); i++)
        if (isdigit((unsigned char)ports[i])) { has_digit = 1; break; }
    if (!has_digit) {
        print_err("Ports must contain at least one digit.");
        return 0;
    }
    return 1;
}

// validate_path: wordlist and output_dir.
int validate_path(const char *path, const char *label) {
    if (!path || strlen(path) == 0) return 1; /* empty ok */
    for (size_t i = 0; i < strlen(path); i++) {
        if (!is_safe_path_char(path[i])) {
            char errbuf[128];
            snprintf(errbuf, sizeof(errbuf),
                     "%s contains invalid character '%c'.", label, path[i]);
            print_err(errbuf);
            return 0;
        }
    }
    if (strstr(path, "..")) {
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "%s: path traversal (..) not allowed.", label);
        print_err(errbuf);
        return 0;
    }
    return 1;
}

//master validation — call before any scan
int validate_all(Config *cfg) {
    print_section("INPUT VALIDATION", YELLOW);
    int ok = 1;

    if (!validate_target(cfg->target))   ok = 0;
    else print_ok("Target OK");

    if (!validate_ports(cfg->ports))     ok = 0;
    else if (strlen(cfg->ports)) print_ok("Ports OK");

    if (!validate_path(cfg->wordlist, "Wordlist"))   ok = 0;
    else if (strlen(cfg->wordlist)) print_ok("Wordlist path OK");

    if (!validate_path(cfg->output_dir, "Output dir")) ok = 0;
    else if (cfg->save_output) print_ok("Output dir OK");

    printf("\n");
    if (!ok) print_err("Validation failed — scan aborted.");
    else     print_ok("All inputs validated — proceeding.");

    print_section_end(YELLOW);
    return ok;
}

//nmap
static int xml_attr(const char *line, const char *attr, char *out, int outsz) {
    char search[64];
    snprintf(search, sizeof(search), "%s=\"", attr);
    const char *p = strstr(line, search);
    if (!p) return 0;
    p += strlen(search);
    const char *end = strchr(p, '"');
    if (!end) return 0;
    int len = (int)(end - p);
    if (len >= outsz) len = outsz - 1;
    strncpy(out, p, len);
    out[len] = '\0';
    return 1;
}

void parse_nmap_xml(Config *cfg, const char *xmlfile) {
    FILE *f = fopen(xmlfile, "r");
    if (!f) return;

    char line[MAX_LINE * 4];
    int  in_port = 0;
    PortEntry cur;
    memset(&cur, 0, sizeof(cur));

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "elapsed=")) {
            char el[32]="";
            if (xml_attr(line, "elapsed", el, sizeof(el)))
                strncpy(cfg->nmap_elapsed, el, sizeof(cfg->nmap_elapsed)-1);
        }
        if (strstr(line, "<osmatch ")) {
            char name[256]="";
            xml_attr(line, "name", name, sizeof(name));
            if (name[0] && !cfg->os_guess[0])
                strncpy(cfg->os_guess, name, sizeof(cfg->os_guess)-1);
        }
        if (strstr(line, "<port ")) {
            in_port = 1;
            memset(&cur, 0, sizeof(cur));
            char proto[8]="", portid[16]="";
            xml_attr(line, "protocol", proto, sizeof(proto));
            xml_attr(line, "portid", portid, sizeof(portid));
            strncpy(cur.protocol, proto, sizeof(cur.protocol)-1);
            cur.number = atoi(portid);
        }
        if (in_port) {
            if (strstr(line, "<state ")) {
                char st[16]="";
                xml_attr(line, "state", st, sizeof(st));
                strncpy(cur.state, st, sizeof(cur.state)-1);
            }
            if (strstr(line, "<service ")) {
                char sname[64]="", product[128]="", ver[64]="", extra[128]="";
                xml_attr(line, "name",      sname,   sizeof(sname));
                xml_attr(line, "product",   product, sizeof(product));
                xml_attr(line, "version",   ver,     sizeof(ver));
                xml_attr(line, "extrainfo", extra,   sizeof(extra));
                strncpy(cur.service, sname, sizeof(cur.service)-1);
                if (product[0])
                    snprintf(cur.version, sizeof(cur.version), "%s %s %s", product, ver, extra);
            }
            if (strstr(line, "</port>")) {
                in_port = 0;
                if (strcmp(cur.state, "open") == 0 && cfg->port_count < MAX_PORTS_N)
                    cfg->ports_found[cfg->port_count++] = cur;
            }
        }
    }
    fclose(f);
}

static const char *port_color(int port) {
    if (port == 22 || port == 3389) return YELLOW;
    if (port == 80 || port == 8080 || port == 8000) return CYAN;
    if (port == 443 || port == 8443) return GREEN;
    if (port == 21 || port == 23)   return RED;
    if (port == 3306 || port == 5432 || port == 1433) return ORANGE;
    return WHITE;
}

void display_nmap_results(Config *cfg) {
    print_section("OPEN PORTS", CYAN);
    if (cfg->port_count == 0) { print_warn("No open ports found."); print_section_end(CYAN); return; }

    printf("  %s%-12s  %-10s  %-20s  %s%s\n", BOLD, "PORT/PROTO", "STATE", "SERVICE", "VERSION", RESET);
    printf("  %s%s%s\n", DIM, "--------------------------------------------------------------", RESET);

    for (int i = 0; i < cfg->port_count; i++) {
        PortEntry *p = &cfg->ports_found[i];
        char portproto[24];
        snprintf(portproto, sizeof(portproto), "%d/%s", p->number, p->protocol);
        char ver[52]; strncpy(ver, p->version, sizeof(ver)-1); ver[sizeof(ver)-1]='\0';
        if (strlen(ver) > 48) { ver[48]='.'; ver[49]='.'; ver[50]='\0'; }
        printf("  %s%-12s%s  %s%-10s%s  %-20s  %s%s%s\n",
               port_color(p->number), portproto, RESET,
               GREEN, p->state, RESET,
               p->service, DIM, ver, RESET);
    }
    printf("\n");
    char buf[64];
    snprintf(buf, sizeof(buf), "%d open port(s) found", cfg->port_count);
    print_ok(buf);
    if (cfg->os_guess[0])    print_kv("OS Guess:", cfg->os_guess, YELLOW);
    if (cfg->nmap_elapsed[0]) {
        char e[36]; snprintf(e, sizeof(e), "%ss", cfg->nmap_elapsed);
        print_kv("Elapsed:", e, DIM);
    }
    print_section_end(CYAN);
}

int run_nmap(Config *cfg) {
    char ts[64];
    char xmlfile[] = "/tmp/hs_nmap_XXXXXX";
    int fd = mkstemp(xmlfile);
    if (fd == -1) { print_err("Could not create temp file"); return -1; }
    close(fd);

    print_section("NMAP PORT SCANNER", CYAN);
    if (!check_tool("nmap")) { print_err("nmap not found! Install: sudo apt install nmap"); return -1; }

    get_timestamp(ts, sizeof(ts));
    print_kv("Target:",  cfg->target, GREEN);
    print_kv("Started:", ts, WHITE);
    print_kv("Mode:",
             cfg->aggressive ? "Aggressive (-A)" :
             cfg->stealth    ? "Stealth (-sS)"   : "Default (-sV)", YELLOW);
    print_kv("Ports:", strlen(cfg->ports) ? cfg->ports : "Top 1000", CYAN);
    printf("\n");

    char *args[20];
    int i = 0;
    if (cfg->stealth) args[i++] = "sudo";
    args[i++] = "nmap";
    if (cfg->aggressive)    args[i++] = "-A";
    else if (cfg->stealth) { args[i++] = "-sS"; args[i++] = "-sV"; }
    else                    args[i++] = "-sV";
    if (strlen(cfg->ports)) { args[i++] = "-p"; args[i++] = cfg->ports; }
    args[i++] = "-oX"; args[i++] = xmlfile;
    args[i++] = cfg->target;
    args[i++] = NULL;

    print_info("Running nmap scan...\n");
    pid_t pid = fork();
    if (pid == 0) { execvp(args[0], args); exit(1); }
    else if (pid > 0) { int st; waitpid(pid, &st, 0); }
    else { print_err("Fork failed!"); return -1; }

    if (cfg->save_output) {
        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s/nmap_%s.xml", cfg->output_dir, cfg->target);
        copy_file(xmlfile, outpath);
        printf("  %sSaved:%s %s\n", DIM, RESET, outpath);
    }

    parse_nmap_xml(cfg, xmlfile);
    unlink(xmlfile);
    display_nmap_results(cfg);
    return 0;
}

/*Dirb*/
static const char *http_color(int code) {
    if (code >= 200 && code < 300) return GREEN;
    if (code >= 300 && code < 400) return YELLOW;
    if (code == 401 || code == 403) return ORANGE;
    if (code >= 500) return RED;
    return WHITE;
}
static const char *http_label(int code) {
    switch (code) {
        case 200: return "OK";        case 201: return "Created";
        case 301: return "Redirect";  case 302: return "Found";
        case 401: return "Unauth";    case 403: return "Forbidden";
        case 500: return "SrvError";  default:  return "";
    }
}

void parse_dirb_output(Config *cfg, const char *outfile) {
    FILE *f = fopen(outfile, "r");
    if (!f) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '+' && strstr(line, "http")) {
            if (cfg->dir_count >= MAX_DIRS_N) continue;
            DirbEntry e; memset(&e, 0, sizeof(e));
            char *start = line + 2;
            while (*start == ' ') start++;
            char *paren = strchr(start, '(');
            if (!paren) continue;
            int urllen = (int)(paren - start);
            if (urllen > 0 && start[urllen-1] == ' ') urllen--;
            if (urllen >= (int)sizeof(e.url)) urllen = (int)sizeof(e.url)-1;
            strncpy(e.url, start, urllen); e.url[urllen] = '\0';
            char *code_p = strstr(paren, "CODE:");
            if (code_p) e.code = atoi(code_p+5);
            char *size_p = strstr(paren, "SIZE:");
            if (size_p) e.size = atoi(size_p+5);
            cfg->dirs_found[cfg->dir_count++] = e;
        }
        if (strncmp(line, "==> DIRECTORY:", 14) == 0) {
            if (cfg->dir_count >= MAX_DIRS_N) continue;
            DirbEntry e; memset(&e, 0, sizeof(e));
            char *url = line + 15;
            while (*url == ' ') url++;
            strncpy(e.url, url, sizeof(e.url)-1);
            e.code = 0; e.size = -1;
            cfg->dirs_found[cfg->dir_count++] = e;
        }
    }
    fclose(f);
}

void display_dirb_results(Config *cfg) {
    print_section("DISCOVERED PATHS", MAGENTA);
    if (cfg->dir_count == 0) { print_warn("No paths discovered."); print_section_end(MAGENTA); return; }

    printf("  %s%-16s  %-10s  %s%s\n", BOLD, "CODE", "SIZE", "URL", RESET);
    printf("  %s%s%s\n", DIM, "--------------------------------------------------------------", RESET);

    for (int i = 0; i < cfg->dir_count; i++) {
        DirbEntry *e = &cfg->dirs_found[i];
        if (e->code == 0) {
            printf("  %s%-16s%s  %s%-10s%s  %s%s%s\n",
                   CYAN, "[DIR]", RESET, DIM, "-", RESET, CYAN BOLD, e->url, RESET);
        } else {
            char codedisp[32]; char sizestr[16];
            const char *label = http_label(e->code);
            if (label[0]) snprintf(codedisp, sizeof(codedisp), "%d %-8s", e->code, label);
            else          snprintf(codedisp, sizeof(codedisp), "%d", e->code);
            if (e->size >= 0) snprintf(sizestr, sizeof(sizestr), "%d", e->size);
            else              strncpy(sizestr, "-", sizeof(sizestr));
            printf("  %s%-16s%s  %-10s  %s\n",
                   http_color(e->code), codedisp, RESET, sizestr, e->url);
        }
    }
    printf("\n");
    char buf[64];
    snprintf(buf, sizeof(buf), "%d path(s) discovered", cfg->dir_count);
    print_ok(buf);
    print_section_end(MAGENTA);
}

int run_dirb(Config *cfg) {
    char ts[64];
    char tmpout[] = "/tmp/hs_dirb_XXXXXX";
    char url[MAX_TARGET + 16];

    int fd = mkstemp(tmpout);
    if (fd == -1) { print_err("Could not create temp file"); return -1; }
    close(fd);

    print_section("DIRB WEB SCANNER", MAGENTA);
    if (!check_tool("dirb")) { print_err("dirb not found! Install: sudo apt install dirb"); return -1; }

    if (strncmp(cfg->target, "http", 4) == 0)
        strncpy(url, cfg->target, sizeof(url)-1);
    else
        snprintf(url, sizeof(url), "http://%s", cfg->target);

    const char *wl = strlen(cfg->wordlist) ? cfg->wordlist : "/usr/share/dirb/wordlists/common.txt";
    if (access(wl, F_OK) != 0) { print_warn("Wordlist not found! Use -w to specify."); unlink(tmpout); return -1; }

    get_timestamp(ts, sizeof(ts));
    print_kv("Target URL:", url, GREEN);
    print_kv("Started:", ts, WHITE);
    print_kv("Wordlist:", wl, YELLOW);
    printf("\n");

    char *args[] = { "dirb", url, (char *)wl, "-o", tmpout, NULL };

    print_info("Running dirb scan...\n");
    pid_t pid = fork();
    if (pid == 0) { execvp(args[0], args); exit(1); }
    else if (pid > 0) { int st; waitpid(pid, &st, 0); }

    if (cfg->save_output) {
        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s/dirb_%s.txt", cfg->output_dir, cfg->target);
        copy_file(tmpout, outpath);
        printf("  %sSaved:%s %s\n", DIM, RESET, outpath);
    }

    parse_dirb_output(cfg, tmpout);
    unlink(tmpout);
    display_dirb_results(cfg);
    return 0;
}

void print_summary(Config *cfg, int nmap_ret, int dirb_ret) {
    char ts[64]; get_timestamp(ts, sizeof(ts));
    print_section("RECON SUMMARY", GREEN);
    print_kv("Target:", cfg->target, GREEN);
    print_kv("Finished:", ts, WHITE);
    printf("\n");
    if (cfg->run_nmap) {
        char s[32]=""; if (cfg->port_count>0) snprintf(s,sizeof(s),"(%d open)",cfg->port_count);
        printf("  %sCYAN  NMAP%s  %s%s%s  %s%s%s\n",
               CYAN, RESET, nmap_ret==0?GREEN:RED, nmap_ret==0?"SUCCESS":"FAILED", RESET, DIM, s, RESET);
    }
    if (cfg->run_dirb) {
        char s[32]=""; if (cfg->dir_count>0) snprintf(s,sizeof(s),"(%d paths)",cfg->dir_count);
        printf("  %sMAGENTA DIRB%s  %s%s%s  %s%s%s\n",
               MAGENTA, RESET, dirb_ret==0?GREEN:RED, dirb_ret==0?"SUCCESS":"FAILED", RESET, DIM, s, RESET);
    }
    if (cfg->save_output)
        printf("\n  %sOutputs in:%s %s/\n", DIM, RESET, cfg->output_dir);
    printf("\n%s  ============================================%s\n", CYAN DIM, RESET);
    printf("%s  hyper-sonic v%s  --  stay legal, stay sharp%s\n", CYAN, VERSION, RESET);
    printf("%s  ============================================%s\n\n", CYAN DIM, RESET);
}

int main(int argc, char *argv[]) {
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.run_nmap = 1; cfg.run_dirb = 1;
    strncpy(cfg.output_dir, "./hs-output", sizeof(cfg.output_dir)-1);

    if (argc < 2) { usage(argv[0]); return 1; }

    int opt, nmap_only = 0, dirb_only = 0;
    while ((opt = getopt(argc, argv, "ndasp:w:o:h")) != -1) {
        switch (opt) {
            case 'n': nmap_only = 1; break;
            case 'd': dirb_only = 1; break;
            case 'a': cfg.aggressive = 1; break;
            case 's': cfg.stealth    = 1; break;
            case 'p': strncpy(cfg.ports,    optarg, MAX_PORTS-1);    cfg.ports[MAX_PORTS-1]='\0';    break;
            case 'w': strncpy(cfg.wordlist, optarg, MAX_WORDLIST-1); cfg.wordlist[MAX_WORDLIST-1]='\0'; break;
            case 'o': strncpy(cfg.output_dir, optarg, 255); cfg.output_dir[255]='\0'; cfg.save_output=1; break;
            case 'h': usage(argv[0]); return 0;
            default:  print_err("Unknown option. Use -h."); return 1;
        }
    }

    if (optind >= argc) { print_err("No target specified! Use -h."); return 1; }
    strncpy(cfg.target, argv[optind], MAX_TARGET-1);
    cfg.target[MAX_TARGET-1] = '\0';

    if (nmap_only) { cfg.run_nmap = 1; cfg.run_dirb = 0; }
    if (dirb_only) { cfg.run_nmap = 0; cfg.run_dirb = 1; }

    print_banner();
    printf(BOLD "  Target:  " GREEN "%s" RESET "\n", cfg.target);
    printf(BOLD "  Modules: " RESET);
    if (cfg.run_nmap) printf(CYAN "NMAP " RESET);
    if (cfg.run_nmap && cfg.run_dirb) printf(DIM "+ " RESET);
    if (cfg.run_dirb) printf(MAGENTA "DIRB" RESET);
    printf("\n" CYAN DIM "  ============================================\n\n" RESET);

    if (!validate_all(&cfg)) return 1;

    if (cfg.save_output) {
        struct stat st = {0};
        if (stat(cfg.output_dir, &st) == -1) mkdir(cfg.output_dir, 0700);
    }

    int nmap_ret = 0, dirb_ret = 0;
    if (cfg.run_nmap) {
        nmap_ret = run_nmap(&cfg);
        if (cfg.run_dirb) {
            int web_port_open = 0;
            for (int i = 0; i < cfg.port_count; i++) {
                int p = cfg.ports_found[i].number;
                if (p == 80 || p == 443 || p == 8080 || p == 8443) {
                    web_port_open = 1;
                    break; // Lqina port web, n7bso l'qlyb f la boucle
                }
            }
            
            if (!web_port_open) {
                printf("\n  %s[%s!%s]%s %sAucun port Web ouvert (80/443/8080). Annulation du scan DIRB.%s\n", 
                       BOLD, YELLOW, BOLD, RESET, YELLOW, RESET);
                cfg.run_dirb = 0; // Kan-désactiviw Dirb bach maykhdemch
            }
        }
    }

    if (cfg.run_dirb) {
        dirb_ret = run_dirb(&cfg);
    }

    print_summary(&cfg, nmap_ret, dirb_ret);
    return (nmap_ret != 0 || dirb_ret != 0) ? 1 : 0;
}
