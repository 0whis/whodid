/*
 * whodid - File system activity monitor
 *
 * Shows which process (PID + executable path) is accessing or modifying
 * files in real time, using the Linux fanotify API.
 *
 * Usage:  sudo whodid [OPTIONS] <path>
 * Requires root or CAP_SYS_ADMIN capability.
 *
 * Modern mode  (kernel >= 5.1):  full CREATE/DELETE/RENAME events via
 *                                 FAN_REPORT_DFID_NAME.
 * Basic  mode  (kernel <  5.1):  OPEN/MODIFY/CLOSE_WRITE events only,
 *                                 paths resolved through the event's fd.
 */

/* _GNU_SOURCE is defined by the Makefile (-D_GNU_SOURCE); define it here
 * as a fallback for direct single-file compilation (gcc whodid.c -o whodid). */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Compatibility: define modern fanotify constants when system headers
 * are older than glibc 2.33 / kernel 5.1.
 * ---------------------------------------------------------------------- */
#ifndef FAN_ATTRIB
# define FAN_ATTRIB          0x00000004U
#endif
#ifndef FAN_MOVED_FROM
# define FAN_MOVED_FROM      0x00000040U
#endif
#ifndef FAN_MOVED_TO
# define FAN_MOVED_TO        0x00000080U
#endif
#ifndef FAN_CREATE
# define FAN_CREATE          0x00000100U
#endif
#ifndef FAN_DELETE
# define FAN_DELETE          0x00000200U
#endif
#ifndef FAN_REPORT_FID
# define FAN_REPORT_FID      0x00000200U   /* fanotify_init flag */
#endif
#ifndef FAN_REPORT_DIR_FID
# define FAN_REPORT_DIR_FID  0x00000400U
#endif
#ifndef FAN_REPORT_NAME
# define FAN_REPORT_NAME     0x00000800U
#endif
#ifndef FAN_REPORT_DFID_NAME
# define FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
#endif

/* FAN_MARK_FILESYSTEM: monitor the entire filesystem (kernel >= 4.20).
 * Required for CREATE/DELETE/RENAME/ATTRIB events (FAN_MARK_MOUNT
 * does not support those event types). */
#ifndef FAN_MARK_FILESYSTEM
# define FAN_MARK_FILESYSTEM 0x00000100U
#endif

/* MAX_HANDLE_SZ is defined in <fcntl.h> (glibc 2.14+, value=128).
 * Provide a fallback for older environments. */
#ifndef MAX_HANDLE_SZ
# define MAX_HANDLE_SZ 128
#endif

#ifndef FAN_EVENT_INFO_TYPE_FID
# define FAN_EVENT_INFO_TYPE_FID       1
# define FAN_EVENT_INFO_TYPE_DFID_NAME 2
# define FAN_EVENT_INFO_TYPE_DFID      3

struct fanotify_event_info_header {
    uint8_t  info_type;
    uint8_t  pad;
    uint16_t len;
};

/* __kernel_fsid_t: two int32 values identifying a filesystem */
typedef struct { int val[2]; } __kernel_fsid_t;

struct fanotify_event_info_fid {
    struct fanotify_event_info_header hdr;
    __kernel_fsid_t fsid;
    unsigned char handle[];   /* inline struct file_handle */
};
#endif /* FAN_EVENT_INFO_TYPE_FID */

/* -------------------------------------------------------------------------
 * Program constants
 * ---------------------------------------------------------------------- */
#define WHODID_VERSION    "1.0.0"
#define EVENT_BUF_SIZE    (64 * 1024)   /* bytes read per poll wake-up   */
#define PROC_NAME_MAX     256           /* truncation length for process  */
#define USER_NAME_MAX     64            /* truncation length for username */

/* -------------------------------------------------------------------------
 * ANSI terminal colour helpers (only emitted when g_use_color is set)
 * ---------------------------------------------------------------------- */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_CYAN    "\033[36m"
#define C_BRED    "\033[1;31m"
#define C_BGREEN  "\033[1;32m"
#define C_BYELLOW "\033[1;33m"
#define C_BCYAN   "\033[1;36m"

/* -------------------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------------- */
static volatile sig_atomic_t g_running      = 1;
static int                   g_fan_fd       = -1;
static int                   g_mount_fd     = -1;
static int                   g_use_color    = 1;
static int                   g_show_reads   = 0;
static int                   g_show_self    = 0;
static int                   g_quiet        = 0;
static int                   g_use_syslog   = 0;
static int                   g_modern_mode  = 0;
static char    g_filter_path[PATH_MAX]      = "";
static unsigned long         g_event_count  = 0;

/* -------------------------------------------------------------------------
 * Signal handler
 * ---------------------------------------------------------------------- */
static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* -------------------------------------------------------------------------
 * Privilege dropping
 *
 * Called once, immediately after fanotify_init() + fanotify_mark() succeed
 * and all privileged setup is complete.
 *
 * Strategy:
 *   1. Read the invoking user's UID/GID from SUDO_UID / SUDO_GID (set by
 *      sudo(8)).  Fall back to "nobody" (uid/gid 65534) when those vars are
 *      absent or when their value is 0 (i.e. sudoed from root).
 *   2. Use prctl(PR_SET_KEEPCAPS) so capabilities survive the UID change.
 *   3. Drop supplementary groups, GID, then UID via setresgid / setresuid.
 *   4. Reconstruct a minimal capability set:
 *        modern mode  → keep CAP_DAC_READ_SEARCH (required by
 *                        open_by_handle_at(2) in resolve_handle_path)
 *        basic  mode  → drop all extra capabilities
 *   5. Lock the process against future privilege re-acquisition via execve
 *      using prctl(PR_SET_NO_NEW_PRIVS).
 *
 * Returns 0 on success, -1 on any failure (caller must abort).
 * ---------------------------------------------------------------------- */
static int drop_privileges(int modern_mode)
{
    uid_t unprivileged_uid = 65534;   /* nobody — safe default */
    gid_t unprivileged_gid = 65534;
    const char *s;
    char *end;
    unsigned long v;
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];
    /* uid_t and gid_t are both unsigned 32-bit on Linux; UINT_MAX (0xffffffff)
     * is therefore the largest representable value for either type. */
    const __u32 cap_dac_read_search_mask = (1U << CAP_DAC_READ_SEARCH);

    /* Use the invoking user's IDs when run via sudo, but never use root (0).
     * strtoul returns values in [0, ULONG_MAX]; the UINT_MAX upper-bound
     * check ensures the value fits in uid_t/gid_t (both 32-bit unsigned). */
    if ((s = getenv("SUDO_UID")) != NULL) {
        v = strtoul(s, &end, 10);
        if (*end == '\0' && v > 0 && v <= UINT_MAX)
            unprivileged_uid = (uid_t)v;
    }
    if ((s = getenv("SUDO_GID")) != NULL) {
        v = strtoul(s, &end, 10);
        if (*end == '\0' && v > 0 && v <= UINT_MAX)
            unprivileged_gid = (gid_t)v;
    }

    /* Already not root — nothing to do */
    if (geteuid() != 0)
        return 0;

    /* Instruct the kernel to preserve capabilities across the UID change */
    if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
        perror("whodid: prctl(PR_SET_KEEPCAPS)");
        return -1;
    }

    /* Drop supplementary groups.  EPERM is tolerated in rootless container
     * environments (e.g. Docker with user namespaces) where the process
     * lacks the privilege to call setgroups(2) even when it appears to be
     * uid 0 inside the namespace.  In those environments, supplementary
     * group membership is already restricted by the container runtime. */
    if (setgroups(0, NULL) < 0 && errno != EPERM) {
        perror("whodid: setgroups");
        return -1;
    }

    /* Drop GID first, then UID (order matters: setresuid clears saved-set) */
    if (setresgid(unprivileged_gid, unprivileged_gid, unprivileged_gid) < 0) {
        perror("whodid: setresgid");
        return -1;
    }
    if (setresuid(unprivileged_uid, unprivileged_uid, unprivileged_uid) < 0) {
        perror("whodid: setresuid");
        return -1;
    }

    /* Rebuild the capability set to the bare minimum */
    memset(&hdr,  0, sizeof(hdr));
    memset(data,  0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;

    if (modern_mode) {
        /* CAP_DAC_READ_SEARCH is required by open_by_handle_at(2). */
        data[0].permitted   = cap_dac_read_search_mask;
        data[0].effective   = cap_dac_read_search_mask;
        data[0].inheritable = 0;
    }
    /* data[1] covers capabilities 32-63; all remain zero. */

    if (syscall(SYS_capset, &hdr, data) < 0) {
        perror("whodid: capset");
        return -1;
    }

    /* Prevent any child exec from regaining privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("whodid: prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static void get_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    struct tm tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(buf, len, "%H:%M:%S", &tm_info);
}

/*
 * sanitize_str – replace control characters (including ESC \x1b) with '?'.
 *
 * Security: prevents terminal escape-sequence injection via maliciously
 * crafted file names or process names (e.g. ANSI colour-smuggling attacks).
 */
static void sanitize_str(char *str, size_t max_len)
{
    size_t i;
    if (!str) return;
    for (i = 0; i < max_len && str[i] != '\0'; i++) {
        unsigned char c = (unsigned char)str[i];
        /* Block C0 controls (0x00-0x1f) and DEL (0x7f).
         * High bytes (0x80-0xff) are kept to support UTF-8 paths. */
        if (c < 0x20 || c == 0x7f)
            str[i] = '?';
    }
}

/*
 * get_process_name – resolve the executable path for PID via /proc.
 * Falls back to /proc/<pid>/comm (short name) when /proc/<pid>/exe is gone.
 */
static int get_process_name(pid_t pid, char *buf, size_t len)
{
    char proc_path[64];
    ssize_t n;
    FILE *f;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
    n = readlink(proc_path, buf, len - 1);
    if (n > 0) {
        buf[n] = '\0';
        sanitize_str(buf, len);
        return 0;
    }

    /* Process may have exited; try the short comm name */
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", (int)pid);
    f = fopen(proc_path, "r");
    if (f) {
        /* fgets takes int; clamp to INT_MAX for safety */
        int read_limit = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
        if (fgets(buf, read_limit, f)) {
            buf[strcspn(buf, "\n")] = '\0';
            sanitize_str(buf, len);
            fclose(f);
            return 0;
        }
        fclose(f);
    }

    snprintf(buf, len, "[pid:%d]", (int)pid);
    return -1;
}

/*
 * get_username_for_pid – resolve the OS username for the real UID of a process.
 * Reads /proc/<pid>/status to obtain the real UID, then looks it up with
 * getpwuid_r(3).  Falls back to "uid:<n>" when the name cannot be resolved.
 */
static void get_username_for_pid(pid_t pid, char *buf, size_t len)
{
    char status_path[128];
    FILE *f;
    char line[256];
    uid_t uid = (uid_t)-1;

    snprintf(status_path, sizeof(status_path), "/proc/%d/status", (int)pid);
    f = fopen(status_path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            unsigned int ruid, euid, suid, fsuid;
            if (sscanf(line, "Uid: %u %u %u %u",
                       &ruid, &euid, &suid, &fsuid) == 4) {
                uid = (uid_t)ruid;
                break;
            }
        }
        fclose(f);
    }

    if (uid != (uid_t)-1) {
        struct passwd  pw_buf;
        struct passwd *pw_result;
        char           pw_strbuf[1024];

        if (getpwuid_r(uid, &pw_buf, pw_strbuf, sizeof(pw_strbuf),
                       &pw_result) == 0 && pw_result != NULL) {
            snprintf(buf, len, "%s", pw_result->pw_name);
            sanitize_str(buf, len);
            return;
        }
        snprintf(buf, len, "uid:%u", (unsigned int)uid);
    } else {
        snprintf(buf, len, "?");
    }
}

static const char *get_action_str(uint64_t mask)
{
    if (mask & FAN_CREATE)        return "CREATE";
    if (mask & FAN_DELETE)        return "DELETE";
    if (mask & FAN_MOVED_FROM)    return "MOVE_FROM";
    if (mask & FAN_MOVED_TO)      return "MOVE_TO";
    if (mask & FAN_MODIFY)        return "MODIFY";
    if (mask & FAN_CLOSE_WRITE)   return "WRITE";
    if (mask & FAN_ATTRIB)        return "ATTRIB";
    if (mask & FAN_OPEN)          return "OPEN";
    if (mask & FAN_ACCESS)        return "READ";
    if (mask & FAN_CLOSE_NOWRITE) return "CLOSE";
    return "UNKNOWN";
}

static const char *get_action_color(uint64_t mask)
{
    if (mask & (FAN_DELETE | FAN_MOVED_FROM))   return C_BRED;
    if (mask & (FAN_CREATE | FAN_MOVED_TO))     return C_BGREEN;
    if (mask & (FAN_MODIFY | FAN_CLOSE_WRITE))  return C_RED;
    if (mask & FAN_ATTRIB)                      return C_BYELLOW;
    if (mask & (FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE)) return C_DIM;
    return C_RESET;
}

/*
 * path_is_under_filter – return 1 if path is at or below g_filter_path.
 *
 * Guards against false prefix matches: /etc must NOT match /etcbak/file.
 */
static int path_is_under_filter(const char *path)
{
    size_t filter_len;

    if (g_filter_path[0] == '\0') return 1;

    filter_len = strlen(g_filter_path);
    if (strncmp(path, g_filter_path, filter_len) != 0)
        return 0;
    /* Exact match (the path IS the watched directory) or proper sub-path */
    return (path[filter_len] == '\0' || path[filter_len] == '/');
}

/*
 * resolve_handle_path – turn a struct file_handle into an absolute path
 * using open_by_handle_at(2) and /proc/self/fd/.
 *
 * Requires CAP_DAC_READ_SEARCH (available when running as root).
 */
static int resolve_handle_path(struct file_handle *fh,
                                char *path_buf, size_t path_len)
{
    char fd_link[64];
    ssize_t n;
    int obj_fd;

    /* Sanity: reject suspiciously large handle sizes */
    if (fh->handle_bytes > MAX_HANDLE_SZ)
        return -1;

    obj_fd = open_by_handle_at(g_mount_fd, fh,
                               O_PATH | O_RDONLY | O_CLOEXEC);
    if (obj_fd < 0)
        return -1;

    snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", obj_fd);
    n = readlink(fd_link, path_buf, path_len - 1);
    close(obj_fd);

    if (n < 0)
        return -1;

    path_buf[n] = '\0';
    return 0;
}

/*
 * print_event – format and emit one line of output.
 */
static void print_event(pid_t pid, uint64_t mask, const char *filepath)
{
    char timestamp[16];
    char procname[PROC_NAME_MAX];
    char username[USER_NAME_MAX];
    const char *action;

    if (!g_show_self && pid == getpid()) return;
    if (!path_is_under_filter(filepath))  return;

    get_timestamp(timestamp, sizeof(timestamp));
    get_process_name(pid, procname, sizeof(procname));
    get_username_for_pid(pid, username, sizeof(username));
    action = get_action_str(mask);

    g_event_count++;

    if (g_use_syslog)
        syslog(LOG_INFO, "action=%s pid=%d user=%s process=%s file=%s",
               action, (int)pid, username, procname, filepath);

    if (g_use_color) {
        const char *ac = get_action_color(mask);
        printf("%s%-8s%s │ %s%-7d%s │ %s%-12s%s │ %s%-45s%s │ %s%-10s%s │ %s\n",
               C_CYAN,   timestamp, C_RESET,
               C_YELLOW, (int)pid,  C_RESET,
               C_CYAN,   username,  C_RESET,
               C_BOLD,   procname,  C_RESET,
               ac,       action,    C_RESET,
               filepath);
    } else {
        printf("%-8s │ %-7d │ %-12s │ %-45s │ %-10s │ %s\n",
               timestamp, (int)pid, username, procname, action, filepath);
    }
    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * Modern-mode event processing  (FAN_REPORT_DFID_NAME, kernel >= 5.1)
 *
 * Events carry embedded info records instead of an open file descriptor.
 * We parse the first FAN_EVENT_INFO_TYPE_DFID_NAME or DFID record to
 * recover the directory handle and file name, then build an absolute path.
 * ---------------------------------------------------------------------- */
static void process_event_modern(struct fanotify_event_metadata *meta)
{
    /* Static: avoids putting 4 KB+ on the stack; process_event_modern is
     * called from a single-threaded event loop, so this is safe. */
    static char path[PATH_MAX + NAME_MAX + 2];
    struct fanotify_event_info_header *info_hdr;
    char  *info_ptr;
    size_t info_remaining;

    path[0] = '\0';

    info_ptr       = (char *)meta + FAN_EVENT_METADATA_LEN;
    info_remaining = (size_t)meta->event_len - FAN_EVENT_METADATA_LEN;

    while (info_remaining >= sizeof(struct fanotify_event_info_header)) {
        info_hdr = (struct fanotify_event_info_header *)info_ptr;

        /* Validate record length before touching it */
        if (info_hdr->len == 0 || info_hdr->len > info_remaining)
            break;

        if (info_hdr->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
            info_hdr->info_type == FAN_EVENT_INFO_TYPE_DFID) {

            struct fanotify_event_info_fid *fid =
                (struct fanotify_event_info_fid *)info_ptr;
            struct file_handle *fh = (struct file_handle *)fid->handle;

            /* Bounds-check: ensure the file_handle fits inside the record */
            size_t fid_hdr_sz  = sizeof(struct fanotify_event_info_fid);
            size_t fh_base_sz  = sizeof(struct file_handle);

            if (info_hdr->len < fid_hdr_sz + fh_base_sz)
                goto next_record;

            /* handle_bytes is user-space readable but kernel-supplied */
            if (fh->handle_bytes > MAX_HANDLE_SZ)
                goto next_record;

            size_t fh_total = fh_base_sz + fh->handle_bytes;
            if (info_hdr->len < fid_hdr_sz + fh_total)
                goto next_record;

            char dir_path[PATH_MAX + 1];
            if (resolve_handle_path(fh, dir_path, sizeof(dir_path)) != 0) {
                snprintf(path, sizeof(path), "<unresolved>");
                break;
            }

            if (info_hdr->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                /* The file name immediately follows the file_handle data */
                char  *name        = (char *)fid->handle + fh_total;
                size_t name_offset = fid_hdr_sz + fh_total;

                if (name_offset < info_hdr->len) {
                    size_t name_max = info_hdr->len - name_offset;
                    char   safe_name[NAME_MAX + 1];
                    size_t copy_len = (name_max < sizeof(safe_name))
                                      ? name_max
                                      : sizeof(safe_name) - 1;
                    memcpy(safe_name, name, copy_len);
                    safe_name[copy_len] = '\0';
                    sanitize_str(safe_name, sizeof(safe_name));

                    /* "." means the event is on the directory itself */
                    if (strcmp(safe_name, ".") == 0)
                        snprintf(path, sizeof(path), "%s", dir_path);
                    else
                        snprintf(path, sizeof(path), "%s/%s",
                                 dir_path, safe_name);
                } else {
                    snprintf(path, sizeof(path), "%s", dir_path);
                }
            } else {
                /* DFID only: the event is on the directory itself */
                snprintf(path, sizeof(path), "%s", dir_path);
            }

            break; /* found a usable path – stop scanning records */
        }

next_record:
        info_ptr       += info_hdr->len;
        info_remaining -= info_hdr->len;
    }

    if (path[0] == '\0')
        snprintf(path, sizeof(path), "<unknown>");

    sanitize_str(path, sizeof(path));
    print_event(meta->pid, meta->mask, path);
}

/* -------------------------------------------------------------------------
 * Basic-mode event processing  (no FID reporting, kernel < 5.1)
 *
 * Each event carries an open file descriptor; we resolve it via
 * /proc/self/fd/<n> to get an absolute path, then close the fd.
 * ---------------------------------------------------------------------- */
static void process_event_basic(struct fanotify_event_metadata *meta)
{
    char path[PATH_MAX];

    if (meta->fd >= 0) {
        char fd_link[64];
        ssize_t n;

        snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", meta->fd);
        n = readlink(fd_link, path, sizeof(path) - 1);
        if (n > 0)
            path[n] = '\0';
        else
            snprintf(path, sizeof(path), "<unresolved>");

        close(meta->fd);   /* must always close the fd from fanotify */
    } else {
        snprintf(path, sizeof(path), "<no-fd>");
    }

    sanitize_str(path, sizeof(path));
    print_event(meta->pid, meta->mask, path);
}

/*
 * process_events – drain all pending events from the fanotify fd.
 */
static void process_events(int fan_fd)
{
    /* Static buffer keeps 64 KB off the stack */
    static char buf[EVENT_BUF_SIZE];
    struct fanotify_event_metadata *meta;
    ssize_t len;

    len = read(fan_fd, buf, sizeof(buf));
    if (len < 0) {
        if (errno == EAGAIN || errno == EINTR) return;
        perror("whodid: read");
        return;
    }

    meta = (struct fanotify_event_metadata *)buf;
    while (FAN_EVENT_OK(meta, len)) {
        if (meta->vers != FANOTIFY_METADATA_VERSION) {
            fprintf(stderr, "whodid: fanotify metadata version mismatch\n");
            /* Close stale fd to avoid leaks in basic mode */
            if (!g_modern_mode && meta->fd >= 0)
                close(meta->fd);
            meta = FAN_EVENT_NEXT(meta, len);
            continue;
        }

        if (g_modern_mode)
            process_event_modern(meta);
        else
            process_event_basic(meta);

        meta = FAN_EVENT_NEXT(meta, len);
    }
}

/* -------------------------------------------------------------------------
 * Banner
 * ---------------------------------------------------------------------- */
static void print_banner(const char *path, int modern)
{
    const char *mode_str = modern
        ? "modern  (fanotify + FID, kernel >= 5.1)"
        : "basic   (fanotify only; no CREATE/DELETE events)";
    const char *events_str = g_show_reads
        ? "OPEN READ WRITE CREATE DELETE RENAME ATTRIB"
        : "WRITE CREATE DELETE RENAME ATTRIB  (use -a to add OPEN/READ)";
    const char *syslog_str = g_use_syslog ? "yes  (journalctl -t whodid)" : "no";

    if (g_quiet) return;

    if (g_use_color) {
        printf("\n");
        printf("  %s┌─────────────────────────────────────────┐%s\n",
               C_CYAN, C_RESET);
        printf("  %s│  %swhodid%s v%-5s%s  — who touched that file? %s│%s\n",
               C_CYAN, C_BOLD, C_RESET, WHODID_VERSION, C_CYAN, C_DIM, C_RESET);
        printf("  %s└─────────────────────────────────────────┘%s\n\n",
               C_CYAN, C_RESET);
        printf("  %s►%s Watching : %s%s%s\n",
               C_BCYAN, C_RESET, C_BOLD, path, C_RESET);
        printf("  %s►%s Mode     : %s\n", C_BCYAN, C_RESET, mode_str);
        printf("  %s►%s Events   : %s\n", C_BCYAN, C_RESET, events_str);
        printf("  %s►%s Syslog   : %s\n", C_BCYAN, C_RESET, syslog_str);
        printf("  %s►%s Stop     : Ctrl-C%s\n\n", C_BCYAN, C_RESET, C_RESET);
        printf("%s%-8s │ %-7s │ %-12s │ %-45s │ %-10s │ %s%s\n",
               C_DIM,
               "TIME", "PID", "USER", "PROCESS", "ACTION", "FILE",
               C_RESET);
        printf("%s%.8s─┼─%.7s─┼─%.12s─┼─%.45s─┼─%.10s─┼─%.4s%s\n",
               C_DIM,
               "─────────", "────────", "─────────────",
               "──────────────────────────────────────────────",
               "───────────", "────",
               C_RESET);
        printf("\n");
    } else {
        printf("whodid v%s — file-system activity monitor\n", WHODID_VERSION);
        printf("Watching : %s\n", path);
        printf("Mode     : %s\n", mode_str);
        printf("Events   : %s\n", events_str);
        printf("Syslog   : %s\n", syslog_str);
        printf("Stop     : Ctrl-C\n\n");
        printf("%-8s │ %-7s │ %-12s │ %-45s │ %-10s │ FILE\n",
               "TIME", "PID", "USER", "PROCESS", "ACTION");
        printf("%.8s─┼─%.7s─┼─%.12s─┼─%.45s─┼─%.10s─┼─%.4s\n",
               "─────────", "────────", "─────────────",
               "──────────────────────────────────────────────",
               "───────────", "────");
    }
    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * Usage
 * ---------------------------------------------------------------------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] <path>\n"
        "\n"
        "DESCRIPTION\n"
        "  Real-time file-system activity monitor.  For every event under\n"
        "  <path>, whodid reports the timestamp, PID, username, full\n"
        "  executable path, action type, and affected file — one line per\n"
        "  event, ready for grep(1), awk(1), or tee(1).\n"
        "\n"
        "  Requires root or CAP_SYS_ADMIN (needed by fanotify_init(2)).\n"
        "  Privileges are dropped immediately after fanotify setup.\n"
        "\n"
        "OPTIONS\n"
        "  -a, --all\n"
        "      Report ALL events: OPEN, READ, and CLOSE in addition to the\n"
        "      default write-side events (WRITE, MODIFY, CREATE, DELETE,\n"
        "      RENAME, ATTRIB).  Warning: greatly increases output on busy\n"
        "      directories.\n"
        "\n"
        "  -l, --syslog\n"
        "      In addition to stdout, write each event to the system journal\n"
        "      via syslog(3) with facility LOG_DAEMON, priority LOG_INFO,\n"
        "      and tag 'whodid'.  Follow live:\n"
        "          journalctl -t whodid -f\n"
        "      Query by time:\n"
        "          journalctl -t whodid --since '1 hour ago'\n"
        "\n"
        "  -n, --no-color\n"
        "      Disable ANSI colour codes.  Colour is also suppressed\n"
        "      automatically when stdout is not a terminal.\n"
        "\n"
        "  -s, --self\n"
        "      Include file-system events generated by whodid itself.\n"
        "      Suppressed by default to reduce noise.\n"
        "\n"
        "  -q, --quiet\n"
        "      Suppress the startup banner and column headers.  Useful in\n"
        "      scripts or when whodid is used as a pipeline source.\n"
        "\n"
        "  -v, --version\n"
        "      Print version string and exit.\n"
        "\n"
        "  -h, --help\n"
        "      Print this help and exit.\n"
        "\n"
        "OUTPUT FORMAT\n"
        "  HH:MM:SS | PID | USER | PROCESS | ACTION | FILE\n"
        "\n"
        "  Default actions:  WRITE  MODIFY  CREATE  DELETE\n"
        "                    MOVE_FROM  MOVE_TO  ATTRIB\n"
        "  With -a, also:    OPEN   READ    CLOSE\n"
        "\n"
        "EXAMPLES\n"
        "  # Incident response: watch /etc/ for unauthorized modifications\n"
        "  sudo whodid /etc/\n"
        "\n"
        "  # Hunt for persistence: watch cron and systemd drop-zones\n"
        "  sudo whodid /etc/cron.d/ &\n"
        "  sudo whodid /etc/systemd/system/ &\n"
        "\n"
        "  # Log to stdout and the system journal simultaneously\n"
        "  sudo whodid --syslog /home/ | tee /var/log/whodid-home.log\n"
        "\n"
        "  # Filter live output to a specific process\n"
        "  sudo whodid /var/www/ | grep nginx\n"
        "\n"
        "  # Query the system journal for whodid events\n"
        "  journalctl -t whodid --since 'today' | grep DELETE\n"
        "  grep 'whodid' /var/log/syslog | grep -v root\n"
        "\n"
        "  # Disable banner and colour for scripts or log pipelines\n"
        "  sudo whodid -q -n /tmp/ | awk '{ print $0 }' >> events.log\n"
        "\n"
        "NOTES\n"
        "  Monitoring is at mount-point granularity; output is filtered to\n"
        "  the given path prefix in user-space.\n"
        "\n"
        "  Full CREATE/DELETE/RENAME/ATTRIB reporting requires Linux\n"
        "  kernel >= 5.1 (Debian 11 Bullseye, Ubuntu 20.10, RHEL 9, or\n"
        "  WSL2 after: wsl --update).\n"
        "\n"
        "  In modern mode (kernel >= 5.1) CAP_DAC_READ_SEARCH is retained\n"
        "  after setup for file-handle resolution; all other capabilities\n"
        "  and the root UID/GID are relinquished.\n",
        prog);
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    int opt;
    const char *target_path;
    struct stat st;
    uint64_t event_mask;
    unsigned int mark_flags;

    static const struct option long_opts[] = {
        { "all",      no_argument, NULL, 'a' },
        { "syslog",   no_argument, NULL, 'l' },
        { "no-color", no_argument, NULL, 'n' },
        { "self",     no_argument, NULL, 's' },
        { "quiet",    no_argument, NULL, 'q' },
        { "version",  no_argument, NULL, 'v' },
        { "help",     no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "alnsqvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a': g_show_reads = 1; break;
        case 'l': g_use_syslog = 1; break;
        case 'n': g_use_color  = 0; break;
        case 's': g_show_self  = 1; break;
        case 'q': g_quiet      = 1; break;
        case 'v':
            printf("whodid v%s\n", WHODID_VERSION);
            return EXIT_SUCCESS;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "whodid: error: no path specified\n\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    target_path = argv[optind];

    /* ---- Privilege check ---- */
    if (geteuid() != 0) {
        fprintf(stderr,
            "whodid: error: root privileges required"
            " (fanotify needs CAP_SYS_ADMIN)\n"
            "  Try:  sudo whodid %s\n", target_path);
        return EXIT_FAILURE;
    }

    /* ---- Validate path ---- */
    if (stat(target_path, &st) < 0) {
        fprintf(stderr, "whodid: error: cannot access '%s': %s\n",
                target_path, strerror(errno));
        return EXIT_FAILURE;
    }

    /* ---- Normalise the filter path (resolve symlinks, strip trailing /) ---- */
    if (realpath(target_path, g_filter_path) == NULL) {
        if (strlen(target_path) >= sizeof(g_filter_path)) {
            fprintf(stderr, "whodid: error: path too long\n");
            return EXIT_FAILURE;
        }
        strncpy(g_filter_path, target_path, sizeof(g_filter_path) - 1);
        g_filter_path[sizeof(g_filter_path) - 1] = '\0';
    }
    /* Remove any trailing slash (realpath shouldn't leave one, but be safe) */
    {
        size_t flen = strlen(g_filter_path);
        while (flen > 1 && g_filter_path[flen - 1] == '/')
            g_filter_path[--flen] = '\0';
    }

    /* ---- Auto-disable colour when not writing to a terminal ---- */
    if (!isatty(STDOUT_FILENO))
        g_use_color = 0;

    /* ---- Open syslog connection when requested ---- */
    if (g_use_syslog)
        openlog("whodid", LOG_PID, LOG_DAEMON);

    /* ---- Open a mount-fd for open_by_handle_at (modern mode only) ----
     *
     * IMPORTANT: open_by_handle_at(2) requires a regular fd (not O_PATH)
     * as its mount_fd argument — the kernel rejects O_PATH fds with EBADF.
     * We open the filter path (or root) for reading; this fd stays open
     * throughout execution as the filesystem anchor.
     */
    g_mount_fd = open(g_filter_path, O_RDONLY | O_CLOEXEC);
    if (g_mount_fd < 0) {
        /* Non-fatal: fall back to root directory on the same filesystem */
        g_mount_fd = open("/", O_RDONLY | O_CLOEXEC);
    }

    /* ---- Initialise fanotify: try modern mode first ---- */
    g_fan_fd = fanotify_init(
        FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_DFID_NAME,
        O_RDONLY | O_LARGEFILE | O_CLOEXEC);

    if (g_fan_fd >= 0) {
        g_modern_mode = 1;
    } else if (errno == EINVAL || errno == ENOSYS) {
        /* Kernel too old for FAN_REPORT_DFID_NAME – use basic mode */
        if (!g_quiet) {
            fprintf(stderr,
                "whodid: kernel < 5.1 detected; running in basic mode\n"
                "         CREATE, DELETE and RENAME events will NOT be shown.\n");
        }
        g_fan_fd = fanotify_init(
            FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
            O_RDONLY | O_LARGEFILE | O_CLOEXEC);
        if (g_fan_fd < 0) {
            if (errno == EPERM)
                fprintf(stderr,
                    "whodid: error: CAP_SYS_ADMIN required\n"
                    "  Try:  sudo whodid %s\n", target_path);
            else
                perror("whodid: fanotify_init");
            if (g_mount_fd >= 0) close(g_mount_fd);
            return EXIT_FAILURE;
        }
    } else {
        if (errno == EPERM)
            fprintf(stderr,
                "whodid: error: CAP_SYS_ADMIN required for fanotify\n"
                "  Try:  sudo whodid %s\n", target_path);
        else
            perror("whodid: fanotify_init");
        if (g_mount_fd >= 0) close(g_mount_fd);
        return EXIT_FAILURE;
    }

    /* ---- Build the event mask ---- */
    if (g_modern_mode) {
        event_mask = FAN_MODIFY | FAN_CLOSE_WRITE
                   | FAN_CREATE | FAN_DELETE
                   | FAN_MOVED_FROM | FAN_MOVED_TO
                   | FAN_ATTRIB;
        if (g_show_reads)
            event_mask |= FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE;
    } else {
        event_mask = FAN_MODIFY | FAN_CLOSE_WRITE;
        if (g_show_reads)
            event_mask |= FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE;
    }

    /* ---- Mark the filesystem / mount point ----
     *
     * FAN_CREATE, FAN_DELETE, FAN_MOVED_*, FAN_ATTRIB require
     * FAN_MARK_FILESYSTEM (kernel >= 4.20).  FAN_MARK_MOUNT cannot carry
     * those event types and will return EINVAL if they are present.
     *
     * Strategy:
     *   modern mode → try FAN_MARK_FILESYSTEM first (full event set)
     *                 fall back to FAN_MARK_MOUNT with reduced mask
     *   basic mode  → FAN_MARK_MOUNT with MODIFY|CLOSE_WRITE only
     */
    if (g_modern_mode) {
        mark_flags = FAN_MARK_ADD | FAN_MARK_FILESYSTEM;
        if (fanotify_mark(g_fan_fd, mark_flags, event_mask,
                          AT_FDCWD, target_path) < 0) {
            if (errno == EINVAL) {
                /* FAN_MARK_FILESYSTEM not available (kernel < 4.20?);
                 * drop dirent events and fall back to FAN_MARK_MOUNT. */
                if (!g_quiet)
                    fprintf(stderr,
                        "whodid: FAN_MARK_FILESYSTEM unavailable;"
                        " falling back to mount-level monitoring\n"
                        "         CREATE, DELETE and RENAME events"
                        " will NOT be shown.\n");
                event_mask &= ~(FAN_CREATE | FAN_DELETE
                                | FAN_MOVED_FROM | FAN_MOVED_TO
                                | FAN_ATTRIB);
                mark_flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
                if (fanotify_mark(g_fan_fd, mark_flags, event_mask,
                                  AT_FDCWD, target_path) < 0) {
                    perror("whodid: fanotify_mark");
                    goto cleanup_fail;
                }
            } else {
                perror("whodid: fanotify_mark");
                goto cleanup_fail;
            }
        }
    } else {
        mark_flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
        if (fanotify_mark(g_fan_fd, mark_flags, event_mask,
                          AT_FDCWD, target_path) < 0) {
            perror("whodid: fanotify_mark");
            goto cleanup_fail;
        }
    }

    /* ---- Signal handling ---- */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP,  &sa, NULL);
    }

    /* ---- Drop elevated privileges ----
     *
     * All privileged setup (fanotify_init, fanotify_mark, open g_mount_fd)
     * is complete.  Shed root now to minimise the attack surface for the
     * duration of monitoring.  In modern mode we retain only
     * CAP_DAC_READ_SEARCH for open_by_handle_at(2); in basic mode all
     * extra capabilities are relinquished entirely.
     */
    if (drop_privileges(g_modern_mode) < 0) {
        fprintf(stderr, "whodid: error: failed to drop privileges — aborting\n");
        goto cleanup_fail;
    }

    print_banner(g_filter_path, g_modern_mode);

    /* ---- Event loop ---- */
    {
        struct pollfd pfd = { .fd = g_fan_fd, .events = POLLIN };

        while (g_running) {
            int ret = poll(&pfd, 1, 500);   /* 500 ms: check g_running twice/s */
            if (ret < 0) {
                if (errno == EINTR) continue;
                perror("whodid: poll");
                break;
            }
            if (ret > 0 && (pfd.revents & POLLIN))
                process_events(g_fan_fd);
        }
    }

    /* ---- Shutdown ---- */
    if (!g_quiet) {
        if (g_use_color)
            printf("\n%swhodid%s: stopped — %lu event(s) recorded.\n",
                   C_BOLD, C_RESET, g_event_count);
        else
            printf("\nwhodid: stopped — %lu event(s) recorded.\n",
                   g_event_count);
    }

    close(g_fan_fd);
    if (g_mount_fd >= 0) close(g_mount_fd);
    if (g_use_syslog) closelog();
    return EXIT_SUCCESS;

cleanup_fail:
    close(g_fan_fd);
    if (g_mount_fd >= 0) close(g_mount_fd);
    if (g_use_syslog) closelog();
    return EXIT_FAILURE;
}
