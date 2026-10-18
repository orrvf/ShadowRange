
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define LINE_SIZE 4096
#define OUTPUT_FILE "shadowrange.telemetry"

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint64_t inode;
    char permissions[5];
    char device[6];
    char path[LINE_SIZE];
};

struct ProcessInfo {
    char name[256];
    char state[128];
    long ppid;
    char cmdline[LINE_SIZE];
    char exe[LINE_SIZE];
};

int parse_pid(const char *text, pid_t *pid) {
    char *endptr;
    errno = 0;

    long value = strtol(text, &endptr, 10);

    if (errno != 0 || text == endptr || *endptr != '\0' ||
        value <= 0 || value > INT_MAX) {
        return 0;
    }

    *pid = (pid_t)value;
    return 1;
}

void write_json_string(FILE *output, const char *value) {
    fputc('"', output);

    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', output);
            fputc(*p, output);
        } else if (*p < 32) {
            fprintf(output, "\\u%04x", (unsigned int)*p);
        } else {
            fputc(*p, output);
        }
    }

    fputc('"', output);
}

void trim_newline(char *text) {
    text[strcspn(text, "\n")] = '\0';
}

int read_process_status(pid_t pid, struct ProcessInfo *info) {
    char filename[64];

    snprintf(filename, sizeof(filename),
             "/proc/%ld/status", (long)pid);

    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        perror("Cannot open process status");
        return 0;
    }

    char line[LINE_SIZE];

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "Name:", 5) == 0) {
            if (sscanf(line + 5, "%255s", info->name) != 1) {
                info->name[0] = '\0';
            }
        } else if (strncmp(line, "State:", 6) == 0) {
            char *value = line + 6;

            while (*value == ' ' || *value == '\t') {
                value++;
            }

            snprintf(info->state, sizeof(info->state),
                     "%s", value);
            trim_newline(info->state);
        } else if (strncmp(line, "PPid:", 5) == 0) {
            long parent;

            if (sscanf(line + 5, "%ld", &parent) == 1) {
                info->ppid = parent;
            }
        }
    }

    int read_error = ferror(file);
    fclose(file);

    if (read_error) {
        fprintf(stderr, "Error reading process status\n");
        return 0;
    }

    return 1;
}

void read_process_cmdline(pid_t pid, struct ProcessInfo *info) {
    char filename[64];

    snprintf(filename, sizeof(filename),
             "/proc/%ld/cmdline", (long)pid);

    FILE *file = fopen(filename, "rb");

    if (file == NULL) {
        return;
    }

    size_t length = fread(info->cmdline, 1,
                          sizeof(info->cmdline) - 1, file);

    fclose(file);

    for (size_t i = 0; i < length; i++) {
        if (info->cmdline[i] == '\0') {
            info->cmdline[i] = ' ';
        }
    }

    while (length > 0 && info->cmdline[length - 1] == ' ') {
        length--;
    }

    info->cmdline[length] = '\0';
}

void read_process_exe(pid_t pid, struct ProcessInfo *info) {
    char filename[64];

    snprintf(filename, sizeof(filename),
             "/proc/%ld/exe", (long)pid);

    ssize_t length = readlink(filename, info->exe,
                              sizeof(info->exe) - 1);

    if (length < 0) {
        return;
    }

    info->exe[length] = '\0';
}

int parse_region(const char *line, struct MemoryRegion *region) {
    unsigned long long start, end, offset, inode;
    int path_position = 0;

    region->path[0] = '\0';

    int fields = sscanf(
        line,
        "%llx-%llx %4s %llx %5s %llu %n",
        &start,
        &end,
        region->permissions,
        &offset,
        region->device,
        &inode,
        &path_position
    );

    if (fields != 6 || start >= end || path_position <= 0) {
        return 0;
    }

    region->start = (uint64_t)start;
    region->end = (uint64_t)end;
    region->offset = (uint64_t)offset;
    region->inode = (uint64_t)inode;

    const char *path = line + path_position;

    if (*path == '\0' || *path == '\n') {
        strcpy(region->path, "-----");
    } else {
        snprintf(region->path, sizeof(region->path), "%s", path);
        trim_newline(region->path);
    }

    return 1;
}

void write_process(FILE *output, pid_t pid,
                   const struct ProcessInfo *info) {
    fprintf(output, "{\"type\":\"process\",\"pid\":%ld",
            (long)pid);

    fprintf(output, ",\"name\":");
    write_json_string(output, info->name);

    fprintf(output, ",\"state\":");
    write_json_string(output, info->state);

    fprintf(output, ",\"ppid\":%ld", info->ppid);

    fprintf(output, ",\"cmdline\":");
    write_json_string(output, info->cmdline);

    fprintf(output, ",\"exe\":");
    write_json_string(output, info->exe);

    fprintf(output, "}\n");
}

void write_region(FILE *output, pid_t pid,
                  const struct MemoryRegion *region) {
    fprintf(
        output,
        "{\"type\":\"memory_region\",\"pid\":%ld"
        ",\"start\":%" PRIu64
        ",\"end\":%" PRIu64
        ",\"offset\":%" PRIu64
        ",\"inode\":%" PRIu64
        ",\"permissions\":",
        (long)pid,
        region->start,
        region->end,
        region->offset,
        region->inode
    );

    write_json_string(output, region->permissions);

    fprintf(output, ",\"device\":");
    write_json_string(output, region->device);

    fprintf(output, ",\"path\":");
    write_json_string(output, region->path);

    fprintf(output, "}\n");
}

int main(int argc, char *argv[]) {
    pid_t pid = getpid();

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [PID]\n", argv[0]);
        return 1;
    }

    if (argc == 2 && !parse_pid(argv[1], &pid)) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    char maps_file[64];

    snprintf(maps_file, sizeof(maps_file),
             "/proc/%ld/maps", (long)pid);

    FILE *input = fopen(maps_file, "r");

    if (input == NULL) {
        perror("Cannot open process maps");
        return 1;
    }

    struct ProcessInfo info = {0};

    strcpy(info.name, "unknown");
    strcpy(info.state, "unknown");
    strcpy(info.cmdline, "unavailable");
    strcpy(info.exe, "unavailable");

    if (!read_process_status(pid, &info)) {
        fclose(input);
        return 1;
    }

    read_process_cmdline(pid, &info);
    read_process_exe(pid, &info);

    FILE *output = fopen(OUTPUT_FILE, "w");

    if (output == NULL) {
        perror("Cannot open telemetry output");
        fclose(input);
        return 1;
    }

    write_process(output, pid, &info);

    char line[LINE_SIZE];
    int count = 0;
    int invalid = 0;

    while (fgets(line, sizeof(line), input) != NULL) {
        if (strchr(line, '\n') == NULL && !feof(input)) {
            invalid++;

            int ch;
            while ((ch = fgetc(input)) != '\n' && ch != EOF) {
            }

            continue;
        }

        struct MemoryRegion region;

        if (!parse_region(line, &region)) {
            invalid++;
            continue;
        }

        write_region(output, pid, &region);
        count++;
    }

    int read_error = ferror(input);

    if (fclose(output) != 0) {
        perror("Cannot close telemetry output");
        fclose(input);
        return 1;
    }

    fclose(input);

    if (read_error) {
        fprintf(stderr, "Error reading process maps\n");
        return 1;
    }

    printf("ShadowRange Process Monitor\n");
    printf("Target PID: %ld\n", (long)pid);
    printf("Process: %s\n", info.name);
    printf("Parent PID: %ld\n", info.ppid);
    printf("Executable: %s\n", info.exe);
    printf("Regions collected: %d\n", count);
    printf("Invalid regions: %d\n", invalid);
    printf("Output: %s\n", OUTPUT_FILE);

    return 0;
}
