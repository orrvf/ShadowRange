
#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int parse_region(const char* line, struct MemoryRegion* region) {
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

    const char* path = line + path_position;

    if (*path == '\0' || *path == '\n') {
        strcpy(region->path, "-----");
    }
    else {
        snprintf(region->path, sizeof(region->path), "%s", path);
        region->path[strcspn(region->path, "\n")] = '\0';
    }

    return 1;
}

void write_json_string(FILE* output, const char* value) {
    fputc('"', output);

    for (const unsigned char* p = (const unsigned char*)value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', output);
            fputc(*p, output);
        }
        else if (*p < 32) {
            fprintf(output, "\\u%04x", (unsigned int)*p);
        }
        else {
            fputc(*p, output);
        }
    }

    fputc('"', output);
}

void write_region(FILE* output, int pid, const struct MemoryRegion* region) {
    fprintf(
        output,
        "{\"pid\":%d,\"start\":%" PRIu64
        ",\"end\":%" PRIu64
        ",\"offset\":%" PRIu64
        ",\"inode\":%" PRIu64
        ",\"permissions\":",
        pid,
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

int main(void) {
    FILE* input = fopen("/proc/self/maps", "r");

    if (input == NULL) {
        perror("Cannot open /proc/self/maps");
        return 1;
    }

    FILE* output = fopen(OUTPUT_FILE, "w");

    if (output == NULL) {
        perror("Cannot open telemetry output");
        fclose(input);
        return 1;
    }

    char line[LINE_SIZE];
    int pid = (int)getpid();
    int count = 0;
    int invalid = 0;

    while (fgets(line, sizeof(line), input) != NULL) {
        if (strchr(line, '\n') == NULL && !feof(input)) {
            fprintf(stderr, "Input line too long\n");
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

    printf("ShadowRange proc_monitor\n");
    printf("PID: %d\n", pid);
    printf("Regions collected: %d\n", count);
    printf("Invalid regions: %d\n", invalid);
    printf("Output: %s\n", OUTPUT_FILE);

    return 0;
}
