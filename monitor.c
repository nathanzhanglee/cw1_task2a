#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>

#define MAX_USERS 1000
#define MAX_PROCESSES 10000
#define MAX_LINE 1024

// Structure to track per-process CPU usage
typedef struct {
    pid_t pid;
    uid_t uid;
    unsigned long utime;  // user mode CPU time
    unsigned long stime;  // kernel mode CPU time
} ProcessInfo;

// Structure to track per-user CPU usage
typedef struct {
    uid_t uid;
    char username[256];
    unsigned long long total_cpu_ms;  // total CPU time in milliseconds
} UserInfo;

// Global arrays to track processes and users
ProcessInfo baseline[MAX_PROCESSES];
int baseline_count = 0;

UserInfo users[MAX_USERS];
int user_count = 0;

ProcessInfo last_sample[MAX_PROCESSES];
int last_sample_count = 0;

// Check if a string represents a valid PID (all digits)
int is_number(const char *str) {
    if (str == NULL || *str == '\0')
        return 0;
    
    while (*str) {
        if (!isdigit(*str))
            return 0;
        str++;
    }
    return 1;
}


// Read the UID of a process from /proc/<pid>/status
uid_t get_process_uid(pid_t pid) {
    char path[256];
    char line[MAX_LINE];
    FILE *fp;
    uid_t uid = -1;
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    
    if (fp == NULL)
        return -1;
    
    // Look for the "Uid:" line
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            // Format: "Uid:  1000  1000  1000  1000"
            // We want the first UID (real UID)
            sscanf(line + 4, "%u", &uid);
            break;
        }
    }
    
    fclose(fp);
    return uid;
}

// Read CPU times (utime, stime) from /proc/<pid>/stat
int get_process_cpu_times(pid_t pid, unsigned long *utime, unsigned long *stime) {
    char path[256];
    char line[MAX_LINE];
    FILE *fp;
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    
    if (fp == NULL)
        return -1;
    
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    
    // Parse the stat file
    // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ...
    // We need fields 14 (utime) and 15 (stime)
    
    char *p = line;
    
    // Skip to the end of the command name in parentheses
    // The comm field can contain spaces and special characters, so we need to find the last ')'
    p = strrchr(line, ')');
    if (p == NULL)
        return -1;
    
    p += 2;  // Skip ") "
    
    // Now parse fields: state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime
    // We need to skip fields 3-13 to get to utime (field 14) and stime (field 15)
    char state;
    int ppid, pgrp, session, tty_nr, tpgid;
    unsigned int flags;
    unsigned long minflt, cminflt, majflt, cmajflt;
    
    int ret = sscanf(p, "%c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu",
                     &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
                     &minflt, &cminflt, &majflt, &cmajflt, utime, stime);
    
    if (ret != 13)
        return -1;
    
    return 0;
}

// Convert UID to username
void get_username(uid_t uid, char *username, size_t size) {
    struct passwd *pw = getpwuid(uid);
    
    if (pw != NULL) {
        snprintf(username, size, "%s", pw->pw_name);
    } else {
        // If username not found, use UID as string
        snprintf(username, size, "%u", uid);
    }
}


// Find or create a user entry in the users array
UserInfo* find_or_create_user(uid_t uid) {
    // First, try to find existing user
    for (int i = 0; i < user_count; i++) {
        if (users[i].uid == uid)
            return &users[i];
    }
    
    // Not found, create new entry
    if (user_count >= MAX_USERS) {
        fprintf(stderr, "Warning: MAX_USERS exceeded\n");
        return NULL;
    }
    
    users[user_count].uid = uid;
    users[user_count].total_cpu_ms = 0;
    get_username(uid, users[user_count].username, sizeof(users[user_count].username));
    
    return &users[user_count++];
}


// Take a baseline snapshot of all current processes
void take_baseline_snapshot() {
    DIR *proc_dir;
    struct dirent *entry;
    
    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("opendir /proc");
        exit(1);
    }
    
    baseline_count = 0;
    
    // Iterate through all entries in /proc
    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if the directory name is a number (PID)
        if (!is_number(entry->d_name))
            continue;
        
        pid_t pid = atoi(entry->d_name);
        unsigned long utime, stime;
        uid_t uid;
        
        // Get CPU times
        if (get_process_cpu_times(pid, &utime, &stime) != 0)
            continue;
        
        // Get UID
        uid = get_process_uid(pid);
        if (uid == (uid_t)-1)
            continue;
        
        // Store in baseline
        if (baseline_count < MAX_PROCESSES) {
            baseline[baseline_count].pid = pid;
            baseline[baseline_count].uid = uid;
            baseline[baseline_count].utime = utime;
            baseline[baseline_count].stime = stime;
            baseline_count++;
        }
    }
    
    closedir(proc_dir);
}

// Update CPU usage for all current processes
void update_cpu_usage(long clock_ticks_per_sec) {
    DIR *proc_dir;
    struct dirent *entry;
    ProcessInfo current_sample[MAX_PROCESSES];
    int current_count = 0;
    
    proc_dir = opendir("/proc");
    if (proc_dir == NULL)
        return;
    
    // First pass: collect current data
    while ((entry = readdir(proc_dir)) != NULL && current_count < MAX_PROCESSES) {
        if (!is_number(entry->d_name))
            continue;
        
        pid_t pid = atoi(entry->d_name);
        unsigned long utime_now, stime_now;
        uid_t uid;
        
        if (get_process_cpu_times(pid, &utime_now, &stime_now) != 0)
            continue;
        
        uid = get_process_uid(pid);
        if (uid == (uid_t)-1)
            continue;
        
        current_sample[current_count].pid = pid;
        current_sample[current_count].uid = uid;
        current_sample[current_count].utime = utime_now;
        current_sample[current_count].stime = stime_now;
        current_count++;
    }
    closedir(proc_dir);
    
    // Second pass: calculate deltas from last sample (not from baseline!)
    for (int i = 0; i < current_count; i++) {
        pid_t pid = current_sample[i].pid;
        uid_t uid = current_sample[i].uid;
        unsigned long utime_now = current_sample[i].utime;
        unsigned long stime_now = current_sample[i].stime;
        
        unsigned long utime_delta = 0;
        unsigned long stime_delta = 0;
        
        // Find in last sample
        int found_in_last = 0;
        for (int j = 0; j < last_sample_count; j++) {
            if (last_sample[j].pid == pid) {
                // Delta since last sample
                utime_delta = utime_now - last_sample[j].utime;
                stime_delta = stime_now - last_sample[j].stime;
                found_in_last = 1;
                break;
            }
        }
        
        if (!found_in_last) {
            // New process - find in baseline
            int found_in_baseline = 0;  // ← ADD THIS FLAG
            for (int j = 0; j < baseline_count; j++) {
                if (baseline[j].pid == pid) {
                    utime_delta = utime_now - baseline[j].utime;
                    stime_delta = stime_now - baseline[j].stime;
                    found_in_baseline = 1;  // ← SET FLAG
                    break;
                }
            }
            // If not in baseline either, it's completely new
            if (!found_in_baseline) {  // ← FIX: Check flag instead of delta values!
                utime_delta = utime_now;
                stime_delta = stime_now;
            }
        }
        
        unsigned long total_ticks = utime_delta + stime_delta;
        unsigned long long cpu_ms = (total_ticks * 1000ULL) / clock_ticks_per_sec;
        
        UserInfo *user = find_or_create_user(uid);
        if (user != NULL) {
            user->total_cpu_ms += cpu_ms;
        }
    }
    
    // Update last_sample for next iteration
    memcpy(last_sample, current_sample, sizeof(ProcessInfo) * current_count);
    last_sample_count = current_count;
}


// Comparison function for qsort (descending order by CPU time)
int compare_users(const void *a, const void *b) {
    const UserInfo *user_a = (const UserInfo *)a;
    const UserInfo *user_b = (const UserInfo *)b;
    
    if (user_b->total_cpu_ms > user_a->total_cpu_ms)
        return 1;
    else if (user_b->total_cpu_ms < user_a->total_cpu_ms)
        return -1;
    else
        return 0;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <duration_in_seconds>\n", argv[0]);
        return 1;
    }
    
    int duration = atoi(argv[1]);
    if (duration <= 0) {
        fprintf(stderr, "Error: Duration must be a positive integer\n");
        return 1;
    }
    
    // Get clock ticks per second
    long clock_ticks_per_sec = sysconf(_SC_CLK_TCK);
    if (clock_ticks_per_sec == -1) {
        perror("sysconf");
        return 1;
    }
    
    // Take initial baseline snapshot
    take_baseline_snapshot();
    
    // Clear user totals (in case we want to run multiple times)
    user_count = 0;
    
    // Monitor for the specified duration
    for (int elapsed = 0; elapsed < duration; elapsed++) {
        sleep(1);  // Sleep for 1 second
        update_cpu_usage(clock_ticks_per_sec);
    }
    
    // Sort users by CPU time (descending)
    qsort(users, user_count, sizeof(UserInfo), compare_users);
    
    // Print results
    printf("Rank User CPU Time (milliseconds)\n");
    printf("----------------------------------------\n");
    
    for (int i = 0; i < user_count; i++) {
        printf("%-4d %-15s %llu\n", i + 1, users[i].username, users[i].total_cpu_ms);
    }
    
    return 0;
}