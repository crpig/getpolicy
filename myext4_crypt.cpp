/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "myext4_crypt.h"

#include <array>

#include <asm/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>


// ext4enc:TODO Include structure from somewhere sensible
// MUST be in sync with ext4_crypto.c in kernel
#define EXT4_KEY_DESCRIPTOR_SIZE 8
#define EXT4_KEY_DESCRIPTOR_SIZE_HEX 17

struct ext4_encryption_policy {
    uint8_t version;
    uint8_t contents_encryption_mode;
    uint8_t filenames_encryption_mode;
    uint8_t flags;
    uint8_t master_key_descriptor[EXT4_KEY_DESCRIPTOR_SIZE];
} __attribute__((__packed__));

#define EXT4_ENCRYPTION_MODE_AES_256_XTS    1
#define EXT4_ENCRYPTION_MODE_AES_256_CTS    4
#define EXT4_ENCRYPTION_MODE_AES_256_HEH    126
#define EXT4_ENCRYPTION_MODE_PRIVATE        127

#define EXT4_POLICY_FLAGS_PAD_4         0x00
#define EXT4_POLICY_FLAGS_PAD_8         0x01
#define EXT4_POLICY_FLAGS_PAD_16        0x02
#define EXT4_POLICY_FLAGS_PAD_32        0x03
#define EXT4_POLICY_FLAGS_PAD_MASK      0x03
#define EXT4_POLICY_FLAGS_VALID         0x03

// ext4enc:TODO Get value from somewhere sensible
#define EXT4_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct ext4_encryption_policy)
#define EXT4_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct ext4_encryption_policy)

#define HEX_LOOKUP "0123456789ABCDEF"

static void policy_to_hex(const char* policy, char* hex) {
    for (size_t i = 0, j = 0; i < EXT4_KEY_DESCRIPTOR_SIZE; i++) {
        hex[j++] = HEX_LOOKUP[(policy[i] & 0xF0) >> 4];
        hex[j++] = HEX_LOOKUP[policy[i] & 0x0F];
    }
    hex[EXT4_KEY_DESCRIPTOR_SIZE_HEX - 1] = '\0';
}

static bool is_dir_empty(const char *dirname, bool *is_empty)
{
    int n = 0;
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(dirname), closedir);
    if (!dirp) {
        printf("Unable to read directory: [%s]\n", dirname);
        return false;
    }
    for (;;) {
        errno = 0;
        auto entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                printf("Unable to read directory: [%s]\n", dirname);
                return false;
            }
            break;
        }
        if (strcmp(entry->d_name, "lost+found") != 0) { // Skip lost+found
            ++n;
            if (n > 2) {
                *is_empty = false;
                return true;
            }
        }
    }
    *is_empty = true;
    return true;
}

bool e4crypt_policy_print(const char *directory)
{
    char existing_policy_hex[EXT4_KEY_DESCRIPTOR_SIZE_HEX];
    int fd = open(directory, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        printf("Failed to open directory [%s]\n", directory);
        return false;
    }

    char dirfullpath[PATH_MAX] = {0};
    realpath(directory, dirfullpath);

    ext4_encryption_policy eep;
    memset(&eep, 0, sizeof(ext4_encryption_policy));
    if (ioctl(fd, EXT4_IOC_GET_ENCRYPTION_POLICY, &eep) != 0) {
        printf("Failed to get encryption policy for [%s]\n", dirfullpath);
        close(fd);
        return false;
    }
    close(fd);

    policy_to_hex((const char*)eep.master_key_descriptor, existing_policy_hex);
    printf("============= %s ============\n", dirfullpath);
    printf("Version: 0x%.2X\n", eep.version);
    printf("Contents Encryption Mode: 0x%.2X\n", eep.contents_encryption_mode);
    printf("Filename Encryption Mode: 0x%.2X\n", eep.filenames_encryption_mode);
    printf("Flags: 0x%.2X\n", eep.flags);

    printf("Found policy [%s] at [%s]\n", existing_policy_hex, dirfullpath);
    printf("============= %s ============\n", dirfullpath);

    return true;
}
