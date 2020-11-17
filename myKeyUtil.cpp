#include "myKeyUtil.h"

#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>


// ext4enc:TODO get this const from somewhere good
const int EXT4_KEY_DESCRIPTOR_SIZE = 8;

// ext4enc:TODO Include structure from somewhere sensible
// MUST be in sync with ext4_crypto.c in kernel
constexpr int EXT4_ENCRYPTION_MODE_AES_256_XTS = 1;
constexpr int EXT4_AES_256_XTS_KEY_SIZE = 64;
constexpr int EXT4_MAX_KEY_SIZE = 64;
struct ext4_encryption_key {
    uint32_t mode;
    char raw[EXT4_MAX_KEY_SIZE];
    uint32_t size;
};

static char const* const NAME_PREFIXES[] = {
    "ext4",
    "f2fs",
    "fscrypt",
    nullptr
};

// Init keyring we store all keys in
int e4crypt_install_keyring()
{
    key_serial_t device_keyring = add_key("keyring", "e4crypt", 0, 0,
                                          KEY_SPEC_SESSION_KEYRING);

    if (device_keyring == -1) {
        printf("Failed to create keyring errno=%d err=[%s]\n", errno, strerror(errno));
        return -1;
    }

    printf("Keyring created with id 0x%.8X\n", device_keyring);

    return 0;
}

static std::string keyname(const std::string& prefix, const std::string& raw_ref) {
    std::ostringstream o;
    o << prefix << ":";
    for (unsigned char i : raw_ref) {
        o << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    return o.str();
}

// Get the keyring we store all keys in
static bool e4cryptKeyring(key_serial_t* device_keyring) {
    *device_keyring = keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "e4crypt", 0);
    if (*device_keyring == -1) {
        printf("Unable to find device keyring\n");
        return false;
    }
    return true;
}

// Get raw keyref - used to make keyname and to pass to ioctl
static std::string generateKeyRef(const char* key, int length) {
    SHA512_CTX c;

    SHA512_Init(&c);
    SHA512_Update(&c, key, length);
    unsigned char key_ref1[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref1, &c);

    SHA512_Init(&c);
    SHA512_Update(&c, key_ref1, SHA512_DIGEST_LENGTH);
    unsigned char key_ref2[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref2, &c);

    static_assert(EXT4_KEY_DESCRIPTOR_SIZE <= SHA512_DIGEST_LENGTH,
                  "Hash too short for descriptor");
    return std::string((char*)key_ref2, EXT4_KEY_DESCRIPTOR_SIZE);
}


static bool fillKey(const std::string& key, ext4_encryption_key* ext4_key) {
    if (key.size() != EXT4_AES_256_XTS_KEY_SIZE) {
        printf("Wrong size key = %zd\n", key.size());
        return false;
    }
    static_assert(EXT4_AES_256_XTS_KEY_SIZE <= sizeof(ext4_key->raw), "Key too long!");
    ext4_key->mode = EXT4_ENCRYPTION_MODE_AES_256_XTS;
    ext4_key->size = key.size();
    memset(ext4_key->raw, 0, sizeof(ext4_key->raw));
    memcpy(ext4_key->raw, key.data(), key.size());

    std::string str(ext4_key->raw, EXT4_MAX_KEY_SIZE);
    std::ostringstream o;
    for (unsigned char i : str) {
        o << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    printf("Raw key: %s\n", o.str().c_str());
    return true;
}

// Install password into global keyring
// Return raw key reference for use in policy
bool installKey(const std::string& key) {
    // Place ext4_encryption_key into automatically zeroing buffer.
    ext4_encryption_key ext4_key;
    memset(&ext4_key, 0, sizeof(ext4_key));

    if (!fillKey(key, &ext4_key)) return false;
    std::string raw_ref = generateKeyRef(ext4_key.raw, ext4_key.size);
    key_serial_t device_keyring;
    if (!e4cryptKeyring(&device_keyring)) return false;
    for (char const* const* name_prefix = NAME_PREFIXES; *name_prefix != nullptr; name_prefix++) {
        auto ref = keyname(*name_prefix, raw_ref);
        key_serial_t key_id =
            add_key("logon", ref.c_str(), (void*)&ext4_key, sizeof(ext4_key), device_keyring);
        if (key_id == -1) {
            printf("Failed to insert key into keyring 0x%.8X\n", device_keyring);
            return false;
        }
        printf("Added key 0x%.8X (%s) to keyring 0x%.8X\n", key_id, ref.c_str(), device_keyring);
    }
    return true;
}


// Deliberately not exposed. Callers should use the typed APIs instead.
static long keyctl(int cmd, ...) {
  va_list va;
  va_start(va, cmd);
  unsigned long arg2 = va_arg(va, unsigned long);
  unsigned long arg3 = va_arg(va, unsigned long);
  unsigned long arg4 = va_arg(va, unsigned long);
  unsigned long arg5 = va_arg(va, unsigned long);
  va_end(va);
  return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}

key_serial_t add_key(const char* type, const char* description, const void* payload,
                     size_t payload_length, key_serial_t ring_id) {
  return syscall(__NR_add_key, type, description, payload, payload_length, ring_id);
}

key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create) {
  return keyctl(KEYCTL_GET_KEYRING_ID, id, create);
}

long keyctl_revoke(key_serial_t id) {
  return keyctl(KEYCTL_REVOKE, id);
}

long keyctl_search(key_serial_t ring_id, const char* type, const char* description,
                   key_serial_t dest_ring_id) {
  return keyctl(KEYCTL_SEARCH, ring_id, type, description, dest_ring_id);
}

long keyctl_setperm(key_serial_t id, int permissions) {
  return keyctl(KEYCTL_SETPERM, id, permissions);
}

long keyctl_unlink(key_serial_t key, key_serial_t keyring) {
  return keyctl(KEYCTL_UNLINK, key, keyring);
}
