#ifndef _KEYUTILS_H_
#define _KEYUTILS_H_

#include <linux/keyctl.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <string>

__BEGIN_DECLS

typedef int32_t key_serial_t;

key_serial_t add_key(const char* type, const char* description, const void* payload,
                     size_t payload_length, key_serial_t ring_id);

key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create);

long keyctl_revoke(key_serial_t id); /* TODO: remove this */

long keyctl_search(key_serial_t ring_id, const char* type, const char* description,
                   key_serial_t dest_ring_id);

long keyctl_setperm(key_serial_t id, int permissions);

long keyctl_unlink(key_serial_t key, key_serial_t keyring);

int e4crypt_install_keyring();
bool installKey(const std::string& key);

__END_DECLS

#endif