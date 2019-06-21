/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _EXT4_CRYPT_H_
#define _EXT4_CRYPT_H_

#include <sys/cdefs.h>
#include <stdbool.h>

__BEGIN_DECLS


bool e4crypt_policy_print(const char *directory);

static const char* e4crypt_unencrypted_folder = "/unencrypted";
static const char* e4crypt_key_ref = "/unencrypted/ref";
static const char* e4crypt_key_mode = "/unencrypted/mode";

__END_DECLS

#endif // _EXT4_CRYPT_H_
