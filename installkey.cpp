#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "myKeyUtil.h"

std::string hex2str(std::string str)
{
     std::string ret;

    const char *data = str.data();
    uint32_t num = 0;
    for(int16_t i=0; i<(str.length()/2); i++)
    {
        sscanf(data+i*2, "%02X", &num);

        char key = num & 0xFF;
        ret.append(&key, 1);
    }

    return ret;
}

int main(int argc, char *argv[])
{
    std::string test("364d5fa91847715ec90074b389dfc71fb3f8d27ac37e492237fbb8c51b12b1dc9b03cc1cb3eae8c7614fd8f608bd1a66ea506daf7dcea17b5494645bef2b7533");
    std::string ret = hex2str(test);

    if(e4crypt_install_keyring() == 0) {
        sleep(1);
        installKey(ret);
    }
    return 0;
}