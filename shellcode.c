#include <stdio.h>
#include <string.h>

void main() {
    unsigned char code[] = "%s";
    void (*s)() = (void *)code;
    s();
}
