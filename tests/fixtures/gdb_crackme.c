/* gdb-bridge validation fixture: a small serial crackme with ptrace
 * anti-debug.  serial = Σ (name[i] ^ (i+2)) mod 2^64, printed as decimal —
 * the same formula as the Root-Me KeygenMe that motivated v0.3.3's raw
 * disassembler.  The ptrace(TRACEME) check fails under a debugger, so a
 * real solve must patch $rax=0 after the call — exactly the workflow the
 * bridge exists to support. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>

int main(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        printf("[!] debugger detected, exiting\n");
        return 1;
    }
    char buf[64];
    printf("serial: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;

    const char *name = "lvr";
    unsigned long long want = 0;
    for (int i = 0; name[i]; i++)
        want += (unsigned long long)(unsigned char)name[i] ^ (unsigned long long)(i + 2);
    want %= 0xFFFFFFFFFFFFFFFFULL;

    char expect[32];
    snprintf(expect, sizeof(expect), "%llu", want);

    if (strcmp(buf, expect) == 0) {
        printf("correct! %s\n", expect);
        return 0;
    }
    printf("wrong (want %s)\n", expect);
    return 1;
}
