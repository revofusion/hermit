#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    assert(getuid() == 1234 && geteuid() == 1234);
    assert(getgid() == 5678 && getegid() == 5678);
    assert(getresuid(&ruid, &euid, &suid) == 0);
    assert(ruid == 1234 && euid == 1234 && suid == 1234);
    assert(getresgid(&rgid, &egid, &sgid) == 0);
    assert(rgid == 5678 && egid == 5678 && sgid == 5678);
    assert(setuid(1234) == 0 && setgid(5678) == 0);
    assert(setresuid((uid_t)-1, 1234, (uid_t)-1) == 0);
    assert(setresgid(5678, (gid_t)-1, 5678) == 0);
    errno = 0;
    assert(setuid(0) == -1 && errno == EPERM);
    errno = 0;
    assert(setgid(0) == -1 && errno == EPERM);
    assert(setfsuid(0) == 1234 && setfsgid(0) == 5678);
    assert(geteuid() == 1234 && getegid() == 5678);
    char path[] = "/tmp/hermit-identity-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    struct stat metadata;
    assert(fstat(fd, &metadata) == 0);
    assert(metadata.st_uid == getuid() && metadata.st_gid == getgid());
    assert(stat(path, &metadata) == 0);
    assert(metadata.st_uid == getuid() && metadata.st_gid == getgid());
    assert(close(fd) == 0 && unlink(path) == 0);
    puts("fixed-guest-identity-ok");
    return 0;
}
