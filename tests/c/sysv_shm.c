/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
  fprintf(stderr, "sysv_shm:%d: %s errno=%d\n", __LINE__, #condition, errno); exit(1); \
} } while (0)
#define FAILS(expression, error) do { errno = 0; CHECK((expression) == -1); CHECK(errno == (error)); } while (0)

static struct shmid_ds status(int id, unsigned long count) {
  struct shmid_ds info;
  memset(&info, 0xa5, sizeof(info));
  CHECK(shmctl(id, IPC_STAT, &info) == 0);
  CHECK(info.shm_nattch == count);
  CHECK(info.shm_segsz == 56);
  CHECK(info.shm_perm.cuid == getuid());
  CHECK(info.shm_perm.cgid == getgid());
  return info;
}

static void reap(pid_t pid) {
  int result;
  CHECK(waitpid(pid, &result, 0) == pid);
  CHECK(WIFEXITED(result) && WEXITSTATUS(result) == 0);
}

/* Transport descriptors must never survive a successful or failed attachment,
 * nor may their cleanup close an application-owned descriptor with a reused
 * number. Check both the next allocation slot and a live canary descriptor. */
static void descriptors_unchanged(int canary, int next_fd) {
  int duplicate = dup(canary);
  CHECK(duplicate == next_fd);
  CHECK(close(duplicate) == 0);
  CHECK(write(canary, "x", 1) == 1);
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "after-exec") == 0) {
    status(atoi(argv[2]), 1); /* exec detached the child's inherited mapping */
    volatile uint32_t *fresh = shmat(atoi(argv[2]), NULL, 0);
    CHECK(fresh != (void *)-1 && fresh[0] == 789 && fresh[1] == 456);
    status(atoi(argv[2]), 2);
    CHECK(shmdt((const void *)fresh) == 0);
    return 0;
  }
  CHECK(argc == 1);
  int canary = open("/dev/null", O_RDWR | O_CLOEXEC);
  CHECK(canary >= 0);
  int next_fd = dup(canary);
  CHECK(next_fd >= 0 && close(next_fd) == 0);
  const key_t key = 0x513748;
  FAILS(shmget(key, 56, 0600), ENOENT);
  FAILS(shmget(IPC_PRIVATE, 0, 0600), EINVAL);
  FAILS(shmget(IPC_PRIVATE, SIZE_MAX, 0600), EINVAL);
  FAILS(shmget(IPC_PRIVATE, 56, SHM_HUGETLB | 0600), EOPNOTSUPP);
  int id = shmget(key, 56, IPC_CREAT | IPC_EXCL | 0600);
  CHECK(id >= 0);
  FAILS(shmget(key, 56, IPC_CREAT | IPC_EXCL | 0600), EEXIST);
  CHECK(shmget(key, 0, 0600) == id);
  FAILS(shmget(key, 57, 0600), EINVAL);
  struct shmid_ds info = status(id, 0);
  CHECK(info.shm_cpid == getpid() && info.shm_atime == 0 && info.shm_dtime == 0);
  CHECK(info.shm_ctime > 0);
  volatile uint32_t *shared = shmat(id, NULL, 0);
  CHECK(shared != (void *)-1);
  CHECK(shared[0] == 0 && shared[1] == 0);
  shared[0] = 123;
  info = status(id, 1);
  CHECK(info.shm_lpid == getpid() && info.shm_atime >= info.shm_ctime);
  errno = 0;
  CHECK(shmat(id, (void *)shared, 0) == (void *)-1 && errno == EINVAL);
  status(id, 1); /* failed map must release its reservation without an attachment */
  FAILS(shmctl(id, IPC_STAT, NULL), EFAULT);
  FAILS(shmctl(id, IPC_SET, NULL), EFAULT);
  FAILS(shmctl(id, SHM_LOCK, NULL), EOPNOTSUPP);
  FAILS(shmdt((const void *)(shared + 1)), EINVAL);
  FAILS(munmap((void *)shared, 4096), EOPNOTSUPP);
  FAILS(madvise((void *)shared, 4096, MADV_DONTFORK), EOPNOTSUPP);
  FAILS(syscall(SYS_mremap, shared, 0, 4096, MREMAP_MAYMOVE), EOPNOTSUPP);
  errno = 0;
  CHECK(shmat(id, (void *)shared, SHM_REMAP) == (void *)-1 && errno == EOPNOTSUPP);
  errno = 0;
  CHECK(mmap((void *)shared, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED);
  CHECK(errno == EOPNOTSUPP && shared[0] == 123);
  const volatile uint32_t *alias = shmat(id, NULL, SHM_RDONLY);
  CHECK(alias != (void *)-1 && alias != shared && alias[0] == 123);
  status(id, 2);
  CHECK(shmdt((const void *)alias) == 0);
  descriptors_unchanged(canary, next_fd);
  info.shm_perm.mode = 0000;
  CHECK(shmctl(id, IPC_SET, &info) == 0);
  if (getuid() != 0) {
    FAILS(shmget(key, 0, 0400), EACCES);
    errno = 0;
    CHECK(shmat(id, NULL, SHM_RDONLY) == (void *)-1 && errno == EACCES);
    FAILS(shmctl(id, IPC_STAT, &info), EACCES);
  }
  info.shm_perm.mode = 0600;
  CHECK(shmctl(id, IPC_SET, &info) == 0);
  status(id, 1);

  int ready[2], release[2];
  CHECK(pipe(ready) == 0 && pipe(release) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(shared[0] == 123);
    shared[1] = 456;
    CHECK(write(ready[1], "r", 1) == 1);
    char token;
    CHECK(read(release[0], &token, 1) == 1);
    CHECK(shared[0] == 789);
    _exit(0); /* exit, not shmdt, must release this mm's attachment */
  }
  char token;
  CHECK(read(ready[0], &token, 1) == 1);
  status(id, 2);
  CHECK(shared[1] == 456);
  shared[0] = 789;
  CHECK(write(release[1], "g", 1) == 1);
  reap(child);
  status(id, 1);
  CHECK(close(ready[0]) == 0 && close(ready[1]) == 0);
  CHECK(close(release[0]) == 0 && close(release[1]) == 0);

  /* Different virtual addresses in different mms must name the same shared
   * futex. Wake retries only until the parent's real wait is registered. */
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    volatile uint32_t *own_alias = shmat(id, NULL, 0);
    CHECK(own_alias != (void *)-1 && own_alias != shared);
    for (;;) {
      long woken = syscall(SYS_futex, own_alias + 2, FUTEX_WAKE, 1, NULL, NULL, 0);
      CHECK(woken >= 0);
      if (woken == 1) break;
      CHECK(sched_yield() == 0);
    }
    CHECK(shmdt((const void *)own_alias) == 0);
    _exit(0);
  }
  CHECK(syscall(SYS_futex, shared + 2, FUTEX_WAIT, 0, NULL, NULL, 0) == 0);
  reap(child);
  status(id, 1);

  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    errno = 0;
    execl("/hermit-sysv-shm-missing-executable", "missing", (char *)NULL);
    CHECK(errno == ENOENT);
    status(id, 2); /* a failed exec keeps the inherited mm attached */
    char number[32];
    snprintf(number, sizeof(number), "%d", id);
    execl(argv[0], argv[0], "after-exec", number, (char *)NULL);
    _exit(2);
  }
  reap(child);
  status(id, 1);

  CHECK(shmctl(id, IPC_RMID, NULL) == 0);
  info = status(id, 1);
  CHECK((info.shm_perm.mode & SHM_DEST) != 0);
  FAILS(shmget(key, 0, 0), ENOENT);
  int replacement = shmget(key, 56, IPC_CREAT | IPC_EXCL | 0600);
  CHECK(replacement > id);
  alias = shmat(id, NULL, SHM_RDONLY); /* Linux permits attaching a live removed ID */
  CHECK(alias != (void *)-1 && alias[1] == 456);
  status(id, 2);
  CHECK(shmdt((const void *)alias) == 0);
  CHECK(shmdt((const void *)shared) == 0);
  FAILS(shmctl(id, IPC_STAT, &info), EINVAL);
  CHECK(shmctl(replacement, IPC_RMID, NULL) == 0);
  descriptors_unchanged(canary, next_fd);
  CHECK(close(canary) == 0);
  puts("sysv-shm shared=fork aliases=ok stat=ok rmid=ok exec=ok exit=ok errors=ok");
  return 0;
}
