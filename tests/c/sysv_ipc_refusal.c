/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

/* Semaphores and message queues remain unavailable on every backend. Shared
 * memory is either explicitly unsupported (ENOSYS) or real run-local backing.
 * The ptrace/KVM sysv_shm.c regression separately requires the supported path.
 * Keep raw results in stdout so verify observes which capability ran. */
int main(void) {
  enum { EXPECTED_CHECKS = 3 };

  errno = 0;
  int sem = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
  int sem_errno = errno;
  int sem_refused = sem == -1 && sem_errno == ENOSYS;

  errno = 0;
  int shm = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
  int shm_errno = errno;
  int shm_refused = shm == -1 && shm_errno == ENOSYS;
  int shm_backed = 0;
  if (shm >= 0) {
    volatile int *first = shmat(shm, NULL, 0);
    volatile int *second = shmat(shm, NULL, 0);
    if (first != (void *)-1 && second != (void *)-1) {
      *first = 42;
      shm_backed = *second == 42;
    }
    if (first != (void *)-1 && shmdt((const void *)first) != 0) shm_backed = 0;
    if (second != (void *)-1 && shmdt((const void *)second) != 0) shm_backed = 0;
    if (shmctl(shm, IPC_RMID, NULL) != 0) shm_backed = 0;
  }

  errno = 0;
  int msg = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
  int msg_errno = errno;
  int msg_refused = msg == -1 && msg_errno == ENOSYS;

  int ok = sem_refused + (shm_refused || shm_backed) + msg_refused;
  printf(
      "sysvipc ok=%d sem_rc=%d sem_errno=%d shm_rc=%d shm_errno=%d "
      "msg_rc=%d msg_errno=%d\n",
      ok,
      sem,
      sem_errno,
      shm,
      shm_errno,
      msg,
      msg_errno);
  return ok == EXPECTED_CHECKS ? 0 : 1;
}
