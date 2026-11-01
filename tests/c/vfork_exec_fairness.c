// A vfork child must not retain a priority boost after exec. A CPU-busy
// child still lets its parent consume a ready pipe and terminate it.
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "spin") == 0) {
    int fd = atoi(argv[2]);
    if (write(fd, "x", 1) != 1 || close(fd) != 0) return 2;
    // Retired conditional branches drive Hermit's CPU-slice counter.
    volatile unsigned running = 1;
    while (running) {
      __asm__ volatile("" ::: "memory");
    }
  }
  int pipefd[2];
  if (pipe(pipefd) != 0) return 2;
  char fd[32];
  snprintf(fd, sizeof(fd), "%d", pipefd[1]);
  char *child_argv[] = {argv[0], "spin", fd, NULL};
  pid_t child = vfork();
  if (child < 0) return 2;
  if (child == 0) {
    execv(argv[0], child_argv);
    _exit(127);
  }
  if (close(pipefd[1]) != 0) return 2;
  char ready;
  if (read(pipefd[0], &ready, 1) != 1 || ready != 'x') return 2;
  if (close(pipefd[0]) != 0 || kill(child, SIGTERM) != 0) return 2;
  int status;
  if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
      WTERMSIG(status) != SIGTERM) return 2;
  puts("parent serviced ready pipe while exec child was CPU-busy");
  return 0;
}
