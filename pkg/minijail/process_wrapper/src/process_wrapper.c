#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Executes argv[3] with argv[4..argc-1] as arguments after changing the
// working directory to argv[1].
int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr,
            "Usage: %s <directory> <executable_path> <executable_arg1> ...\n",
            argv[0]);
    return 1;
  }

  if (chdir(argv[1]) == -1) {
    fprintf(stderr, "chdir(%s) failed: %s\n", argv[1], strerror(errno));
    return 1;
  }

  // Skip over both the process wrapper's own argv[0], the directory,
  // and the -- separator.
  if (execv(argv[3], argv + 3) == -1) {
    fprintf(stderr, "execv(%s) failed: %s\n", argv[3], strerror(errno));
    return 1;
  }
  // Not reached.
}
