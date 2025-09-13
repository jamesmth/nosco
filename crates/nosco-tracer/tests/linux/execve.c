#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static void* thread_start(void* args);
static void run_execve(char *argv[]);

int main(int argc, char *argv[]) {
  if (argc == 3) {
    // call execve in a different thread (for test purposes)

    pthread_attr_t attr;
    pthread_attr_init(&attr);

    pthread_t thread;
    pthread_create(&thread, &attr, &thread_start, (void*)argv);

    pthread_attr_destroy(&attr);

    pthread_join(thread, NULL);
  } else if (argc == 2) {
    // call execve in the same thread (for test purposes)

    char *newargv[] = {argv[0], NULL};
    run_execve(newargv);
  }

  return 0;
}

void* thread_start(void* args) {
  char *argv[] = {((char**)args)[0], "1", NULL};
  run_execve(argv);
}

void run_execve(char *argv[]) {
  char *env[] = { NULL };

  execve(argv[0], argv, env);
  exit(EXIT_FAILURE);
}
