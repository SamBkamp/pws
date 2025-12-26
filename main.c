#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#include "src/prot.h"
#include "src/pws.h"


//make sure our output buffers get flushed
void sig_handler(int sig){
  exit(sig);
}

void fork_worker(const char *path){
  pid_t parent = getppid();
  //create new session and become session leader (with no tty)
  setsid();
  //if we wanted to, we could fork again here to make sure we don't reaquire a tty

  //set our chroot (not 100% secure, but this isn't a security feature, just a pragmatic one so we don't block other drives from being unmounted)
  if(chroot(path) < 0 ){
    perror("chroot");
    fputs("bailing\n", stderr);
    return;
  }

  umask(000);


  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  freopen(LOG_FILE, "w", stdout);
  freopen(ERROR_FILE, "w", stderr);

  //tell parent we no longer need the tty open
  kill(parent, SIGCONT);

  //make sure buffer is flushed when signal arrives
  signal(SIGINT, sig_handler);
  signal(SIGABRT, sig_handler);
  signal(SIGTERM, sig_handler);
  signal(SIGSEGV, sig_handler);

  //all done! ready to work
  puts("daemonization successful");
  pws();
}


void lame_ass_sig_handler(){ //this exists purely so pause() can return
  return;
}

int main(int argc, char *argv[]){
  prog_opts opts = {0};
  for(uint8_t i = 1; i < argc; i++){
    if(strcmp(argv[i], "--daemonize")==0){
      opts.daemonize = 1;
      break;
    }
  }
  if(opts.daemonize == 1){
    char cwd[1024];
    pid_t f_res;
    if(getcwd(cwd, 1024)==NULL){
      fputs("I couldn't figure out where we are. Did you run me as root?\n", stderr);
      return 1;
    }
    f_res = fork();

    switch(f_res){
    case -1:
      perror("fork");
      return 1;
    case 0: //child
      fork_worker(cwd);
      break;
    default:
      signal(SIGCONT, lame_ass_sig_handler); //man this feels so stupid
      pause();
      printf("child started: [%d]\n", f_res);
      break;
    }
  }
  else{
    puts("running as foreground application");
    return pws();
  }
}
