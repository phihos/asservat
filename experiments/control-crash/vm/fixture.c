/* Synthetic opt-in crashing process. Core contents are generated, not user evidence. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
static void crash_here(void) { *(volatile unsigned int *)0 = 42; }
int main(int argc,char **argv) {
 size_t n=argc>1?strtoul(argv[1],NULL,10):4194304;
 if(n>67108864) return 2;
 char *p=malloc(n); if(!p)return 3;
 memset(p,0x41,n); memcpy(p,"ASSERVAT_SYNTHETIC_CORE_MARKER",28);
 prctl(PR_SET_DUMPABLE,1);
 printf("%d\n",getpid());fflush(stdout);
 if(getchar()=='x')crash_here();
 free(p);return 0;
}
