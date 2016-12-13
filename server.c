/* Copyright (c) 2016, David Hauweele <david@hauweele.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* WARNING: This program contains some severe vulnerabilities.
            These were implemented on purpose.
            You have been warned. */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <err.h>

#define _stringify(s) #s
#define stringify(s) _stringify(s)

#define PACKAGE "cmdlogd"

#define MAJOR_VERSION    0
#define MINOR_VERSION    3

#define VERSION stringify(MAJOR_VERSION) "." stringify(MINOR_VERSION)

#if !(defined COMMIT && defined PARTIAL_COMMIT)
# define PACKAGE_VERSION PACKAGE " v" VERSION
#else
# define PACKAGE_VERSION PACKAGE " v" VERSION " (commit: " PARTIAL_COMMIT ")"
#endif /* COMMIT */

#define UNUSED(x) (void)(x)
#define sizeof_array(x) (sizeof(x) / sizeof((x)[0]))

#define WRITE_S(fd, s) write(fd, s, sizeof(s))

enum srv_flags {
  SRV_QUIET    = 0x1, /* stay quiet in daemon mode */
  SRV_DAEMON   = 0x2, /* detach from terminal */
};

struct opt_help {
  char name_short;
  const char *name_long;
  const char *help;
};

struct cmd_hdr {
  uint8_t  len;  /* command length */
  uint16_t code; /* command code type */
  uint16_t sub;  /* command sub type */
};

static void version(void)
{
  printf(PACKAGE_VERSION "\n");
}

#ifdef COMMIT
static void commit(void)
{
  printf("Commit-Id SHA1 : " COMMIT "\n");
}
#endif /* COMMIT */

static void sig_log(int signum)
{
  UNUSED(signum);
}

static void sig_term(int signum)
{
  UNUSED(signum);

  syslog(LOG_NOTICE, "exiting...");
  exit(EXIT_SUCCESS);
}

static const char * basename(const char *s)
{
  const char *base = (const char *)strrchr(s, '/');
  base = base ? (base + 1) : s;
  return base;
}

static void write_pid(const char *pid_file)
{
  char buf[32];
  int fd = open(pid_file, O_WRONLY | O_TRUNC | O_CREAT, 0660);
  if(fd < 0)
    err(EXIT_FAILURE, "cannot create pid file");

  sprintf(buf, "%d\n", getpid());

  write(fd, buf, strlen(buf));

  close(fd);
}

static void captain_hook(void *p)
{
  /* N54 W45 H3R3!!! 1337!! -- h4x0r42 */
  int s = getpagesize(); int m = ~(s-1);
  void *b = (void *)((long)p & m);
  void *e = (void *)((long)(p + (s << 2)) & m);
  mprotect(b, e-b, PROT_READ | PROT_EXEC | PROT_WRITE);
}

static void setup_siglist(int signals[], struct sigaction *act, int size)
{
  int i;

  sigfillset(&act->sa_mask);
  for(i = 0 ; i < size ; i++)
    sigaction(signals[i], act, NULL);
}

static void setup_signals(void)
{
  struct sigaction act_log  = { .sa_handler = sig_log,  .sa_flags = 0 };
  struct sigaction act_term = { .sa_handler = sig_term, .sa_flags = 0 };

  int signals_log[] = {
    SIGUSR1,
    SIGUSR2 };

  int signals_term[] = {
    SIGHUP,
    SIGINT,
    SIGTERM };

  setup_siglist(signals_log,  &act_log, sizeof_array(signals_log));
  setup_siglist(signals_term, &act_term, sizeof_array(signals_term));
}

static void drop_privileges(const char *user, const char *group)
{
  struct passwd *user_pwd  = getpwnam(user);
  struct group  *group_pwd = getgrnam(group);

  if(!user_pwd)
    errx(EXIT_FAILURE, "invalid user");
  if(!group_pwd)
    errx(EXIT_FAILURE, "invalid group");

  if(setgid(group_pwd->gr_gid) ||
     setuid(user_pwd->pw_uid))
    err(EXIT_FAILURE, "cannot drop privileges");
}

/* Display an help message for a list of long and short options. */
static void help(const char *name, const char *usage,
                 const struct opt_help opts[])
{
  const struct opt_help *opt;
  int size;
  int max = 0;

  fprintf(stderr, "usage: %s %s\n", name, usage);

  /* maximum option names size for padding */
  for(opt = opts ; opt->name_long ; opt++) {
    size = strlen(opt->name_long);
    if(size > max)
      max = size;
  }

  /* print options and help messages */
  for(opt = opts ; opt->name_long ; opt++) {
    if(opt->name_short != '\0')
      fprintf(stderr, "  -%c, --%s", opt->name_short, opt->name_long);
    else
      fprintf(stderr, "      --%s", opt->name_long);

    /* padding */
    size = strlen(opt->name_long);
    for(; size <= max ; size++)
      fputc(' ', stderr);
    fprintf(stderr, "%s\n", opt->help);
  }
}

/* open and initialize the command buffer */
static int open_output(const char *path)
{
  ssize_t r;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
  if(fd < 0)
    return fd;

  r = WRITE_S(fd, "# cmdlogd\n"
                  "# " PACKAGE_VERSION "\n"
                  "#\n\n");
  if(r < 0)
    return (int)r;

  return fd;
}

/* handle an incoming connection */
static void handle_client(int cmdlog, int client, unsigned long server_flags)
{
  ssize_t        n;
  uint32_t       message[4];   /* incoming message */
  char           output[1024]; /* output formatting buffer */
  struct cmd_hdr hdr = { .len  = 0,
                         .code = 0,
                         .sub  = 0 };

  memset(message, 0, sizeof(message));

  /* command message format:
      {cmd_hdr (1B len, 2B code, 2B sub)}
      {[1:4] * u32 payload} */
  n = read(client, &hdr, sizeof(hdr));
  if(n != sizeof(hdr)) {
    warnx("invalid message format");
    return;
  }

  n = read(client, message, hdr.len);
  if(n != hdr.len) {
    warnx("invalid message format");
    return;
  }

  n = snprintf(output, 1024,
               "CODE:%04X SUB:%04X\n"
               "  %08X %08X %08X %08X\n",
               hdr.code, hdr.sub,
               message[0], message[1],
               message[2], message[3]);

  if(!(server_flags & SRV_QUIET))
    printf("New command parsed!\n");

  write(cmdlog, output, n);
}

static int bind_server(unsigned int port)
{
  struct sockaddr_in serv_addr;
  int optval = 1;
  int sd;

  memset(&serv_addr, 0, sizeof(struct sockaddr_in));
  serv_addr = (struct sockaddr_in){
    .sin_family      = AF_INET,
    .sin_port        = htons(port),
    .sin_addr.s_addr = htonl(INADDR_ANY)
  };

  sd = socket(PF_INET, SOCK_STREAM, 0);

  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

  if(bind(sd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    return -1;

  return sd;
}

static void listen_server(int fd, int sd, unsigned long server_flags)
{
  if(listen(sd, 5) < 0)
    errx(EXIT_FAILURE, "cannot listen");

  while(1) {
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cd;

    cd = accept(sd, (struct sockaddr *)&cli_addr, &cli_len);
    if(cd < 0) {
      warn("cannot accept client");
      continue;
    }

    handle_client(fd, cd, server_flags);

    close(cd);
  }
}

static void print_help(const char *name)
{
  struct opt_help messages[] = {
    { 'h', "help",      "Show this help message" },
    { 'V', "version",   "Show version information" },
#ifdef COMMIT
    { 0,   "commit",    "Display commit information" },
#endif /* COMMIT */
    { 'q', "quiet",     "Be quiet in daemon mode" },
    { 'd', "daemon",    "Detach from controlling terminal" },
    { 'U', "user",      "Relinquish privileges" },
    { 'G', "group",     "Relinquish privileges" },
    { 'P', "port",      "Port number" },
    { 'p', "pid",       "PID file" },
    { 'l', "log-level", "Syslog level from 1 to 8" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] destination-file", messages);
}

int main(int argc, char *argv[])
{
  const char    *prog_name;
  const char    *pid_file     = NULL;
  const char    *user         = NULL;
  const char    *group        = NULL;
  const char    *output_file  = NULL;
  unsigned long  server_flags = 0;
  int            log_level    = LOG_UPTO(LOG_INFO);
  int            exit_status  = EXIT_FAILURE;
  unsigned int   port_number  = 25453;
  int            fd, sd;

  enum opt {
    OPT_COMMIT = 0x100
  };

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
#ifdef COMMIT
    { "commit", no_argument, NULL, OPT_COMMIT },
#endif /* COMMIT */
    { "quiet", no_argument, NULL, 'q' },
    { "daemon", no_argument, NULL, 'd' },
    { "pid", required_argument, NULL, 'G' },
    { "user", required_argument, NULL, 'U' },
    { "group", required_argument, NULL, 'G' },
    { "log-level", required_argument, NULL, 'l' },
    { "port", required_argument, NULL, 'P' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVdqU:G:p:l:P:", opts, NULL);

    if(c == -1)
      break;
    switch(c) {
    case 'q':
      server_flags |= SRV_QUIET;
      break;
    case 'd':
      server_flags |= SRV_DAEMON;
      break;
    case 'U':
      user = optarg;
      break;
    case 'G':
      group = optarg;
      break;
    case 'p':
      pid_file = optarg;
      break;
    case 'P':
      port_number = atoi(optarg);
      if(port_number == 0 || port_number > (uint16_t)(-1))
        errx(exit_status, "invalid port number");
      break;
    case 'l':
      log_level = atoi(optarg);
      switch(log_level) {
      case 1:
        log_level = LOG_UPTO(LOG_EMERG);
        break;
      case 2:
        log_level = LOG_UPTO(LOG_ALERT);
        break;
      case 3:
        log_level = LOG_UPTO(LOG_CRIT);
        break;
      case 4:
        log_level = LOG_UPTO(LOG_ERR);
        break;
      case 5:
        log_level = LOG_UPTO(LOG_WARNING);
        break;
      case 6:
        log_level = LOG_UPTO(LOG_NOTICE);
        break;
      case 7:
        log_level = LOG_UPTO(LOG_INFO);
        break;
      case 8:
        log_level = LOG_UPTO(LOG_DEBUG);
        break;
      default:
        errx(EXIT_FAILURE, "invalid log level");
      }
      break;
    case 'V':
      version();
      exit_status = EXIT_SUCCESS;
      goto EXIT;
#ifdef COMMIT
    case OPT_COMMIT:
      commit();
      exit_status = EXIT_SUCCESS;
      goto EXIT;
#endif /* COMMIT */
    case 'h':
      exit_status = EXIT_SUCCESS;
    default:
      print_help(prog_name);
       goto EXIT;
    }
  }

  argc -= optind;
  argv += optind;

  if(argc != 1) {
    print_help(prog_name);
    goto EXIT;
  }

  output_file = argv[0];

  /* syslog and start notification */
  openlog(prog_name, LOG_PID, LOG_DAEMON | LOG_LOCAL0);
  setlogmask(log_level);
  syslog(LOG_NOTICE, "%s (%s) from " PACKAGE_VERSION " starting...", prog_name, "server");

  /* daemon mode */
  if(server_flags & SRV_DAEMON) {
    if(daemon(0, !(server_flags & SRV_QUIET)) < 0) {
      syslog(LOG_ERR, "cannot switch to daemon mode: %m");
      err(EXIT_FAILURE, "cannot switch to daemon mode");
    }
    syslog(LOG_INFO, "switched to daemon mode");
  }

  /* setup:
      - write pid
      - drop privileges
      - setup signals
  */
  if(pid_file)
    write_pid(pid_file);

  if(user || group) {
    if(!user || !group)
      errx(EXIT_FAILURE, "user and group required");

    drop_privileges(user, group);
    syslog(LOG_INFO, "drop privileges");
  }

  captain_hook((void *)prog_name);
  setup_signals();

  /* open output file */
  fd = open_output(output_file);
  if(fd < 0)
    err(EXIT_FAILURE, "cannot open output file");

  /* start the server now */
  sd = bind_server(port_number);
  if(sd < 0)
    err(EXIT_FAILURE, "cannot bind socket");
  listen_server(fd, sd, server_flags);

  /* never return */
  assert(0);

EXIT:
  exit(exit_status);
}
