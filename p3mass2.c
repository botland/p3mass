/*
Copyright (c) 2007-2022 botland@free.fr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
// possible enhancements :
// - overcome icmp and rst rate limiting
// - merge all requests by host
// - add min, max and average statictics
// gcc -pthread -o prog prog.c
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <arpa/inet.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>

#ifdef DEBUGMEM
#define MAX_THREADS	256
#endif
#ifdef DEBUG
#ifndef STATS
#define STATS
#endif
#endif
#ifndef SCALE
#define SCALE		5
#endif
#define MAX_IP		16
#define MAX_SOCKETS	(2 << (5 + SCALE))
#ifndef MAX_THREADS
#ifdef __APPLE__
#define MAX_THREADS	2048
#else
#define MAX_THREADS	MAX_SOCKETS
#endif
#endif
#define PORT		80
#define READ_BUFSIZE	512
#define RETRIES_CONNECT	0
#define RETRIES_ERROR	5
//#define SLEEP		102400 / (2 << SCALE)
#define SOCKET_READ	0
#define SOCKET_WRITE	1
#define TIMEOUT_CONNECT	(2 << (10 + SCALE))
#define TIMEOUT_READ	TIMEOUT_CONNECT * 10
#define TIMEOUT_WRITE	TIMEOUT_CONNECT
#ifndef VERBOSE
#define VERBOSE		2
#endif

const unsigned int SLEEP	= 102400 / (2 << SCALE);

#ifdef STATS
#define MAX_ERRORS	8
struct errno_pool {
  int error;
  unsigned int count;
} ep[MAX_ERRORS];
struct timeval before;
#endif

unsigned int c_probe;
unsigned int c_request;
unsigned int c_resource;
unsigned int c_response;
unsigned int c_target;
unsigned int c_timeout_connect;
unsigned int c_timeout_read;
unsigned int c_timeout_write;
unsigned int probes;

int smf=0;
int smre=0;
int sst=0;
int sse=0;
int stt=0;
int ste=0;

int cooldown=0;
int target=0;
pthread_mutex_t mmem	= PTHREAD_MUTEX_INITIALIZER;
struct probe {
  char *resource;
  char *pattern;
  char *command;
} *rpc;
struct probe_data {
  char ip[MAX_IP];
  unsigned short tid;
};
struct pthread_pool {
  pthread_t thread;
  unsigned short available;
} pp[MAX_THREADS];

void wusleep(int s) {
  struct timeval tv;
  tv.tv_sec = s / 1000000; 
  tv.tv_usec = s - tv.tv_sec * 1000000;
  select(0,NULL,NULL,NULL,&tv);
//  sleep(tv.tv_sec);
//  usleep(tv.tv_usec);
}

void *wmalloc(size_t s) {
  char *m;
  pthread_mutex_lock(&mmem);
  while((m = malloc(s)) == NULL) {
    perror("wmalloc");
    smf++;
    wusleep(SLEEP);
  }
  pthread_mutex_unlock(&mmem);
  memset(m,0,s);
  return m;
}

void *wrealloc(void *p,size_t s) {
  char *m;
  pthread_mutex_lock(&mmem);
  while((m = realloc(p,s)) == NULL) {
    perror("rwmalloc");
    smre++;
    wusleep(SLEEP);
  }
  pthread_mutex_unlock(&mmem);
  memset(m,0,s);
  return m;
}

void reportusage(int w) {
  struct rusage ru;
  getrusage(w,&ru);
  printf("utime.sec=%li\tutime.usec=%li\t",ru.ru_utime.tv_sec,ru.ru_utime.tv_usec);
  printf("stime.sec=%li\tstime.usec=%li\n",ru.ru_stime.tv_sec,ru.ru_stime.tv_usec);
  printf("max_rss=%li\tixrss=%li\tidrss=%li\tisrss=%li\n",ru.ru_maxrss,ru.ru_ixrss,ru.ru_idrss,ru.ru_isrss);
  printf("minflt=%li\tmajflt=%li\tnswap=%li\t",ru.ru_minflt,ru.ru_majflt,ru.ru_nswap);
  printf("inblock=%li\toublock=%li\n",ru.ru_inblock,ru.ru_oublock);
  printf("msgsnd=%li\tmsgrcv=%li\tnsignals=%li\t",ru.ru_msgsnd,ru.ru_msgrcv,ru.ru_nsignals);
  printf("nvcsw=%li\tnivcsw=%li\n",ru.ru_nvcsw,ru.ru_nivcsw);
  printf("-----------------------------------------------------------------\n");
}

#ifdef STATS
void incerror(int error) {
  int i = 0;
  while(i < MAX_ERRORS) {
    if(ep[i].error == 0) {
      ep[i].error = error;
    }
    if(ep[i].error == error) {
      ep[i].count++;
      i = MAX_ERRORS;
    }
    i++;
  }
}

void reportstats() {
  printf("-----------------------------------------------------------------\n");
#ifdef DEBUGNET
  int i = 0;
  while(i < MAX_ERRORS && ep[i].error) {
    printf("statistics: %s (%d): %d\n",strerror(ep[i].error),ep[i].error,ep[i].count);
    i++;
  }
#endif
#if VERBOSE > 1
  printf("statistics: %d timeouts on connect\n",c_timeout_connect);
  printf("statistics: %d timeouts on read\n",c_timeout_read);
  printf("statistics: %d timeouts on write\n",c_timeout_write);
  printf("statistics: %d probes\n",c_probe);
#endif
  printf("statistics: %d requests\n",c_request);
  printf("statistics: %d responses\n",c_response);
  printf("statistics: %d resources\n",c_resource);
  printf("statistics: %d targets\n",c_target);
  printf("-----------------------------------------------------------------\n");
}

void reporttime() {
  int d,h,m,s,u;
  long bu = before.tv_sec * 1000000 + before.tv_usec;
  gettimeofday(&before,NULL);
  long nu = before.tv_sec * 1000000 + before.tv_usec - bu;
  long ns = nu / 1000000;
  d = ns / 86400;
  h = ns / 3600 - d * 24;
  m = ns / 60 - d * 1440 - h * 60;
  s = ns % 60;
  u = nu % 1000000;
  printf("statistics: %d days %d hours %d minutes %d.%06d seconds elapsed\n",d,h,m,s,u);
  printf("-----------------------------------------------------------------\n");
}

void reporttimeremaining(long ns) {
  int d,h,m,s;
  d = ns / 86400;
  h = ns / 3600 - d * 24;
  m = ns / 60 - d * 1440 - h * 60;
  s = ns % 60;
  printf("statistics: %d days %d hours %d minutes %d seconds remaining\n",d,h,m,s,ns);
  printf("-----------------------------------------------------------------\n");
}

void *estimatestats() {
  int i = 1;
  wusleep(1000000 * i);
  printf("statistics: %d probes per second\n",c_probe / i);
  reporttimeremaining((probes - c_probe) / (c_probe / i));
  pthread_exit(NULL);
  return NULL;
}

void resetstats() {
  int i = 0;
  while(i < MAX_ERRORS && ep[i].error) {
    ep[i].count = 0;
    i++;
  }
  c_timeout_write = c_timeout_read = c_timeout_connect = 0;
  c_target = c_response = c_resource = c_request = c_probe = 0;
}
#endif

int getsocket() {
  int s;
  while((s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0 || s >= MAX_SOCKETS) {
    sst++;
    wusleep(SLEEP);
    if(s >= MAX_SOCKETS) {
#ifdef DEBUGNET
      printf("ooops socket %d outside limitation\n",s);
#endif
      close(s);
    }
  }
  return s;
}

int getthread() {
  int i;
  for(;;) {
    stt++;
    wusleep(SLEEP);
    for(i=0;i<MAX_THREADS;i++) {
      if(pp[i].available) {
        pp[i].available = 0;
        return i;
      }
    }
    wusleep(SLEEP);
  }
//  printf("failed to get an available thread\n");
  return getthread();
}

int pollwait(int s,int w,int t) {
  struct pollfd fds[1];
  memset(&fds,0,sizeof(fds));
  fds[0].fd = s;
  if(w) {
    fds[0].events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;
  } else {
    fds[0].events = POLLIN | POLLHUP;
  }
  return poll(fds,1,t / 1000);
}

int selectwait(int s,int w,int t) {
  fd_set fdsr,fdsw;
  struct timeval tv; 
  tv.tv_sec = t / 1000000; 
  tv.tv_usec = t - tv.tv_sec * 1000000;
  FD_ZERO(&fdsr);
  FD_ZERO(&fdsw);
  if(w) {
    FD_SET(s,&fdsw);
  } else {
    FD_SET(s,&fdsr);
  }
  return select(s + 1,&fdsr,&fdsw,NULL,&tv);
}

void setnonblock(int s) {
  long arg = fcntl(s,F_GETFL,NULL) | O_NONBLOCK; 
  if(fcntl(s,F_SETFL,arg) < 0) { 
    perror("blocking"); 
  }
}

void unsetnonblock(int s) {
  long arg = fcntl(s,F_GETFL,NULL) & (~O_NONBLOCK); 
  if(fcntl(s,F_SETFL,arg) < 0) { 
    perror("blockingnot");
  }
}

int waitsocket(int s,int w,int t) {
  int opt,r;
  socklen_t l = sizeof(int);
  r = pollwait(s,w,t);
  if(r > 0) {
    if(getsockopt(s,SOL_SOCKET,SO_ERROR,&opt,&l) < 0 || opt) {
#ifdef DEBUGNET
      printf("+");
#endif
      r = -1;
    }
#ifdef DEBUGNET
  } else if(r == 0) {
//    printf(".");
  } else {
    printf("|");
#endif
  }
  return r;
}

int closesocket(int s) {
#ifdef STATS
  if(errno) {
    incerror(errno);
#ifdef DEBUGNET
    if(errno != EINPROGRESS) {
      char b[20];
      sprintf(b,"closesocket %d",s);
      perror(b);
    }
#endif
  }
#endif
  if(s) {
    if(!target && shutdown(s,SHUT_RDWR) < 0) {
#ifdef STATS
      if(errno) {
        incerror(errno);
      }
#endif
    }
    if(close(s) < 0) {
#ifdef STATS
      if(errno) {
        incerror(errno);
      }
#endif
    }
  }
  return 0;
}

void configuresocket(s) {
  int opt;
  socklen_t l = sizeof(int);
#ifdef DEBUGNET
  opt = 1;
  setsockopt(s,SOL_SOCKET,SO_DEBUG,&opt,l);
#endif
#ifdef TCP_CORK
  opt = 1;
  setsockopt(s,SOL_TCP,TCP_CORK,&opt,l);
#endif
#ifdef TCP_NODELAY
  opt = 1;
  setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&opt,l);
#endif
#ifdef TCP_QUICKACK
  opt = 1;
  setsockopt(s,IPPROTO_TCP,TCP_QUICKACK,&opt,l);
#endif
#ifdef TCP_SYNCNT
  opt = RETRIES_CONNECT;
  setsockopt(s,IPPROTO_TCP,TCP_SYNCNT,&opt,l);
#endif
}

int opensocket(char *ip) {
  int r,s;
  struct sockaddr_in sin;
  s = getsocket();
  memset(&sin,0,sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(PORT);
  sin.sin_addr.s_addr = inet_addr(ip);
  configuresocket(s);
  setnonblock(s);
  r = connect(s,(struct sockaddr *)&sin,sizeof(sin));
  unsetnonblock(s);
  if(r < 0) {
    if(errno == EINPROGRESS || errno == EAGAIN) {
      r = waitsocket(s,SOCKET_WRITE,TIMEOUT_CONNECT);
      if(r <= 0) {
        if(r == 0) {
          c_timeout_connect++;
        }
        sse++;
        return closesocket(s);
      }
    } else {
      sse++;
      return closesocket(s);
    }
  }
  return s;
}

int readsocket(int s, char **buf,int *bufsize) {
  int i = 0, r;
  memset(*buf,0,*bufsize);
  for(;;) {
    if(i == *bufsize - 1) {
      *buf = wrealloc(*buf,*bufsize *= 2);
    } 
    r = waitsocket(s,SOCKET_READ,TIMEOUT_READ);
    if(r <= 0) {
      if(r == 0) {
        c_timeout_read++;
      }
      return -1;
    }
    r = read(s,(*buf + i),1);
    if(r < 0) {
      return r;
    } else if (r == 0) {
      (*buf)[i] = '\0';
      return r;				/* EOF */
    } else if((*buf)[i] == '\r') {
      continue;				/* watch for cr-lf */
    } else if((*buf)[i] == '\n') {
      i++;
      break;
    }
    i++;
  }
  (*buf)[i] = '\0';
  return r;
}

int writesocket(int s, char *buf) {
  int r;
  r = waitsocket(s,SOCKET_WRITE,TIMEOUT_WRITE);
  if(r <= 0) {
    if(r == 0) {
      c_timeout_write++;
    }
    return -1;
  }
  r = write(s,buf,strlen(buf));
  return r;
}

int readheader(int s,char *ip,char **buf,int *bufsize,int i) {
  int c = 0;
  while(readsocket(s,buf,bufsize) > 0 && (*buf)[1]) {
    if(strncasecmp(*buf,"HTTP/1.",7) == 0) {
#if VERBOSE > 0
      printf("%s: (%s) %s",ip,rpc[i].resource,*buf);
#endif
      if(strstr(*buf,"200") || strstr(*buf,"302")) {
        c++;
      }
    } else if(strncasecmp(*buf,"Content-Type:",13) == 0) {
      c++;
#if VERBOSE > 2
    } else if(!i) {
      printf("%s: %s",ip,*buf);
#elif VERBOSE > 1
//    } else if(!i && *buf[0] == 'S' && *buf[1] == 'e') {
//      printf("%s: %s",ip,*buf);
#endif
    }
  }
  if(c) {
    c_response++;
  }
  if(c == 2) {
    c_resource++;
  } else {
    c = 0;
  }
  return c;
}

int readcontent(int s,char *ip,char **buf,int *bufsize,int i) {
  int c = 0;
  while(readsocket(s,buf,bufsize) > 0) {
#if VERBOSE > 3
    printf("%s: %s",ip,*buf);
#endif
    if(rpc[i].pattern && strstr(*buf,rpc[i].pattern)) {
      c++;
    }
  }
  if(c) {
    printf("Yola!! Found a target for %s at %s\n",rpc[i].pattern,ip);
    if(rpc[i].command) {
      memset(*buf,0,*bufsize);
      sprintf(*buf,"%s %s",rpc[i].command,ip);
      system(*buf);
    }
    c_target++;
  }
  return c;
}

void *probe(void *p) {
  int i = 0,bufsize = READ_BUFSIZE,s = 1;
  char *buf;
  struct probe_data *pd = (struct probe_data *)p;
  c_probe++;
  while(rpc[i].resource && s) {
    s = opensocket(pd->ip);	// should open 1 socket for n ressouces
    if(s) {
#if VERBOSE > 2
#ifdef DEBUGPERF
      reporttime();
#endif
      printf("Probing %s for %s on socket %d with thread %d\n",pd->ip,rpc[i].resource,s,pd->tid);
#endif
      buf = wmalloc(bufsize);
//      sprintf(buf,"GET %s HTTP/1.0\r\n\r\n",rpc[i].resource);
      sprintf(buf,"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",rpc[i].resource,pd->ip);
      if(writesocket(s,buf)) {
        c_request++;
        if(readheader(s,pd->ip,&buf,&bufsize,i) && !target) {
          readcontent(s,pd->ip,&buf,&bufsize,i);
        }
      }
#ifdef DEBUGMEM
      printf("%d\n",__LINE__);
#endif
      free(buf);
      closesocket(s);
    }
    i++;
  }
  pp[pd->tid].available = 1;
#ifdef DEBUGTHREAD
  if(cooldown) {
    printf("Thread %d probing %s ended\n",pd->tid,pd->ip);
  }
#endif
#ifdef DEBUGMEM
//  printf("%d\n",__LINE__);
#endif
  free(pd);
#ifdef DEBUGMEM
  reportusage(RUSAGE_SELF);
#endif
  pthread_exit(NULL);
}

void *fakeprobe(void *p) {
  int s;
  struct probe_data *pd = (struct probe_data *)p;
  s = opensocket(pd->ip);
  printf("ip=%s\tthread=%d\tsocket=%d\n",pd->ip,pd->tid,s);
  if(s) closesocket(s);
  pp[pd->tid].available = 1;
#ifdef DEBUGMEM
  printf("%d\n",__LINE__);
#endif
  free(pd);
  pthread_exit(NULL);
}

int callprobe(char *ip, pthread_attr_t *attr, int retry) {
  int r;
  int tid = getthread();
  struct probe_data *pd;
  pd = wmalloc(sizeof(struct probe_data));
  pd->tid = tid;
  strcpy(pd->ip,ip);
  r = pthread_create(&pp[pd->tid].thread,attr,probe,(void *)pd);
  if(r) {
    pp[tid].available = 1;
#ifdef DEBUGMEM
    printf("%d\n",__LINE__);
#endif
    free(pd);
    ste++;
    if(/*errno == ENOMEM &&*/ retry) {
      wusleep(tid == MAX_THREADS - 1 ? TIMEOUT_CONNECT : SLEEP);
      callprobe(ip,attr,--retry);
#ifdef DEBUGTHREAD
    } else if(!target) {
      printf("failed to create thread %d for probing ip %s\n",tid,ip);
#endif
    }
  }
  return 0;
}

#ifdef STATS
int callstats() {
  pthread_t thread;
  pthread_create(&thread,NULL,&estimatestats,NULL);
  return 0;
}
#endif

void bigscan(char *net, pthread_attr_t *attr) {
  int g,h,i;
  char ip[MAX_IP];
  printf("Scanning big network %s0.0.0/8\n",net);
  printf("-----------------------------------------------------------------\n");
  probes = powl(2,24);
  for(i=254;i>0;i--) {
    for(h=0;h<255;h++) {
      for(g=0;g<255;g++) {
//        ip = wmalloc(17);
        sprintf(ip,"%s%d.%d.%d",net,g,h,i);
        callprobe(ip,attr,RETRIES_ERROR);
      }
    }
#ifdef STATS
    reportstats();
    resetstats();
#endif
  }
}

void mediumscan(char *net, pthread_attr_t *attr) {
  int h,i;
  char ip[MAX_IP];
  printf("Scanning medium network %s0.0/16\n",net);
  printf("-----------------------------------------------------------------\n");
  probes = powl(2,16);
  for(i=254;i>0;i--) {
    for(h=0;h<255;h++) {
//      ip = wmalloc(17);
      sprintf(ip,"%s%d.%d",net,h,i);
      callprobe(ip,attr,RETRIES_ERROR);
    }
  }
}

void noscan(char *host, pthread_attr_t *attr) {
  unsigned int i;
  printf("Targeting host %s\n",host);
  printf("-----------------------------------------------------------------\n");
  probes = powl(2,31);
  for(i=0;i<powl(2,31);i++) {
    callprobe(host,attr,RETRIES_ERROR);
  }
}

void smallscan(char *net, pthread_attr_t *attr) {
  int i;
  char ip[MAX_IP];
  printf("Scanning small network %s0/24\n",net);
  printf("-----------------------------------------------------------------\n");
  probes = powl(2,8);
  for(i=254;i>0;i--) {
//    ip = wmalloc(17);
    sprintf(ip,"%s%d",net,i);
    callprobe(ip,attr,RETRIES_ERROR);
  }
}

void initprobe(int argc,char **argv) {
  int i = 0,c,s;
  char *p;
  rpc = wmalloc(sizeof(struct probe) * (argc - 1));
  while((i + 2) < argc) {
    p = argv[i + 2];
    c = 0;
    s = 1;
    while(*p++) {
      if(*p == ':' || *p == '\0') {
        switch(c++) {
          case 0:
            rpc[i].resource = wmalloc(s + 1);
            strncpy(rpc[i].resource,p - s,s);
            break;
          case 1:
            rpc[i].pattern = wmalloc(s + 1);
            strncpy(rpc[i].pattern,p - s,s);
            break;
          case 2:
            rpc[i].command = wmalloc(s + 1);
            strncpy(rpc[i].command,p - s,s);
            break;
        }
        if(*p == ':') {
          p++;
        }
        s = 0;
      }
      s++;
    }
    i++;
  }
}

int initscan(char **argv) {
  int i,s;
  char *p;
  s = strlen(argv[1]) - 1;
  if(*(argv[1] + s) == '0' && *(argv[1] + s - 1) == '.') {
    i = 0;
    p = argv[1];
    while(*p++) {
      if(*p == '.') {
        if(*(p + 1) == '0') {
          *(p + 1) = '\0';
        }
        i++;
      }
    }
  } else {
    target = 1;
    i = 4;
  }
  return i;
}

int init(int argc, char **argv, pthread_attr_t *attr) {
  int i;
  struct rlimit rl;
  getrlimit(RLIMIT_NOFILE,&rl);
  if(rl.rlim_max > MAX_SOCKETS) {
    rl.rlim_cur = MAX_SOCKETS;
  } else {
    rl.rlim_cur = rl.rlim_max;
    printf("Warning: user's limits might slow down operations\n");
  }
  setrlimit(RLIMIT_NOFILE, &rl);
  for(i=0;i<MAX_THREADS;i++) {
    pp[i].available = 1;
  }
  pthread_attr_init(attr);
  pthread_attr_setstacksize(attr,PTHREAD_STACK_MIN);
  pthread_attr_setdetachstate(attr,PTHREAD_CREATE_DETACHED);
#ifdef DEBUG
  printf("MAX_SOCKETS set to %d\n",MAX_SOCKETS);
  printf("MAX_THREADS set to %d\n",MAX_THREADS);
  printf("RLIMIT_NOFILE set to %d\n",rl.rlim_cur);
  printf("SLEEP set to %d\n",SLEEP);
  printf("STACK SIZE set to %d\n",PTHREAD_STACK_MIN);
  printf("TIMEOUT_CONNECT set to %d\n",TIMEOUT_CONNECT);
  printf("TIMEOUT_READ set to %d\n",TIMEOUT_READ);
  printf("TIMEOUT_WRITE set to %d\n",TIMEOUT_WRITE);
#endif
#ifdef STATS
#if VERBOSE > 2
  printf("statistics: maximum %d requests per second\n",1000000 / SLEEP);
  printf("statistics: maximum %d connection requests\n",2 * TIMEOUT_CONNECT / SLEEP);
  printf("statistics: maximum %.2f KiB/s upload stream\n",(float) (100 * 1000) / SLEEP);
#endif
  callstats();
#endif
  printf("\n");
  initprobe(argc,argv);
  return initscan(argv);
}

void term() {
  int i,c=0;
  for(i=0;i<MAX_THREADS;i++) {
    if(!pp[i].available) {
      c++;
    }
  }
#ifdef DEBUG
  printf("Waiting for the last %d threads to finish...\n",c);
#endif
  cooldown=1;
  for(i=0;i<MAX_THREADS;i++) {
    if(!pp[i].available) {
      wusleep(SLEEP);
      i--;
    }
  }
  i = 0;
#ifdef DEBUGTHREAD
  printf("all threads have terminated\n");
#endif
  while(rpc[i].resource) {
#ifdef DEBUGMEM
    printf("%d\n",__LINE__);
#endif
    free(rpc[i].resource);
    free(rpc[i].pattern);
    free(rpc[i].command);
    i++;
  }
#ifdef DEBUGMEM
  printf("%d\n",__LINE__);
#endif
  free(rpc);
#ifdef STATS
  reportstats();
  resetstats();
#endif
#ifdef DEBUGPERF
  printf("performance: malloc=%d realloc=%d sockettry=%d socketerr=%d threadtry=%d threaderr=%d\n",smf,smre,sst,sse,stt,ste);
#endif
}

int main(int argc, char **argv) {
  pthread_attr_t attr;
  if(!argv[1] || !argv[2]) {
    printf("usage: %s <network> <resource>[:<pattern>[:<command>]]...\n",argv[0]);
    pthread_exit(NULL);
  }
#ifdef STATS
  gettimeofday(&before,NULL);
#endif
  switch(init(argc,argv,&attr)) {
    case 1: bigscan(argv[1],&attr); break;
    case 2: mediumscan(argv[1],&attr); break;
    case 3: smallscan(argv[1],&attr); break;
    case 4: noscan(argv[1],&attr); break;
  }
#ifdef DEBUGPERF
  reporttime();
#endif
  term();
#ifdef STATS
  reporttime();
#endif
//  pthread_exit(NULL);
  exit(EXIT_SUCCESS);
}
