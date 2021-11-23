#include<stdio.h>
#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include<arpa/inet.h>
#include<netinet/in.h>
// #include<event.h>
#include<sys/time.h>
#include <setjmp.h>
#include<signal.h>
#include<stdarg.h>
#include<syslog.h>
using namespace std;

#define	RTT_DEBUG


int		daemon_proc;		/* set nonzero by daemon_init() */
/* Print message and return to caller
 * Caller specifies "errnoflag" and "level" */
#define LOG_ERR 3
 
int		rtt_d_flag = 0;		/* debug flag; can be set by caller */

/*
 * Calculate the RTO value based on current estimators:
 *		smoothed RTT plus four times the deviation
 */
#define	  RTT_RTOCALC(ptr) ((ptr)->rtt_srtt + (4.0 * (ptr)->rtt_rttvar))


typedef	void	Sigfunc(int);	/* for signal handlers */

Sigfunc *
Signal(int signo, Sigfunc *func)	/* for our signal() function */
{
	Sigfunc	*sigfunc;

	if ( (sigfunc = signal(signo, func)) == SIG_ERR)
		// err_sys("signal error");
        cout<<"signal error"<<endl;
	return(sigfunc);
}


#define MAXLINE 4096
#define	SA	 sockaddr
typedef int socklent;

struct rtt_info {
	float		rtt_rtt;	/* most recent measured RTT, seconds */
	float		rtt_srtt;	/* smoothed RTT estimator, seconds */
	float		rtt_rttvar;	/* smoothed mean deviation, seconds */
	float		rtt_rto;	/* current RTO to use, seconds */
	int		rtt_nrexmt;	/* #times retransmitted: 0, 1, 2, ... */
	uint32_t	rtt_base;	/* #sec since 1/1/1970 at start */
};

#define	RTT_RXTMIN      2	/* min retransmit timeout value, seconds */
#define	RTT_RXTMAX     60	/* max retransmit timeout value, seconds */
#define	RTT_MAXNREXMT 	3	/* max #times to retransmit */


static struct rtt_info   rttinfo;
static int	rttinit = 0;
static struct msghdr	msgsend, msgrecv;	/* assumed init to 0 */
static struct hdr {
	uint32_t	seq;	/* sequence # */
	uint32_t	ts;		/* timestamp when sent */
} sendhdr, recvhdr;

static void	sig_alrm(int signo);
static sigjmp_buf	jmpbuf;

static int			canjump;
 void
sig_alrm(int signo)
{
	if (canjump == 0)
		return;
	siglongjmp(jmpbuf, 1);
}

int	Dg_send_recv(int, const void*, size_t, void*, size_t, const SA*, socklent);

void Fputs(const char *ptr, FILE *stream)
{
	if (fputs(ptr, stream) == EOF)
		cout<<"fputs error"<<endl;
}

static void err_doit(int errnoflag, const char *fmt, va_list ap)
{
	int		errno_save;
	char	buf[MAXLINE];

	errno_save = errno;		/* value caller might want printed */
	vsprintf(buf, fmt, ap);
	if (errnoflag)
		sprintf(buf+strlen(buf), ": %s", strerror(errno_save));
	strcat(buf, "\n");
	fflush(stdout);		/* in case stdout and stderr are the same */
	fputs(buf, stderr);
	fflush(stderr);		/* SunOS 4.1.* doesn't grok NULL argument */
	return;
}


void err_msg(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	err_doit(0, fmt, ap);
	va_end(ap);
	return;
}


void err_quit(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	err_doit(0, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	err_doit(1, fmt, ap);
	va_end(ap);
	exit(1);
}



char *Fgets(char *ptr, int n, FILE *stream)
{
	char	*rptr;

	 if ( (rptr = fgets(ptr, n, stream)) == NULL && ferror(stream))
    // if ( (rptr = fgets(ptr, n, stream)) == NULL )
		std::cout<<"fgets error"<<endl;

	return (rptr);
}

void dg_cli(FILE* fp, int sockfd, const SA* pservaddr, socklent servlen)
{
	int	n;
	char	sendline[MAXLINE], recvline[MAXLINE + 1];

	while (Fgets(sendline, MAXLINE, fp) != NULL) {

		n = Dg_send_recv(sockfd, sendline, strlen(sendline),
			recvline, MAXLINE, pservaddr, servlen);

		recvline[n] = 0;	/* null terminate */
		Fputs(recvline, stdout);
	}
}


void rtt_newpack(struct rtt_info *ptr)
{
	ptr->rtt_nrexmt = 0;
}

void Gettimeofday(struct timeval *tv, void *foo)
{
	if (gettimeofday(tv, NULL) == -1)
		cout<<"gettimeofday error"<<endl;
	return;
}

static float rtt_minmax(float rto)
{
	if (rto < RTT_RXTMIN)
		rto = RTT_RXTMIN;
	else if (rto > RTT_RXTMAX)
		rto = RTT_RXTMAX;
	return(rto);
}
void rtt_init(struct rtt_info *ptr)
{
	struct timeval	tv;

	Gettimeofday(&tv, NULL);
	ptr->rtt_base = tv.tv_sec;		/* # sec since 1/1/1970 at start */

	ptr->rtt_rtt    = 0;
	ptr->rtt_srtt   = 0;
	ptr->rtt_rttvar = 0.75;
	ptr->rtt_rto = rtt_minmax(RTT_RTOCALC(ptr));
		/* first RTO at (srtt + (4 * rttvar)) = 3 seconds */
}

uint32_t rtt_ts(struct rtt_info *ptr)
{
	uint32_t		ts;
	struct timeval	tv;

	Gettimeofday(&tv, NULL);
	ts = ((tv.tv_sec - ptr->rtt_base) * 1000) + (tv.tv_usec / 1000);
	return(ts);
}


// void Sendto(int fd, const void *ptr, size_t nbytes, int flags,
// 	   const struct sockaddr *sa, socklent salen)
// {
// 	if (sendto(fd, ptr, nbytes, flags, sa, salen) != (ssize_t)nbytes)
// 		cout<<"sendto error"<<endl;
// }

void Sendmsg(int fd, const struct msghdr *msg, int flags)
{
	unsigned int	i;
	ssize_t			nbytes;

	nbytes = 0;	/* must first figure out what return value should be */
	for (i = 0; i < msg->msg_iovlen; i++)
		nbytes += msg->msg_iov[i].iov_len;

	if (sendmsg(fd, msg, flags) != nbytes)
		cout<<"sendmsg error"<<endl;
}

int rtt_start(struct rtt_info *ptr)
{
	return((int) (ptr->rtt_rto + 0.5));		/* round float to int */
		/* 4return value can be used as: alarm(rtt_start(&foo)) */
}

int rtt_timeout(struct rtt_info *ptr)
{
	ptr->rtt_rto *= 2;		/* next RTO */

	if (++ptr->rtt_nrexmt > RTT_MAXNREXMT)
		return(-1);			/* time to give up for this packet */
	return(0);
}

ssize_t Recvmsg(int fd, struct msghdr *msg, int flags)
{
	ssize_t		n;

	if ( (n = recvmsg(fd, msg, flags)) < 0)
		cout<<"recvmsg error"<<endl;
	return(n);
}

/* include rtt_stop */
void rtt_stop(struct rtt_info *ptr, uint32_t ms)
{
	double		delta;

	ptr->rtt_rtt = ms / 1000.0;		/* measured RTT in seconds */

	/*
	 * Update our estimators of RTT and mean deviation of RTT.
	 * See Jacobson's SIGCOMM '88 paper, Appendix A, for the details.
	 * We use floating point here for simplicity.
	 */

	delta = ptr->rtt_rtt - ptr->rtt_srtt;
	ptr->rtt_srtt += delta / 8;		/* g = 1/8 */

	if (delta < 0.0)
		delta = -delta;				/* |delta| */

	ptr->rtt_rttvar += (delta - ptr->rtt_rttvar) / 4;	/* h = 1/4 */

	ptr->rtt_rto = rtt_minmax(RTT_RTOCALC(ptr));
}
/* end rtt_stop */
void rtt_debug(struct rtt_info *ptr)
{
	if (rtt_d_flag == 0)
		return;

	fprintf(stderr, "rtt = %.3f, srtt = %.3f, rttvar = %.3f, rto = %.3f\n",
			ptr->rtt_rtt, ptr->rtt_srtt, ptr->rtt_rttvar, ptr->rtt_rto);
	fflush(stderr);
}



int dg_send_recv(int fd, const void* outbuff, size_t outbytes, void* inbuff, size_t inbytes, const SA* destaddr, socklent destlen)
{
	int	n;
	struct iovec	iovsend[2], iovrecv[2];

	if (rttinit == 0) {
		rtt_init(&rttinfo);		/* first time we're called */
		rttinit = 1;
		rtt_d_flag = 1;
	}

	sendhdr.seq++;
	msgsend.msg_name = destaddr;
	msgsend.msg_namelen = destlen;
	msgsend.msg_iov = iovsend;
	msgsend.msg_iovlen = 2;
	iovsend[0].iov_base = &sendhdr;
	iovsend[0].iov_len = sizeof(struct hdr);
	iovsend[1].iov_base = outbuff;
	iovsend[1].iov_len = outbytes;

	msgrecv.msg_name = NULL;
	msgrecv.msg_namelen = 0;
	msgrecv.msg_iov = iovrecv;
	msgrecv.msg_iovlen = 2;
	iovrecv[0].iov_base = &recvhdr;
	iovrecv[0].iov_len = sizeof(struct hdr);
	iovrecv[1].iov_base = inbuff;
	iovrecv[1].iov_len = inbytes;
	/* end dgsendrecv1 */

	/* include dgsendrecv2 */
	Signal(SIGALRM, sig_alrm);
	rtt_newpack(&rttinfo);		/* initialize for this packet */

sendagain:
#ifdef	RTT_DEBUG
	fprintf(stderr, "send %4d: ", sendhdr.seq);
#endif
	sendhdr.ts = rtt_ts(&rttinfo);
	Sendmsg(fd, &msgsend, 0);

	alarm(rtt_start(&rttinfo));	/* calc timeout value & start timer */
#ifdef	RTT_DEBUG
	rtt_debug(&rttinfo);
#endif

	// if (sigsetjmp(jmpbuf, 1) != 0) {
		if (rtt_timeout(&rttinfo) < 0) {
			cout<<"dg_send_recv: no response from server, giving up"<<endl;
			rttinit = 0;	/* reinit in case we're called again */
			errno = ETIMEDOUT;
			return(-1);
		}
#ifdef	RTT_DEBUG
		err_msg("dg_send_recv: timeout, retransmitting");
#endif
		goto sendagain;
	// }

	do {
		n = Recvmsg(fd, &msgrecv, 0);
#ifdef	RTT_DEBUG
		fprintf(stderr, "recv %4d\n", recvhdr.seq);
#endif
	} while (n < sizeof(struct hdr) || recvhdr.seq != sendhdr.seq);

	alarm(0);			/* stop SIGALRM timer */
		/* 4calculate & store new RTT estimator values */
	rtt_stop(&rttinfo, rtt_ts(&rttinfo) - recvhdr.ts);

	return(n - sizeof(struct hdr));	/* return size of received datagram */
}


int Dg_send_recv(int fd, const void* outbuff, size_t outbytes, void* inbuff, size_t inbytes, const SA* destaddr, socklent destlen)
{
	int	n;

	n = dg_send_recv(fd, outbuff, outbytes, inbuff, inbytes, destaddr, destlen);
	if (n < 0)
	//	err_quit("dg_send_recv error");
	cout << "dg_send_recv error" << endl;

	return(n);
}


void Inet_pton(int family, const char *strptr, void *addrptr)
{
	int		n;

	if ( (n = inet_pton(family, strptr, addrptr)) < 0)
		err_sys("inet_pton error for %s", strptr);	/* errno set */
	else if (n == 0)
		err_quit("inet_pton error for %s", strptr);	/* errno not set */

	/* nothing to return */
}

int Socket(int family, int type, int protocol)
{
	int		n;

	if ( (n = socket(family, type, protocol)) < 0)
		err_sys("socket error");
	return(n);
}

int main(int argc, char **argv)
{

    int					sockfd;
	struct sockaddr_in	servaddr;

	// if (argc != 2)
	// 	err_quit("usage: udpcli <IPaddress>");

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(8888);
	Inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

	sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

	dg_cli(stdin, sockfd, (SA *) &servaddr, sizeof(servaddr));

	exit(0);
  

    // struct msghdr msgsend, msgrecv;
    // struct iovec  iovsend[2],iovrecv[2];
    

    
    
    // int sockfd = socket(PF_LOCAL, SOCK_DGRAM, 0);
    // if (sockfd == -1)
    //     perror("创建socket失败"), exit(-1);
    // struct sockaddr_un addr;
    // addr.sun_family =PF_UNIX;
    // //addr.sin_family=PF_UNIX;
    // strcpy(addr.sun_path, "a.sock");
    // //连接
    // int res = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    // if (res == -1)
    //     perror("失败"), exit(-1);
    // printf("成功\n");
    // write(sockfd, "Hello,Socket!", 14);
    // close(sockfd);
    // int sockfd;
    // struct sockaddr_in mysock;

    // sockfd = socket(AF_INET,SOCK_STREAM,0);  //获得fd

    // bzero(&mysock,sizeof(mysock));  //初始化结构体
    // mysock.sin_family = AF_INET;  //设置地址家族
    // mysock.sin_port = htons(800);  //设置端口
    // mysock.sin_addr.s_addr = inet_addr("192.168.1.0");  //设置地址
    // bind(sockfd,(struct sockaddr *)&mysock,sizeof(struct sockaddr));/* bind的时候进行转化 */
    // return 0;


//         //  初始化事件  
//     event_init();  
 
//     //  设置定时器回调函数  
//     struct event ev_time;  
//   //  evtimer_set(&ev_time, on_time, &ev_time);  
//     evtimer_set(&ev_time, on_time, &ev_time);
 
//     //1s运行一次func函数
//     struct timeval tv;  
//     tv.tv_sec = 1;  
//     tv.tv_usec = 0;  
 
//     //添加到事件循环中
//     event_add(&ev_time, &tv);  
 
//     //程序等待就绪事件并执行事件处理
//     event_dispatch();  
 

    // int sockfd, numbytes;

    // char buff[100];

    // struct sockaddr_in their_addr;

    // int i = 0;

    // their_addr.sin_family = AF_INET;

    // their_addr.sin_port = htons(9999);

    // their_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //本次设置的是本地连接

    // bzero(&(their_addr.sin_zero), 0);

    // if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)

    // {

    //     perror("socket error!\n");

    //     exit(1);
    // }

    // // 使用connect连接服务器，their_addr获取服务器信息

    // if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1)

    // {

    //     perror("connect error!\n");

    //     exit(1);
    // }

    // while (1)

    // {

    //     //连接成功后

    //     memset(buff, 0, sizeof(buff));

    //     printf("clinet----:");

    //     scanf("%s", buff);

    //     //客户端开始写入数据，*****此处buff需要和服务器中接收

    //     if (send(sockfd, buff, sizeof(buff), 0) == -1)
    //     {
    //        // recvfrom()
    //         perror("send error \n");

    //         exit(1);
    //     }
    // }

    // close(sockfd);

    // return 0;
}
