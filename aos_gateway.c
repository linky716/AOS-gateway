#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <pthread.h>
#include <assert.h>
#include <inttypes.h>

#pragma pack(1)

#define PAYLOAD_LEN 810
#define PACKET_LEN 896

#define RECV_PORT 12345
#define SEND_PORT 9999

#define RECV_PORT_2 12346
#define SEND_PORT_2 9996

//unsigned int F_count=0;
uint16_t F_count=1;

typedef unsigned int uint16;
typedef unsigned char uint8;

int send_sd=0;
struct sockaddr_in servsend;

socklen_t addr_len_recv = sizeof(struct sockaddr_in);
socklen_t addr_len_send = sizeof(struct sockaddr_in);

int send_sd2=0;
struct sockaddr_in servsend_ip4;

socklen_t addr_len_recv2 = sizeof(struct sockaddr_in);
socklen_t addr_len_send2 = sizeof(struct sockaddr_in);

/******AOS_PACKET******/
typedef struct _packet_
{
        uint8 frame_head_1; //1
        uint8 frame_head_2;
        uint8 frame_head_3;
        uint8 frame_head_4;

        uint16_t VER_SCID_VCID; //2
        uint8 add;

        uint16_t frame_count;
        uint8 flag_field;

        uint8 insert_field[63]; //63

        uint16_t reserve_field_point;

        uint16_t ver_pliden_lol;
        uint16_t packet_len;

        uint8 PID;     //载荷前长度80字节

        uint8 payload[PAYLOAD_LEN]; //载荷810字节

        uint16_t aos_control_field_1;
        uint16_t aos_control_field_2;

        uint16_t CRC;
} aos_packet_t;

struct sniff_ip
{
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  #define IP_RF 0x8000
  #define IP_DF 0x4000
  #define IP_MF 0x2000
  #define IP_OFFMASK 0x1fff
  u_char ip_ttl;
  u_char ip_p;
  u_short ip_sum;
  struct in_addr ip_src,ip_dst;
};

/******CRC******/
static const uint16_t CRC16Table[256]=
{
     0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
     0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
     0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
     0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
     0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
     0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
     0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
     0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
     0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
     0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
     0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
     0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
     0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
     0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
     0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
     0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
     0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
     0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
     0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
     0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
     0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
     0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
     0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
     0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
     0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
     0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
     0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
     0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
     0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
     0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
     0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
     0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

uint16_t CRC16(uint8_t *data, uint32_t length)
{
        uint16_t result=0;
        uint32_t i;
        result=0xFFFF;

        for(i=0;i<length;i++)
        {
                result=((result<<8)&0XFF00)^CRC16Table[(((result>>8)^data[i])&0x00FF)];
        }

        return result;
}

/******FILL_AOS_PAC******/
int fill_aos_packet(char *src, aos_packet_t *aos_packet,uint16_t F_count, uint16_t P_len) //P_len=n+5 ip包长度+5
{
        aos_packet->frame_count=(htons(F_count)); //帧数赋值
//      printf("F_count: %d\n", F_count);
        aos_packet->packet_len=htons(P_len); //包长
        bzero(aos_packet->payload, PAYLOAD_LEN); //清空载荷空间
        memcpy(aos_packet->payload, src, (P_len-5)); //src复制到aos的payload字段，复制的长度是p_len-5

        uint16_t crc;
        crc=CRC16((char *)(&aos_packet)+4, 890);
        aos_packet->CRC=crc;

        return 0;
}

/******READ_AOS_PAC******/
int read_aos_packet(char *dest, char *packet)
{
        memcpy(dest, packet+80,PAYLOAD_LEN);  //   aos帧长80 Byte
        bzero(packet,PAYLOAD_LEN);
        return 0;
}

/******ADD_AOS_HEADER******/
//static pthread_t encap_aos_thread;
static void* encap_aos(void *args)
{
        int recv_sd=0;
        struct sockaddr_in servrecv, client_adr;

        recv_sd=socket(AF_INET,SOCK_DGRAM,0);
        bzero(&servrecv,sizeof(servrecv));
        servrecv.sin_family=AF_INET;
        servrecv.sin_port=htons(RECV_PORT);
        servrecv.sin_addr.s_addr=htonl(INADDR_LOOPBACK);

//      printf("recv_sd=%d\n",recv_sd);

        //set recvbuff size
        int set_recvbuf=20480*1024;
        if(setsockopt(recv_sd,SOL_SOCKET,SO_RCVBUF,(const char*)&set_recvbuf,sizeof(int))==-1)
        {
                perror("Set receive buffer size failed.");
                return NULL;
        }

        //set reuseport
        int opt_val=1;
        setsockopt(recv_sd,SOL_SOCKET,SO_REUSEPORT,&opt_val,sizeof(opt_val));

        if(bind(recv_sd,(struct sockaddr*)&servrecv,addr_len_recv)==-1)
        {
                perror("servrecv bind failed.");
                return NULL;
        }

        int n,m;
        socklen_t client_adr_sz;
        char IPv4_packet[PAYLOAD_LEN];//接收数据包的缓冲区

        client_adr_sz=sizeof(client_adr);

        aos_packet_t aos_packet={
                .frame_head_1=0x1A,
                .frame_head_2=0xCF,
                .frame_head_3=0xFC,
                .frame_head_4=0x1D,

                .VER_SCID_VCID=0xC074,

                .ver_pliden_lol=0x00EA,

                .PID=0xAF,

                .aos_control_field_1=0x0080,
                .aos_control_field_2=0x0000
        };

        bzero(&IPv4_packet,PAYLOAD_LEN);//将数据缓冲区置零
        n=recvfrom(recv_sd, IPv4_packet, PAYLOAD_LEN, 0, (struct sockaddr*)&client_adr, &client_adr_sz);//接收到的字节数
        struct sniff_ip *ip;
        ip=(struct sniff_ip*)IPv4_packet;
        struct in_addr addr2;
        addr2=ip->ip_src;
        char addr3[256];
        inet_ntop(AF_INET,(void *)&addr2,addr3,256); //源ip转换为string格式
//      printf("encap ipv4 src addr = %s\n",addr3);
        while(n)
        {
                printf("the length of packet has received: %d.\n",n);
                if(n==-1)
                {
                        perror("receive failed.");
                        break;
                }
                printf("encap ipv4 src addr = %s\n",addr3);
                int fill_state=fill_aos_packet(IPv4_packet, &aos_packet, F_count, (n+5)); //n是接收到的字节长度
//              printf("fill_state=%d\n",fill_state);
                /*if(fill_state!=0);
                {
                        perror("fill_aos_packet error.");
                        break;
                }
                */

                m=sendto(send_sd,(char *)(&aos_packet),PACKET_LEN,0,(struct sockaddr*)&servsend,addr_len_send);
                if(m==-1)
                {
                        perror("generate aos_packet and forward failed.");
                        break;
                }
                printf("encaped ipv4 src addr = %s\n",addr3);
//              printf("the length of aos_packet has sended: %d.\n",m);
                bzero(&IPv4_packet,PAYLOAD_LEN);
                n=recvfrom(recv_sd, IPv4_packet, PAYLOAD_LEN, 0, (struct sockaddr*)&client_adr, &client_adr_sz);
                F_count++;
        }

        return NULL;
}

/******DEL_AOS_HEADER******/
//static pthread_t uncap_aos_thread;
static void* uncap_aos(void *args)
{
        int recv_sd2=0;
        struct sockaddr_in servrecv_ip4, client_adr_ip4;

        recv_sd2=socket(AF_INET,SOCK_DGRAM,0);
        bzero(&servrecv_ip4,sizeof(servrecv_ip4));
        servrecv_ip4.sin_family=AF_INET;
        servrecv_ip4.sin_port=htons(RECV_PORT_2);
        servrecv_ip4.sin_addr.s_addr=htonl(INADDR_LOOPBACK);

//      printf("recv_sd2=%d\n",recv_sd2);

        //set recvbuff size
        int set_recvbuf2=20480*1024;
        if(setsockopt(recv_sd2,SOL_SOCKET,SO_RCVBUF,(const char*)&set_recvbuf2,sizeof(int))==-1)
        {
                perror("Set receive buffer size failed.");
                return NULL;
        }

        //set reuseport
        int opt_val2=1;
        setsockopt(recv_sd2,SOL_SOCKET,SO_REUSEPORT,&opt_val2,sizeof(opt_val2));

        if(bind(recv_sd2,(struct sockaddr*)&servrecv_ip4,addr_len_recv2)==-1)
        {
                perror("servrecv_ip4 bind failed.");
                return NULL;
        }

        int a,b;
        socklen_t client_adr_ip4_sz;
        char aos_packet[PACKET_LEN];
        char IPv4_packet2[PAYLOAD_LEN];

        client_adr_ip4_sz=sizeof(client_adr_ip4);
        struct sniff_ip *ip;
        bzero(&aos_packet,PACKET_LEN);
        a=recvfrom(recv_sd2, aos_packet, PACKET_LEN, 0, (struct sockaddr*)&client_adr_ip4, &client_adr_ip4_sz);
        while(a)
        {
                printf("the length of packet(ip4) has received: %d.\n",a);
                if(a==-1)
                {
                        perror("receive failed.");
                        break;
                }

                read_aos_packet(IPv4_packet2, aos_packet);//解封
        ip=(struct sniff_ip*)IPv4_packet2;
                struct in_addr addr2;
                addr2=ip->ip_src;
                char addr3[256];
                inet_ntop(AF_INET,(void *)&addr2,addr3,256); //源ip转换为string格式
                printf("uncap ipv4 src addr = %s\n",addr3);
                b=sendto(send_sd2,IPv4_packet2,PAYLOAD_LEN,0,(struct sockaddr*)&servsend_ip4,addr_len_send2);
                if(b==-1)
                {
                        perror("uncap aos_packet and forward failed.");
                        break;
                }
        //      printf("the length of forward_packet has received: %d.\n",b);
                printf("uncaped ipv4 src addr = %s\n",addr3);
                bzero(&aos_packet,PACKET_LEN);
                a=recvfrom(recv_sd2, aos_packet, PACKET_LEN, 0, (struct sockaddr*)&client_adr_ip4, &client_adr_ip4_sz);
        }

        return NULL;
}

int main(int argc, char *argv[])
{
        int thread_count=3;
        //int i;
        /*start three double orient process thread.*/

        send_sd=socket(AF_INET,SOCK_DGRAM,0);
        bzero(&servsend,sizeof(servsend));
        servsend.sin_family=AF_INET;
        servsend.sin_port=htons(SEND_PORT);
        if(inet_pton(AF_INET,"127.0.0.1",&servsend.sin_addr)==0)
        {
                perror("servsend initialize failed.");
                return NULL;
        }
//      printf("send_sd=%d\n",send_sd);

        send_sd2=socket(AF_INET,SOCK_DGRAM,0);
        bzero(&servsend_ip4,sizeof(servsend_ip4));
        servsend_ip4.sin_family=AF_INET;
        servsend_ip4.sin_port=htons(SEND_PORT_2);
        if(inet_pton(AF_INET,"127.0.0.1",&servsend_ip4.sin_addr)==0)
        {
                perror("servsend_ip4 initialize failed.");
                return NULL;
        }
//      printf("send_sd2=%d\n",send_sd2);

        /******5 encap_aos thread******/
        pthread_t thread_fd_1;
        if(pthread_create(&thread_fd_1,NULL,&encap_aos,NULL)<0)//指向线程标识符的指针，线程属性，运行函数起始地址，运行函数参数
        {
                perror("can't make encap_aos thread.");
                return EXIT_FAILURE;
        }


        /******5 uncap_aos thread******/
        pthread_t thread_fd2_1;
        if(pthread_create(&thread_fd2_1,NULL,&uncap_aos,NULL)<0)//解封
        {
                perror("can't make uncap_aos thread.");
                return EXIT_FAILURE;
        }

        pthread_join(thread_fd_1, NULL);
        pthread_join(thread_fd2_1, NULL);


        return EXIT_SUCCESS;
}
