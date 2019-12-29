#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17
#define MSG_LEN 1000

struct msg_to_kernel
{
    struct nlmsghdr hdr;
    char data[MSG_LEN];
};
struct u_packet_info
{
    struct nlmsghdr hdr;
    char msg[MSG_LEN];
};

int main(int argc, char* argv[])
{

    char data[100] = "";
//./proxy insert 0 192 168 200 153 32 -1 60 170 49 75 32 -1 tcp yes permit
//./proxy insert 1 183 78 181 60 32 -1 192 168 200 150 32 -1 tcp yes permit
//insert 0 192 168 200 150 32 -1 192 168 200 2 32 -1 tcp yes permit
//insert 1 192 168 200 150 32 -1 192 168 200 2 32 -1 udp yes permit
//./proxy insert 0 192 168 200 150 32 -1 183 78 181 60 32 -1 tcp yes snat 11 11 11 11 11
//./proxy insert 0 192 168 200 150 32 -1 183 78 181 60 32 -1 tcp yes dnat 11 11 11 11 11
//./proxy mode accept0/reject1
    int i = 0;
    strcat(data, argv[1]);
    for(i=2;i<argc;i++)
    {
        strcat(data, " ");
        strcat(data, argv[i]);
    }
    //初始化
    struct sockaddr_nl local;
    struct sockaddr_nl kpeer;
    int skfd, ret, kpeerlen = sizeof(struct sockaddr_nl);
    struct nlmsghdr *message;
    struct u_packet_info info;
    char *retval;
    message = (struct nlmsghdr *)malloc(1);
    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd < 0){
        printf("can not create a netlink socket\n");
        return -1;
    }
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0){
        printf("bind() error\n");
        return -1;
    }
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;
    kpeer.nl_groups = 0;
    
    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(strlen(data));
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    message->nlmsg_pid = local.nl_pid;
    
    retval = memcpy(NLMSG_DATA(message), data, strlen(data));
    
    printf("message sent to kernel is:\n%s\nlen:%d\n\n", (char *)NLMSG_DATA(message), message->nlmsg_len);
    ret = sendto(skfd, message, message->nlmsg_len, 0,(struct sockaddr *)&kpeer, sizeof(kpeer));
    if(!ret){
        perror("send pid:");
        exit(-1);
    }
    
    //接受内核态确认信息
    ret = recvfrom(skfd, &info, sizeof(struct u_packet_info),0, (struct sockaddr*)&kpeer, &kpeerlen);
    if(!ret){
        perror("recv from kerner:");
        exit(-1);
    }
    
    printf("message received from kernel:\n%s\n\n",((char *)info.msg));
    //内核和用户进行通信
    
    close(skfd);
    return 0;
}