#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/delay.h>

#define STATUS_MAXNUM 1000
#define NETLINK_TEST 17
#define MAX_LIFE 5

// Struct for holding each rule
struct rule
{
	unsigned long int src_ip;  //源IP
	unsigned long int smaskoff; //源地址掩码
	unsigned long int dest_ip;  //目的IP
	unsigned long int dmaskoff;  //目的地址IP
	int src_port;  //源端口
	int dest_port;  //目的端口
	int protocol;  //协议
	char log;  //是否记录日志
	char ops;  //NAT类型
	unsigned long int cip;  //NAT IP
	int cport;  //NAT端口
	int lifetime;  //生存时间（维持状态之用）
};

struct log_item
{
	struct rule history;//ops==4 : status
	long previous_jiffies;
};

struct { __u32 pid; }user_process;
struct timer_list sln_timer;
static struct sock *netlinkfd = NULL;
// Hook Options structures
static struct nf_hook_ops input_filter;		// NF_INET_PRE_ROUTING - for incoming packets
static struct nf_hook_ops output_filter;	// NF_INET_POST_ROUTING - for outgoing packets
// Array of rules
static struct rule rules[200];
static int numRules = 0;
static struct rule status_table[STATUS_MAXNUM];//按照源ip、目的ip、源端口、目的端口升序排列，二分查找 
static int num_status = 0;
static unsigned int default_mode = NF_ACCEPT;
static struct log_item LOG[2000];
static int numlogs = 0;

int string_op(char input[]);
int send_to_user(char *info);
void print_IP(unsigned long int src_ip);
void sprint_IP(char output[], unsigned long int src_ip);

struct rule forlog;

void clear_log()
{
	numlogs = 0;
}

int add_log()
{
    struct file *fp;
    mm_segment_t fs;
    loff_t pos;

char output[2000]="\n";
char tmp[100];
sprintf(tmp, "[%d] ", jiffies);
strcat(output, tmp);
sprint_IP(tmp, forlog.src_ip);
strcat(output, tmp);
sprintf(tmp, ":%d -> ",	forlog.src_port);
strcat(output, tmp);
sprint_IP(tmp, forlog.dest_ip);
strcat(output, tmp);
sprintf(tmp, ":%d  ", forlog.dest_port);
strcat(output, tmp);
switch(forlog.protocol)
{
	case 0: strcat(output, "tcp "); break;
	case 1: strcat(output, "udp "); break;
	case 2: strcat(output, "icmp ");break;
}
switch(forlog.ops)
{
	case 0: strcat(output, "accepted."); break;
	case 1: strcat(output, "rejected."); break;
	case 2: case 3: strcat(output, "NATed.");break;
	case 4: strcat(output, "status detected. accepted.");
}
printk("%s", output);
/*    fp = filp_open("/home/test/fw.log",O_RDWR | O_CREAT,0644);
    if (IS_ERR(fp)){
        printk("create file error/n");
        return -1;
    }

    fs = get_fs();
    set_fs(KERNEL_DS);
    pos = 0;
    vfs_write(fp, "4", sizeof("4"), &pos);
    //pos =0;
    //vfs_read(fp, buf1, sizeof(buf), &pos);
    //printk("read: %s/n",buf1);
    filp_close(fp,NULL);
    set_fs(fs);*/
    return 0;
}

void sprint_log()
{
	char output[20000] = "log is at /home/test/log. please 'cat' it. ;-)\n";
	/*char tmp[100];
	int i = 0;
	for(;i<numlogs;i++)
	{
		sprintf(tmp, "[%d] ", LOG[i].previous_jiffies);
		strcat(output, tmp);
		sprint_IP(tmp, LOG[i].history.src_ip);
		strcat(output, tmp);
		sprintf(tmp, ":%d -> ",	LOG[i].history.src_port);
		strcat(output, tmp);
		sprint_IP(tmp, LOG[i].history.dest_ip);
		strcat(output, tmp);
		sprintf(tmp, ":%d  ", LOG[i].history.dest_port);
		strcat(output, tmp);
		switch(LOG[i].history.protocol)
		{
			case 0: strcat(output, "tcp "); break;
			case 1: strcat(output, "udp "); break;
			case 2: strcat(output, "icmp ");break;
		}
		switch(LOG[i].history.ops)
		{
			case 0: strcat(output, "accepted.\n"); break;
			case 1: strcat(output, "rejected.\n"); break;
			case 2: case 3: strcat(output, "NATed.\n");break;
			case 4: strcat(output, "status detected. accepted.\n");
		}
	}
	output[1999]='\0';
	printk("-%d-", numlogs);*/
	send_to_user(output);
	clear_log();
}

int cmp_status(struct rule r1, struct rule r2)//比较函数 
{
	if(r1.src_ip == r2.src_ip)
	{
		
		if(r1.dest_ip == r2.dest_ip)
		{
			if(r1.src_port == r2.src_port)
			{
				return r1.dest_port - r2.dest_port;
			}
			else 
				return r1.src_port - r2.src_port;
		}
		else
			return r1.dest_ip - r2.dest_ip;
	}
	else
		return r1.src_ip - r2.src_ip;
}

int find_status(long int src_ip, long int dest_ip, int src_port, int dest_port)//二分查找
{
	int m;
	int x = 0;
	int y = num_status - 1;
	struct rule v;
	v.dest_ip = dest_ip;
	v.dest_port = dest_port;
	v.src_ip = src_ip;
	v.src_port = src_port;
	while(x < y)
	{
		m = x + (y - x)/2;
		if(cmp_status(status_table[m], v)==0)
		{
			status_table[m].lifetime = MAX_LIFE;
			return m;
		}
		else if(cmp_status(status_table[m], v)>0)
			y = m;
		else
			x = m + 1;
	}
	return -1;
}

int insert_status(long int src_ip, long int dest_ip, int src_port, int dest_port)//二分插入 
{
	struct rule v;
	v.dest_ip = dest_ip;
	v.dest_port = dest_port;
	v.src_ip = src_ip;
	v.src_port = src_port;
	v.lifetime = MAX_LIFE;
	int i=0;
	for(i = num_status;i>0;i--)///////////////////////i>=0
	{
		if(cmp_status(status_table[i-1], v)>=0)
			status_table[i] = status_table[i-1];
		else
			break;
	}
	status_table[i]=v;
	num_status++;
	return i;
}

void delete_status(int m)//二分删除 
{
	int i = 0;
	for(i=m;i<num_status-1;i++)
	{
		status_table[i] = status_table[i+1];
	}
	num_status--;
	return;
}

void print_status()
{
	int i=0;
	char output[2000];
	char id_add[20];
	sprintf(output, "\nCurrent status number: %d\n", num_status);
	for(;i<num_status;i++)
	{
		sprint_IP(id_add, status_table[i].src_ip);
		strcat(output, id_add);
		sprintf(id_add, ":%d -> ", status_table[i].src_port);
		strcat(output, id_add);
		sprint_IP(id_add, status_table[i].dest_ip);
		strcat(output, id_add);
		sprintf(id_add, ":%d\n", status_table[i].dest_port);
		strcat(output, id_add);
		//printk("%d %d %d %d\n", status_table[i].src_ip, status_table[i].dest_ip, status_table[i].src_port, status_table[i].dest_port);
	}
	send_to_user(output);
}


unsigned long tsi;
unsigned long tdi;
int tsp;
int tdp;

int checkRule(struct rule *curr_rule, struct sk_buff *skb){
	/* -1: not match
    0: permit
    1: reject
    2: snat
    3: dnat
*/
    
	// The Network Layer Header
	struct iphdr *ip_header;

	// The Transport Layer Header
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	forlog = *curr_rule;

	if ( !skb ) {
		return 0;
	}

	
	ip_header = (struct iphdr *)skb_network_header(skb);

	if ( !ip_header ) {
		return 0;
	}
    
	unsigned long int src_ip_real_area = tsi = (unsigned long int) (ntohl(ip_header->saddr));
	unsigned long int dest_ip_real_area = tdi = (unsigned long int) (ntohl(ip_header->daddr));
	int real_src_port = 0;
	int real_dest_port = 0;
    char real_protocol = 0;

	unsigned long int src_ip_expected_area = curr_rule->src_ip;
    unsigned long int dest_ip_expected_area = curr_rule->dest_ip;
	int expected_src_port = curr_rule->src_port;
	int expected_dest_port = curr_rule->dest_port;
	char expected_protocol = curr_rule->protocol;

	if ( ip_header->protocol == 6 )	// TCP
    {
        tcp_header = tcp_hdr(skb);
        real_src_port = tsp = ntohs(tcp_header->source);
        real_dest_port = tdp = ntohs(tcp_header->dest);
        real_protocol=0;

        if(find_status(src_ip_real_area, dest_ip_real_area, real_src_port, real_dest_port) != -1 || 
                find_status(dest_ip_real_area, src_ip_real_area, real_dest_port, real_src_port) != -1)
        {
        //printk("status match!\n");
            if(curr_rule->log)
            {
                forlog.src_ip = src_ip_real_area;
                forlog.dest_ip = dest_ip_real_area;
                forlog.src_port = real_src_port;
                forlog.dest_port = real_dest_port;
                forlog.ops = 4;
                add_log();
            }
            return 0;
        }
	else
	{
		//if(tcp_header->syn == 0)
		//{
		//judge if it is snat or dnat
		//	return 0;//here, the correct one should be "return 1", but if i use "return 0", the connect will be normal.
		//}
	}
   }
        else if( ip_header->protocol == 17 )	// UDP
        {
                udp_header = udp_hdr(skb);
                real_src_port = tsp = ntohs(udp_header->source);
                real_dest_port = tdp = ntohs(udp_header->dest);
                real_protocol=1;
        }
        else if ( ip_header->protocol == 1 )	// ICMP
        {
		real_protocol=2;
        }

	int tcp_bool = ((src_ip_expected_area & curr_rule->smaskoff) == (src_ip_real_area & curr_rule->smaskoff) &&
			(dest_ip_expected_area & curr_rule->dmaskoff) == (dest_ip_real_area & curr_rule->dmaskoff) &&
			(expected_src_port == real_src_port || expected_src_port == -1) &&
			(expected_dest_port == real_dest_port || expected_dest_port == -1) &&
			(expected_protocol == -1 || expected_protocol == 0) && real_protocol == 0 );
	int udp_bool = ((src_ip_expected_area & curr_rule->smaskoff) == (src_ip_real_area & curr_rule->smaskoff) &&
			(dest_ip_expected_area & curr_rule->dmaskoff) == (dest_ip_real_area & curr_rule->dmaskoff) &&
			(expected_src_port == real_src_port || expected_src_port == -1) &&
			(expected_dest_port == real_dest_port || expected_dest_port == -1) &&
			(expected_protocol == -1 || expected_protocol == 1) && real_protocol == 1 );
	int icmp_bool = ((src_ip_expected_area & curr_rule->smaskoff) == (src_ip_real_area & curr_rule->smaskoff) &&
			(dest_ip_expected_area & curr_rule->dmaskoff) == (dest_ip_real_area & curr_rule->dmaskoff) &&
			(expected_protocol == -1 || expected_protocol == 2) && real_protocol == 2 );

	if(tcp_bool || udp_bool || icmp_bool)
	{
/*print_IP(src_ip_real_area);
printk(":%d -> ",real_src_port);
print_IP(dest_ip_real_area);
printk(":%d    protocol:%d operation:%d\n",real_dest_port,real_protocol, curr_rule->ops);*/
		if( tcp_bool && curr_rule->ops == 0 )
		{
			insert_status(src_ip_real_area, dest_ip_real_area, real_src_port, real_dest_port);
		}
		if(curr_rule->log)
		{
			forlog.src_ip = src_ip_real_area;
			forlog.dest_ip = dest_ip_real_area;
			forlog.src_port = real_src_port;
			forlog.dest_port = real_dest_port;
			forlog.ops = curr_rule->ops;
			add_log();
		}
		return curr_rule->ops;
	}
	else
	{
		return -1;
	}
	
}

void snat(struct rule *curr_rule, struct sk_buff *skb)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	ip_header = (struct iphdr *)ip_hdr(skb);
	ip_header->saddr = curr_rule->cip;

	tcp_header = tcp_hdr(skb);
	tcp_header->source = curr_rule->cport;
}

void dnat(struct rule *curr_rule, struct sk_buff *skb)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	ip_header = (struct iphdr *)ip_hdr(skb);
	ip_header->daddr = curr_rule->cip;

	tcp_header = tcp_hdr(skb);
	tcp_header->dest = curr_rule->cport;
}

// Function that will perform filtering on incoming and outgoing packets
unsigned int hookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
	// Loop through the array of rules and filter packets
	int i = 0;
	struct rule curr_rule;
	for (i = 0 ; i < numRules ; i++){
		curr_rule = rules[i];
		switch(checkRule(&curr_rule, skb))
		{
			case -1: break;
			case 0 : /*log or not*/ return NF_ACCEPT;
            case 1 : /*log or not*/ return NF_DROP;
            case 2 : /*log or not*/ return NF_ACCEPT;//snat
            case 3 : /*log or not*/ dnat(&curr_rule, skb); return NF_ACCEPT;//dnat
		}
	}
	forlog.src_ip = tsi;
	forlog.dest_ip = tdi;
	forlog.src_port = tsp;
	forlog.dest_port = tdp;
	if(default_mode==NF_ACCEPT)
		forlog.ops = 0;
	else
		forlog.ops = 1;
	add_log();
	return default_mode;
}

// Function that will perform filtering on incoming and outgoing packets
unsigned int hookfn2(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
	// Loop through the array of rules and filter packets
	int i = 0;
	struct rule curr_rule;
	for (i = 0 ; i < numRules ; i++){
		curr_rule = rules[i];
		switch(checkRule(&curr_rule, skb))
		{
			case -1: break;
			case 0 : /*log or not*/ return NF_ACCEPT;
            		case 1 : /*log or not*/ return NF_DROP;
            		case 2 : /*log or not*/ snat(&curr_rule, skb); return NF_ACCEPT;//snat
            		case 3 : /*log or not*/ return NF_ACCEPT;//dnat
		}
	}
	return default_mode;
}

long int convertIP(unsigned char ip[])
{
	long int result = (long int)ip[0]*256*256*256 + (long int)ip[1]*256*256 + (long int)ip[2]*256 + (long int)ip[3];
	//printk("IP %d.%d.%d.%d = %ld", ip[0], ip[1], ip[2], ip[3], result);
	return result;
}

void print_IP(unsigned long int src_ip)
{
	unsigned char src_i[4];
	src_i[3] = src_ip%256; src_ip /= 256;
	src_i[2] = src_ip%256; src_ip /= 256;
	src_i[1] = src_ip%256; src_ip /= 256;
	src_i[0] = src_ip%256; src_ip /= 256;
	printk("%d.%d.%d.%d", src_i[0],src_i[1],src_i[2],src_i[3]);
}

void sprint_IP(char output[], unsigned long int src_ip)
{
	unsigned char src_i[4];
	src_i[3] = src_ip%256; src_ip /= 256;
	src_i[2] = src_ip%256; src_ip /= 256;
	src_i[1] = src_ip%256; src_ip /= 256;
	src_i[0] = src_ip%256; src_ip /= 256;
	sprintf(output, "%d.%d.%d.%d", src_i[0],src_i[1],src_i[2],src_i[3]);
}

int send_to_user(char *info)
{
	int size;
	char input[1000];
	memset(input, '\0', 1000*sizeof(char));
	memcpy(input, info, strlen(info));
	struct sk_buff *skb;
	unsigned char *old_tail;
	struct nlmsghdr *nlh;
	int retval;
	size = NLMSG_SPACE(strlen(input));
	skb = alloc_skb(size, GFP_ATOMIC);
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(input))-sizeof(struct nlmsghdr), 0); 
	old_tail = skb->tail;
	memcpy(NLMSG_DATA(nlh), input, strlen(input));
	nlh->nlmsg_len = skb->tail - old_tail;
	NETLINK_CB(skb).pid = 0;
	NETLINK_CB(skb).dst_group = 0;
    //printk(KERN_DEBUG "[kernel space] skb->data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
	retval = netlink_unicast(netlinkfd, skb, user_process.pid, MSG_DONTWAIT);
	printk(KERN_DEBUG "[kernel space] netlink_unicast return: %d\n", retval);
	return 0;
}

void kernel_receive(struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;

	char *data = "This is eric's test message from kernel.";
    //printk(KERN_DEBUG "[kernel space] begin kernel_receive\n");
    skb = skb_get(__skb);
	if(skb->len >= sizeof(struct nlmsghdr)){
		nlh = (struct nlmsghdr *)skb->data;
		if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
		&& (__skb->len >= nlh->nlmsg_len)){
			user_process.pid = nlh->nlmsg_pid;
			//printk(KERN_DEBUG "[kernel space] data receive from user are:%s\n", (char *)NLMSG_DATA(nlh));
			//printk(KERN_DEBUG "[kernel space] user_pid:%d\n", user_process.pid);
			string_op((char *)NLMSG_DATA(nlh));
			//send_to_user(data);
		}
	}else{
		//printk(KERN_DEBUG "[kernel space] data receive from user are:%s\n",(char *)NLMSG_DATA(nlmsg_hdr(__skb)));
		string_op((char *)NLMSG_DATA(nlmsg_hdr(__skb)));
		//send_to_user(data);
	}
	kfree_skb(skb);
}

int find_char(char input[], char split, int start)
{
	int length = strlen(input);
	int i;
	for(i=start;i<length;i++)
	{
		if(split == input[i])
			return i;
	}
	return -1;
}

int string_op(char input[])
{
	char strin[100];
	strcpy(strin, input);
	char p[100];
	int i = 0;
	struct rule tmp;
	int operation;//0 插入， 1 删除， 2 查找， 3 save
	int index;//索引 
	unsigned char src_ip[4] = {0};
	unsigned char dest_ip[4] = {0};
	unsigned char cip[4] = {0};
	
	int start = 0;
	int old;
	do
	{
		old = start;
		if((start = find_char(input, ' ', start))==-1)
		{
			start = strlen(input);
		}
		start++;
		memset(p, 0, 100*sizeof(char));
		memcpy(p, input+old, (start-old-1)*sizeof(char));
		//printk("-%s-\n", p);
		switch(i)
		{
			case 0: 
				if(p[0]=='i')
					operation = 0;
				else if(p[0]=='d')
					operation = 1;
				else if(p[0]=='r')
					operation = 2;
				else if(p[0]=='l')
					operation = 3;
				else if(p[0]=='s')
					operation = 4;
				else if(p[0]=='m')
					operation = 5;
				else
					return -1;
				break;
			case 1:
				index = simple_strtol(p, NULL, 10);
				break;
			case 2:
				src_ip[0] = simple_strtol(p, NULL, 10);
				break;
			case 3:
				src_ip[1] = simple_strtol(p, NULL, 10);
				break;
			case 4:
				src_ip[2] = simple_strtol(p, NULL, 10);
				break;
			case 5:
				src_ip[3] = simple_strtol(p, NULL, 10);
				tmp.src_ip = convertIP(src_ip);
				break;
			case 6:
				tmp.smaskoff = 0xffffffff<<(simple_strtol(p, NULL, 10));
				break;
			case 7:
				tmp.src_port = simple_strtol(p, NULL, 10);
				break;
				
			case 8:
				dest_ip[0] = simple_strtol(p, NULL, 10);
				break;
			case 9:
				dest_ip[1] = simple_strtol(p, NULL, 10);
				break;
			case 10:
				dest_ip[2] = simple_strtol(p, NULL, 10);
				break;
			case 11:
				dest_ip[3] = simple_strtol(p, NULL, 10);
				tmp.dest_ip = convertIP(dest_ip);
				break;
			case 12:
				tmp.dmaskoff = 0xffffffff<<(simple_strtol(p, NULL, 10));
				break;
			case 13:
				tmp.dest_port = simple_strtol(p, NULL, 10);
				break;
				
			case 14:
				if(p[0]=='a')
					tmp.protocol = -1;
				else if(p[0]=='t')
					tmp.protocol = 0;
				else if(p[0]=='u')
					tmp.protocol = 1;
				else if(p[0]=='i')
					tmp.protocol = 2;
				else
					return -1;
				break;
			case 15:
				if(p[0]=='y')
					tmp.log = 1;
				else if(p[0]=='n')
					tmp.log = 0;
				else
					return -1;
				break;
			case 16:
				if(p[0]=='p')
					tmp.ops = 0;
				else if(p[0]=='r')
					tmp.ops = 1;
				else if(p[0]=='s')
					tmp.ops = 2;
				else if(p[0]=='d')
					tmp.ops = 3;
				else
					return -1;
				break;
			
			case 17:
				cip[0] = simple_strtol(p, NULL, 10);
				break;
			case 18:
				cip[1] = simple_strtol(p, NULL, 10);
				break;
			case 19:
				cip[2] = simple_strtol(p, NULL, 10);
				break;
			case 20:
				cip[3] = simple_strtol(p, NULL, 10);
				tmp.cip = convertIP(cip);
				break;
			case 21:
				tmp.cport = simple_strtol(p, NULL, 10);
				break;
		}
		i++;
	}while(start < strlen(input));
	if(operation == 0)
	{
		i=0;
		if(index>numRules || index<0 )
			return -1; 
		for(i = numRules;i>0;i--)
		{
			if(i>index)
				rules[i] = rules[i-1];
			else
				break;
		}
		rules[i] = tmp;
		numRules++;
//printk("inserted.");
send_to_user("inserted.");
		//return 0;
	}
	if(operation == 1)
	{
		i = 0;
		if(index>=numRules || index<0 )
			return -1; 
		for(i= index ;i<numRules-1;i++)
		{
			rules[i] = rules[i+1];
		}
		numRules--;
//printk(" deleted.");
send_to_user("deleted.");
        //return 0;
	}
	if(operation == 2)
	{
		i=0;
		char output[100] = {0};
		char all[1000] = {0};
                struct rule rulesi;
		for(i=0;i<numRules;i++)
		{
            rulesi = rules[i];
			src_ip[3] = rulesi.src_ip%256; rulesi.src_ip /= 256;
			src_ip[2] = rulesi.src_ip%256; rulesi.src_ip /= 256;
			src_ip[1] = rulesi.src_ip%256; rulesi.src_ip /= 256;
			src_ip[0] = rulesi.src_ip%256; rulesi.src_ip /= 256;
			dest_ip[3] = rulesi.dest_ip%256; rulesi.dest_ip /= 256;
			dest_ip[2] = rulesi.dest_ip%256; rulesi.dest_ip /= 256;
			dest_ip[1] = rulesi.dest_ip%256; rulesi.dest_ip /= 256;
			dest_ip[0] = rulesi.dest_ip%256; rulesi.dest_ip /= 256;
			cip[3] = rulesi.cip%256; rulesi.cip /= 256;
			cip[2] = rulesi.cip%256; rulesi.cip /= 256;
			cip[1] = rulesi.cip%256; rulesi.cip /= 256;
			cip[0] = rulesi.cip%256; rulesi.cip /= 256;
			char pro[10];
			switch(rules[i].protocol)
			{
				case -1: strcpy(pro, "any"); break;
				case 0: strcpy(pro, "tcp"); break;
				case 1: strcpy(pro, "udp"); break;
				case 2: strcpy(pro, "icmp"); break;
			}
			char ops[10];
			switch(rules[i].ops)
			{
				case 0: strcpy(ops, "permit"); break;
				case 1: strcpy(ops, "reject"); break;
				case 2: strcpy(ops, "snat"); break;
				case 3: strcpy(ops, "dnat"); break;
			}
			char log[10];
			switch(rules[i].log)
			{
				case 0: strcpy(log, "no"); break;
				case 1: strcpy(log, "yes"); break;
			}
			sprintf(output, "%d  %d.%d.%d.%d %x port:%d -> %d.%d.%d.%d %x port:%d %s %s %s ", i, src_ip[0], src_ip[1], src_ip[2], src_ip[3], rules[i].smaskoff, rules[i].src_port, dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], rules[i].dmaskoff, rules[i].dest_port, pro, log, ops);
			strcat(all, output);
			if(rules[i].ops == 2 || rules[i].ops == 3)
			{
				sprintf(output, "%d.%d.%d.%d port:%d\n", cip[0], cip[1], cip[2], cip[3], rules[i].cport);
				strcat(all, output);
			}
			else
			{
				strcat(all, "\n");
			}
		}
//printk(all);
send_to_user(all);
	}
	if(operation == 3)
	{
		sprint_log();
		clear_log();
	}
	if(operation == 4)
	{
		print_status();
	}
	if(operation == 5)
	{
		if(index = 0)
			default_mode = NF_ACCEPT;
		else
			default_mode = NF_DROP;
	}
	return 0;
}

void sln_timer_do(unsigned long l)
{
	mod_timer(&sln_timer, jiffies + HZ);//HZ为1秒，在此时间之后继续执行
	int i = 0;
	for(;i<num_status;i++)
	{
		status_table[i].lifetime --;
		if(status_table[i].lifetime == 0)
		{
			delete_status(i);
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int init_module()
{	
	// Initialize Pre-Routing Filter
	printk("\nStarting CWall\n");
	input_filter.hook	= (nf_hookfn *)&hookfn;		// Hook Function
	input_filter.pf		= PF_INET;			// Protocol Family
	input_filter.hooknum	= NF_INET_PRE_ROUTING;		// Hook to be used
	input_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)

	// Initialize Post-Routing Filter
	output_filter.hook	= (nf_hookfn *)&hookfn2;	// Hook Function
	output_filter.pf	= PF_INET;			// Protocol Family
	output_filter.hooknum	= NF_INET_POST_ROUTING;		// Hook to be used
	output_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)
	
	// Register our hooks
	nf_register_hook(&input_filter);
	nf_register_hook(&output_filter);

	init_timer(&sln_timer);//初始化定时器
	sln_timer.expires = jiffies + HZ;   //1s后执行
	sln_timer.function = sln_timer_do;    //执行函数
	add_timer(&sln_timer);    //向内核注册定时器

	netlinkfd = netlink_kernel_create(&init_net, NETLINK_TEST, 0, kernel_receive, NULL, THIS_MODULE);
	if(!netlinkfd)
	{
		printk(KERN_ERR "Can not create a netlink socket.\n");
		return -1;
	}
	return 0;

}

void cleanup_module()
{
	// Unregister our hooks
	nf_unregister_hook(&input_filter);
	nf_unregister_hook(&output_filter);

	del_timer(&sln_timer);//删除定时器

	sock_release(netlinkfd->sk_socket);
	printk("\nStopping CWall");
}