#include <linux/module.h>
#include <net/sock.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <net/netlink.h>
#include "msg.h"
#include "tdd.h"

#define pr_dev(fmt, arg...) \
		printk( "%s, Line%d in %s: " fmt, current->comm, __LINE__, __func__, ##arg)
//#define NETLINK_HTTCSEC_PROT    23
//int httcsec_messsage_prot = NETLINK_HTTCSEC_PROT;

static struct sock *message_sock;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18))
void mysk_release_kernel(struct sock *sk)
{
         if (sk == NULL || sk->sk_socket == NULL)

         sock_hold(sk);
         sock_release(sk->sk_socket);
         sock_put(sk);
}
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
void mysk_release_kernel(struct sock *sk)
{
         if (sk == NULL || sk->sk_socket == NULL)

         sock_hold(sk);
         sock_release(sk->sk_socket);
         release_net(sock_net(sk));
         sock_net_set(sk, get_net(&init_net));
         sock_put(sk);
}
#endif




static void send_netlink_back_data(u32 pid,void *message,int length){
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int len = NLMSG_SPACE(length);
	skb = alloc_skb(len,GFP_KERNEL);
	if(!skb){
		printk("[%s:%d]my_net_link:alloc_skb  hter\n", __func__, __LINE__);
	}

	//slen = stringlength(message);

	nlh = nlmsg_put(skb,pid,0,0,length,0);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
    NETLINK_CB(skb).pid = 0; // from kernel
#else
    NETLINK_CB(skb).portid = 0; // from kernel
#endif
	NETLINK_CB(skb).dst_group = 0;

	memcpy(NLMSG_DATA(nlh),message,length);
	//printk("my_net_link:send = %d, message '%s'.\n",length,(char *)NLMSG_DATA(nlh));
	netlink_unicast(message_sock,skb,pid,MSG_DONTWAIT);
}

//static COMMAND_HANDLER_NL defaul_handler;
static COMMAND_HANDLER_NL hanlders[NL_COMMAND_SIZE];
int httcsec_io_command_register_nl(int command,COMMAND_HANDLER_NL handler){
	if(command < 0 || command >= NL_COMMAND_SIZE ){
		printk("Invalid command number!");
	}
	if(hanlders[command]){
		printk(" [%s:%d]hter command Handler existed!", __func__, __LINE__);
		return -1;
	}
	hanlders[command] = handler;
	return 0;
}
//EXPORT_SYMBOL(httcsec_io_command_register_nl);

void httcsec_io_command_unregister_nl(int command){
	if(command < 0 || command >= NL_COMMAND_SIZE ){
		printk("Invalid command number!");
	}
	hanlders[command] = 0;
}
//EXPORT_SYMBOL(httcsec_io_command_unregister_nl);

static void netlink_rcv(struct sk_buff *__skb)
{

	 struct nlmsghdr *nlh;
	 struct sk_buff *skb;
	 char *buffer;
	// printk("netlink_rcv defaul_handler = %p\n",defaul_handler);
	 buffer = kmalloc(4096,GFP_KERNEL);
	 if(!buffer){
		 printk("[%s:%d]No memory  hter\n", __func__, __LINE__);
		 return;
	 }
	 skb = skb_get(__skb);
	 if (skb->len >= NLMSG_SPACE(0)) {
		 int length = 4096;
		 int r = 0;
		 nlh = nlmsg_hdr(skb);
		 printk("received message type=%d,pid=%d,msglen=%d,another pid=%d\n",
				 nlh->nlmsg_type,nlh->nlmsg_pid,skb->len,NETLINK_CB(skb).portid);
//		// NLMSG_DATA(nih),nlh->nlmsg_len
////		 printk("received %d:%s\n",skb->len - NLMSG_SPACE(0),(char *)NLMSG_DATA(nlh));
		 if(nlh->nlmsg_type < 0 || nlh->nlmsg_type >= NL_COMMAND_SIZE){
			printk("[%s:%d]Command handler(%d) number  hter\n", __func__, __LINE__,nlh->nlmsg_type);
			r =  -1;
		 }
		 else if(!hanlders[nlh->nlmsg_type]){
			printk("Command handler not found\n");
			r =  -1;
		 }
		 else{
			 r = hanlders[nlh->nlmsg_type](NLMSG_DATA(nlh),skb->len - NLMSG_SPACE(0),buffer,&length);
			 pr_dev("Command handle result %x\n",r);

		 }


		 if(r){
			 *(u32 *)buffer = r;
			 send_netlink_back_data(nlh->nlmsg_pid,buffer,sizeof(u32));
		 }
		 else{
			 if(length > 4096)length = 4096;
			 send_netlink_back_data(nlh->nlmsg_pid,buffer,length);
		 }

	 }
	 kfree(buffer);
	 kfree_skb(skb);
}


int netlink_init(void)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18))
  	message_sock = netlink_kernel_create(httcsec_messsage_prot, 0, netlink_rcv, THIS_MODULE);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
	message_sock = netlink_kernel_create(&init_net, httcsec_messsage_prot,
                          0, netlink_rcv, NULL, THIS_MODULE);
#else
	  struct netlink_kernel_cfg cfg = {
	      .input  = netlink_rcv,
	  };
	  message_sock = netlink_kernel_create(&init_net, httcsec_messsage_prot, &cfg);
//	message_sock = netlink_kernel_create(&init_net, httcsec_messsage_prot, netlink_rcv);
#endif

    if (!message_sock)
    {
        printk("netlink: Cannot create netlink socket prot=%d.\n",httcsec_messsage_prot);
        return -EIO;
    }

    printk("netlink: create socket ok ,prot = %d.\n",httcsec_messsage_prot);
    return 0;
}

void netlink_exit(void)
{
    if(message_sock != NULL)
    {
        #if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18))
    		mysk_release_kernel(message_sock);
	#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
    		mysk_release_kernel(message_sock);
        #else
            netlink_kernel_release(message_sock);
        #endif
            message_sock = NULL;

	}
}

int httcsec_io_send_message(void *data,int length,int type)
{
    int result =0;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int total_length;
   // pr_dev("Send message %d,%d\n",length,type);
    if(!data || !message_sock)
        return 0;

    // Allocate a new sk_buffer
    total_length =  NLMSG_SPACE(length);
    skb = alloc_skb(total_length, GFP_KERNEL);
    if(!skb)
    {
        printk("[%s:%d]ALLOC SKB  hter.\n", __func__, __LINE__);
        return 0;
    }

    //Initialize the header of netlink message
    nlh = nlmsg_put(skb, 0, 0, type, length, 0);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
    NETLINK_CB(skb).pid = 0; // from kernel
#else
    NETLINK_CB(skb).portid = 0; // from kernel
#endif

    NETLINK_CB(skb).dst_group = 1; // multi cast

    // message[slen] = '/0';
    memcpy(NLMSG_DATA(nlh), data, length);
   // pr_dev("call netlink_broadcast  Send message %d,%d\n",length,type);
    //send message by multi cast
    result =  netlink_broadcast(message_sock, skb, 0, 1, GFP_KERNEL);
   // pr_dev("broadcast result %d\n",result);
    return 0;
}
//EXPORT_SYMBOL(httcsec_io_send_message);

