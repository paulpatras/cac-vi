//============================================================================
// Name        : adaptive_video.cpp
// Author      : Paul Patras
// Version     : 0.02
// Copyright   : 
// Description : Adaptive Algorithm for Efficient Video Transmission over
//					IEEE 802.11e EDCA WLANs
//============================================================================

#include "adaptive_video.h"

char *ifname, *activeIf, *monIf;

struct ifreq ifr;
struct sockaddr_ll skll;

const struct ether_addr * ether_ap;

int sock;
int running, iRet, snifferOn, updaterOn, updating, processing;

unsigned int r, s;
long unsigned int txframes, txframesold;
long unsigned int retries, retriesold;
long unsigned int bcnt, frames;

double pmeas, pcol;
double mu, lambda;
double avframe, framecnt;
double kp,ki,E;

uint8_t *buffer;
uint8_t hwaddr[8];

pthread_t hSniffingThread, hUpdater;

int main(int argc, char** argv) {

	running = 1;
	updating = 0;
	processing = 0;

	activeIf = (char*)calloc(IFNAMSIZ, sizeof(char));
	monIf = (char*)calloc(IFNAMSIZ, sizeof(char));

	// Parse command line
	if(argc !=3 )
	{
		printf("Usage: %s %s %s\n", argv[0], "<active interface>", "<monitor interface>");
		exit(0);
	}
	strcpy(activeIf,argv[1]);
	strcpy(monIf,argv[2]);

	uid_t uid = getuid();

    if ( uid != 0 ) {
         printf("Root permissions required\n");
         exit(0);
    }



	signal(SIGINT, sigproc);

	//get wireless info
	struct wireless_info info;
	getIfaceL2ID(hwaddr,activeIf);

	int skfd;
	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
	{
		 printf("ERROR creating system socket\n");
		 return -1;
	}
	iRet = getWirelessInfo(skfd, activeIf, &info);
	if(iRet < 0)
	{
		printf("Failed to get wireless info\n");
		return -1;
	}
	close(skfd);

	ether_ap = (const struct ether_addr *) &(info.ap_addr).sa_data;

	r=0; s=0;

	avframe=0; framecnt=0;

	//controller parameters
	pcol=0.241680;
	
	kp= 0.8/(pow(pcol,2));
	ki= 0.4/(0.85*(pow(pcol,2)));
	E = CWmin/ki;

	//launch sniffing
	iRet = pthread_create(&hSniffingThread, NULL, SnifferFunction, NULL);

	if(iRet <0 )
	{
		printf("Fail to launch sniffer\n");
		return -1;
	}

	iRet = pthread_create(&hUpdater, NULL, UpdaterFunction, NULL);
	if(iRet <0 )
	{
			printf("Fail to launch updater\n");
			return -1;
	}

	for(;;) sleep(1);

	return EXIT_SUCCESS;
}

//--------------------------------------------------
int processPacket()
{
	int bytes;
	int i;
	uint8_t bssid[6];
	uint8_t src[6];

	int bcast;

	uint8_t DSstatus;

	bytes = recvfrom(sock, buffer, MPDU, 0, NULL, NULL);

	if (bytes < 14)
	{
		//Ignore frames smaller than 14 Bytes
		return -1;
	}

	uint8_t frameType = buffer[0];
	frameType &= 0x0C; //get the type out of the frame control field
	frameType = frameType >> 2;

	if (frameType != 2)		//frame is not a data frame
		goto __PROCESSED;

	DSstatus = buffer[1] & 0x03;

	bcast=0;

	switch(DSstatus){
	case 0: //IBSS
		goto __PROCESSED;
	case 1: //To AP
		//check if destination is broadcast
		for(i=0;i<6;i++)
			if(buffer[i+16] != 0xFF)
				bcast=1;

		//BSSID
		for(i=0;i<6;i++)
			bssid[i]=buffer[i+4];

		for(i=0;i<6;i++)
			src[i]=buffer[i+10];

		//printf("%d\n",bytes);

		break;
	case 2:	//From AP
		//check if destination is broadcast
		for(i=0;i<6;i++)
			if(buffer[i+4] != 0xFF)
				bcast=1;
		for(i=0;i<6;i++)
			src[i]=buffer[i+16];

		//BSSID
		for(i=0;i<6;i++)
			bssid[i]=buffer[i+10];
		break;

	case 3: //WDS
		goto __PROCESSED;
	}

	while(updating);
	processing = 1;
	//Check it the frame belongs to the BSS
	if ((compareMAC(bssid,hwaddr) == 1) && (compareMAC(src,hwaddr) != 1) && (bcast))
	{
		uint8_t flags = buffer[1];
		//check the retry flag
		if((flags & 0x08) == 0x08) r++;
		else s++;
		
		avframe+=bytes;
		framecnt++;
	}
	processing = 0;

__PROCESSED:
	return bytes;
}

//---------------------------------------------------
void *SnifferFunction (void *ptr){

	snifferOn=1;

	iRet = prepareSniffSock();

	if(iRet < 1)
	{
		close(sock);
		snifferOn=0;
		return ptr;
	}

	//main loop
	int size = 0;
	while(running)
	{
		size = processPacket();
	}

	close(sock);
	snifferOn=0;

	return ptr;
}

void *UpdaterFunction (void *ptr){
	updaterOn=1;

	while(running)
	{
		usleep(100000);
		while(processing);
		updating = 1;
	    if(r+s > 0) {
				pmeas = (double)(r)/(r+s);
				r=0; s=0;
				updateCW();
			}
	    updating = 0;
	}

	updaterOn=0;
	return ptr;
}
//-----------------------------------------------------
int prepareSniffSock()
{
		ifname = (char*)calloc(IFNAMSIZ, sizeof(char));
		strcpy(ifname, monIf);
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

		int s;
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
		{
			 printf("ERROR creating system socket\n");
			 return -1;
		}
		//get interface index
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			printf("ERROR - getting index for adapter %s\n", ifr.ifr_name);
		}
		close(s);

		//prepare sniffing socket
		sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock < 0)
		{
				printf("ERROR creating socket\n");
				return -1;
		}

		//socket address
		memset(&skll, 0, sizeof(struct sockaddr_ll));
		skll.sll_family = AF_PACKET;
		skll.sll_ifindex = ifr.ifr_ifindex;
		skll.sll_protocol = htons(ETH_P_ALL);

		//bind socket
		if(bind(sock, (struct sockaddr *) &skll, sizeof(struct sockaddr_ll)) < 0)
		{
			printf("ERROR binding socket\n");
			close(sock);
			return -1;
		}

		//receive buffer;
		buffer = (uint8_t*)calloc(MPDU, sizeof(uint8_t));
		return 1;
}

//------------------------------------------------
void updateCW()
{
	int CW;
	double e;
	int v_be, v_vi;
	char args[3];

	avframe /= framecnt;
	lambda = framecnt/100000;
	double Ts = (96 + avframe*8.0/11 + 10  + 96 + 10 + 50);
	mu = 1.0/Ts;
	
	if (lambda > mu) lambda = mu;
	
	pcol = 1.0-exp(-sqrt(2*Te/Ts));
	
	double popt = pcol*lambda/mu;

	e=pmeas-popt;
	
	kp=0.8/(popt*pcol);
	ki=0.47/(popt*pcol);

	CW = (int)rint(kp*e + ki*E);
	E += e;

	if(CW < CWmin) CW = CWmin;
	if(CW >= CWmax) CW = CWmax;

	v_be = (int) rint(log2(10*CW));

	args[0]=0; //BE
	args[2]=v_be; //new CWmin

	args[1]=1; //STAs
	applyCW(0, args);
	applyCW(1, args);
	
	v_vi = (int) rint(log2(CW));

	args[0]=2; //VI
	args[2]=v_vi; //new CWmin

	args[1]=1; //STAs
	applyCW(0, args);
	applyCW(1, args);
}

//--------------------------------------------------
int applyCW(int win, char args[])
{
	int skfd;
	int		temp;
	iwprivargs *	priv;
	int		number;		// Max of private ioctl
	int i = 0;
	struct iwreq	wrq;
	u_char	buf[4096];

	// Read the private ioctls
	if((skfd = iw_sockets_open()) < 0) return -1;
	number = iw_get_priv_info(skfd, activeIf, &priv);
	close(skfd);

	char *		cmdname = (char*)calloc(64,sizeof(char));
	if (win==0) strcpy(cmdname,"cwmin");
	else strcpy(cmdname,"cwmax");

	// Search the correct ioctl
	int k = -1;
	int		subcmd = 0;	// sub-ioctl index
	while((++k < number) && strcmp(priv[k].name, cmdname));

	int		offset = 0;	// Space for sub-ioctl index

	// Watch out for sub-ioctls !
	if(priv[k].cmd < SIOCDEVPRIVATE)
	{
	     int	j = -1;

	     // Find the matching *real* ioctl
		 while((++j < number) && ((priv[j].name[0] != '\0') || (priv[j].set_args != priv[k].set_args) || (priv[j].get_args != priv[k].get_args)));
		 // Save sub-ioctl number
		 subcmd = priv[k].cmd;
		 // Reserve one int (simplify alignment issues)
		 offset = sizeof(__u32);
		 // Use real ioctl definition from now on
		 k = j;
	}
	int count = 3;

	// Number of args to fetch
	wrq.u.data.length = count;
	if(wrq.u.data.length > (priv[k].set_args & IW_PRIV_SIZE_MASK))
	   wrq.u.data.length = priv[k].set_args & IW_PRIV_SIZE_MASK;

	// Fetch args
	for(; i < wrq.u.data.length; i++)
	{
	    temp = args[i];
	    ((__s32 *) buf)[i] = (__s32) temp;
	}

	strncpy(wrq.ifr_name, activeIf, IFNAMSIZ);

	if(offset)
		wrq.u.mode = subcmd;
	memcpy(wrq.u.name + offset, buf, IFNAMSIZ - offset);

	if((skfd = iw_sockets_open()) < 0) return -1;
	if(ioctl(skfd, priv[k].cmd, &wrq) < 0)
	{
		printf("Cannot set value\n");
		printf("%s (%X): %s\n", cmdname, priv[k].cmd, strerror(errno));
		return -1;
	}

	close(skfd);
	return 0;
}

void sigproc(int i)
{
	printf("\nStopping algorithm...\n");
	running = 0;
	//wait for the sniffer to close
	if(snifferOn){
		sleep(2);
		close(sock);
	}
	exit(0);
}
