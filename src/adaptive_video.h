#ifndef ADAPTIVE_VIDEO_H_
#define ADAPTIVE_VIDEO_H_

#pragma pack(1)

// includes
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <signal.h>

#include <net/if.h>
#include <linux/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#include "wtools/iwlib.h"
#include "wtools/wireless.h"
#include "wtools/wireless_copy.h"
#include "wtools/iwlib.h"

#include "utils.h"
#include "adaptive_video.h"

// ----------------------------------------------------------------------------------------
// Constants

#define CWmin 16
#define CWmax 1024
#define Te 20
#define MPDU 2346

// Error codes defined for setting args
#define IWERR_ARG_NUM		-2
#define IWERR_ARG_TYPE		-3
#define IWERR_ARG_SIZE		-4
#define IWERR_ARG_CONFLICT	-5
#define IWERR_SET_EXT		-6
#define IWERR_GET_EXT		-7

#define	IEEE80211_CHAN_BYTES	32	// howmany(IEEE80211_CHAN_MAX, NBBY)
#define	IEEE80211_IOCTL_SETCHANLIST	(SIOCIWFIRSTPRIV+6)

//IOCTLs
#define SIOCG80211STATS                 (SIOCDEVPRIVATE+2)
#define SIOC80211IFCREATE               (SIOCDEVPRIVATE+7)
#define SIOC80211IFDESTROY              (SIOCDEVPRIVATE+8)
#define	SIOCGATHSTATS		(SIOCDEVPRIVATE+0)

// ----------------------------------------------------------------------------------------
// type definitions

struct ieee80211req_chanlist {
	u_int8_t ic_channels[IEEE80211_CHAN_BYTES];
};

//modes
enum ieee80211_opmode {
        IEEE80211_M_STA         = 1,    /* infrastructure station */
        IEEE80211_M_IBSS        = 0,    /* IBSS (adhoc) station */
        IEEE80211_M_AHDEMO      = 3,    /* Old lucent compatible adhoc demo */
        IEEE80211_M_HOSTAP      = 6,    /* Software Access Point */
        IEEE80211_M_MONITOR     = 8,    /* Monitor mode */
        IEEE80211_M_WDS         = 2     /* WDS link */
};


struct ieee80211_clone_params {
	char icp_name[IFNAMSIZ];				// device name
	u_int16_t icp_opmode;					// operating mode
	u_int16_t icp_flags;					// flags - see below
	#define	IEEE80211_CLONE_BSSID	0x0001	// allocate unique mac/bssid
	#define	IEEE80211_NO_STABEACONS	0x0002	// Do not setup the station beacon timers
} ;

// ----------------------------------------------------------------------------------------
// Functions

int processPacket();
int prepareSniffSock();
int applyCW(int win, char args[]); //0 - CWmin, 1 - CWmax

void *SnifferFunction (void *ptr);
void *UpdaterFunction (void *ptr);

void updateCW();
void sigproc(int i);

// ----------------------------------------------------------------------------------------

#pragma pack()
#endif /*ADAPTIVE_VIDEO_H_*/
