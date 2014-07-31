/******************************************************************************
 * V4V
 *
 * Version 2 of v2v (Virtual-to-Virtual)
 *
 * Copyright (c) 2010, Citrix Systems
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __XEN_CUSTOM_PUBLIC_V4V_H__
#define __XEN_CUSTOM_PUBLIC_V4V_H__

//#include "xen.h"
//#include "event_channel.h"

/*
 * Structure definitions
 */

#define DOMID_INVALID 		(0x7FF4U)	//additional
#define V4V_DOMID_NONE 		DOMID_INVALID	//additional
#define V4V_PORT_NONE		0		//additional

#define V4V_PROTO_DGRAM		0x3c2c1db8	//additional
#define V4V_PROTO_STREAM	0x70f6a8e5	//additional

#define V4V_MYRIXEN_OFFSET 	0xe9046693	//147.102.4.233

#define V4V_ROUNDUP(a) (((a) +0xf ) & ~0xf)	//additional
#define __HYPERVISOR_v4v_op 39

struct sockaddr_xe {
  sa_family_t sxe_family;
  u_int16_t   remote_domid;
  //int         shared_page_gref;
};

struct sockaddr_v4v {
        sa_family_t sa_family;
        unsigned short v4v_reserved1;
        unsigned int port;
        unsigned int domain;
        unsigned char pad[sizeof(struct sockaddr) -
                               sizeof(sa_family_t) -
                               sizeof(unsigned short) -
                               sizeof(unsigned int) - sizeof(unsigned int)];
};


#define AF_XEN  40
#define PF_XEN  AF_XEN

#define xen_sk(__sk) ((struct v4v_sock *)__sk)
#define sk_v4v_sock(__vsk) (&(__vsk)->sk)


#endif
