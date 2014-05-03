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

#define V4V_ROUNDUP(a) (((a) +0xf ) & ~0xf)	//additional
#define __HYPERVISOR_v4v_op 39

#endif
