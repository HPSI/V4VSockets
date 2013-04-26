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

#ifndef __XEN_PUBLIC_V4V_H__
#define __XEN_PUBLIC_V4V_H__

/*
 * Structure definitions
 */

#define V4V_RING_MAGIC          0xA822F72BB0B9D8CC
#define V4V_RING_DATA_MAGIC	0x45FE852220B801E4

#define V4V_PROTO_DGRAM		0x3c2c1db8
#define V4V_PROTO_STREAM 	0x70f6a8e5

#define V4V_DOMID_INVALID       (0x7FFFU)
#define V4V_DOMID_NONE          V4V_DOMID_INVALID
#define V4V_DOMID_ANY           V4V_DOMID_INVALID
#define V4V_PORT_NONE           0

typedef struct v4v_iov
{
    uint64_t iov_base;
    uint64_t iov_len;
} v4v_iov_t;

typedef struct v4v_addr
{
    uint32_t port;
    domid_t domain;
    uint16_t pad;
} v4v_addr_t;

typedef struct v4v_ring_id
{
    v4v_addr_t addr;
    domid_t partner;
    uint16_t pad;
} v4v_ring_id_t;

typedef uint64_t v4v_pfn_t;

typedef struct
{
    v4v_addr_t src;
    v4v_addr_t dst;
} v4v_send_addr_t;

/*
 * v4v_ring
 * id:
 * xen only looks at this during register/unregister
 * and will fill in id.addr.domain
 *
 * rx_ptr: rx pointer, modified by domain
 * tx_ptr: tx pointer, modified by xen
 *
 */
struct v4v_ring
{
    uint64_t magic;
    v4v_ring_id_t id;
    uint32_t len;
    uint32_t rx_ptr;
    uint32_t tx_ptr;
    uint8_t reserved[32];
    uint8_t ring[0];
};
typedef struct v4v_ring v4v_ring_t;

#define V4V_RING_DATA_F_EMPTY       (1U << 0) /* Ring is empty */
#define V4V_RING_DATA_F_EXISTS      (1U << 1) /* Ring exists */
#define V4V_RING_DATA_F_PENDING     (1U << 2) /* Pending interrupt exists - do not
                                               * rely on this field - for
                                               * profiling only */
#define V4V_RING_DATA_F_SUFFICIENT  (1U << 3) /* Sufficient space to queue
                                               * space_required bytes exists */

#if defined(__GNUC__)
# define V4V_RING_DATA_ENT_FULLRING
# define V4V_RING_DATA_ENT_FULL
#else
# define V4V_RING_DATA_ENT_FULLRING fullring
# define V4V_RING_DATA_ENT_FULL full
#endif
typedef struct v4v_ring_data_ent
{
    v4v_addr_t ring;
    uint16_t flags;
    uint16_t pad;
    uint32_t space_required;
    uint32_t max_message_size;
} v4v_ring_data_ent_t;

typedef struct v4v_ring_data
{
    uint64_t magic;
    uint32_t nent;
    uint32_t pad;
    uint64_t reserved[4];
    v4v_ring_data_ent_t data[0];
} v4v_ring_data_t;

struct v4v_info
{
    uint64_t ring_magic;
    uint64_t data_magic;
    evtchn_port_t evtchn;
};
typedef struct v4v_info v4v_info_t;

#define V4V_ROUNDUP(a) (((a) +0xf ) & ~0xf)
/*
 * Messages on the ring are padded to 128 bits
 * Len here refers to the exact length of the data not including the
 * 128 bit header. The message uses
 * ((len +0xf) & ~0xf) + sizeof(v4v_ring_message_header) bytes
 */

#define V4V_SHF_SYN		(1 << 0)
#define V4V_SHF_ACK		(1 << 1)
#define V4V_SHF_RST		(1 << 2)

#define V4V_SHF_PING		(1 << 8)
#define V4V_SHF_PONG		(1 << 9)

struct v4v_stream_header
{
    uint32_t flags;
    uint32_t conid;
};

struct v4v_ring_message_header
{
    uint32_t len;
    uint32_t pad0;
    v4v_addr_t source;
    uint32_t protocol;
    uint32_t pad1;
    uint8_t data[0];
};

typedef struct v4v_viptables_rule
{
    v4v_addr_t src;
    v4v_addr_t dst;
    uint32_t accept;
    uint32_t pad;
} v4v_viptables_rule_t;

typedef struct v4v_viptables_list
{
    uint32_t start_rule;
    uint32_t nb_rules;
    struct v4v_viptables_rule rules[0];
} v4v_viptables_list_t;

/*
 * HYPERCALLS
 */

#define V4VOP_register_ring 	1
/*
 * Registers a ring with Xen, if a ring with the same v4v_ring_id exists,
 * this ring takes its place, registration will not change tx_ptr
 * unless it is invalid
 *
 * do_v4v_op(V4VOP_unregister_ring,
 *           v4v_ring, XEN_GUEST_HANDLE(v4v_pfn),
 *           npage, 0)
 */


#define V4VOP_unregister_ring 	2
/*
 * Unregister a ring.
 *
 * v4v_hypercall(V4VOP_send, v4v_ring, NULL, 0, 0)
 */

#define V4VOP_send 		3
/*
 * Sends len bytes of buf to dst, giving src as the source address (xen will
 * ignore src->domain and put your domain in the actually message), xen
 * first looks for a ring with id.addr==dst and id.partner==sending_domain
 * if that fails it looks for id.addr==dst and id.partner==DOMID_ANY.
 * protocol is the 32 bit protocol number used from the message
 * most likely V4V_PROTO_DGRAM or STREAM. If insufficient space exists
 * it will return -EAGAIN and xen will twing the V4V_INTERRUPT when
 * sufficient space becomes available
 *
 * v4v_hypercall(V4VOP_send,
 *               v4v_send_addr_t addr,
 *               void* buf,
 *               uint32_t len,
 *               uint32_t protocol)
 */


#define V4VOP_notify 		4
/* Asks xen for information about other rings in the system
 *
 * ent->ring is the v4v_addr_t of the ring you want information on
 * the same matching rules are used as for V4VOP_send.
 *
 * ent->space_required  if this field is not null xen will check
 * that there is space in the destination ring for this many bytes
 * of payload. If there is it will set the V4V_RING_DATA_F_SUFFICIENT
 * and CANCEL any pending interrupt for that ent->ring, if insufficient
 * space is available it will schedule an interrupt and the flag will
 * not be set.
 *
 * The flags are set by xen when notify replies
 * V4V_RING_DATA_F_EMPTY	ring is empty
 * V4V_RING_DATA_F_PENDING	interrupt is pending - don't rely on this
 * V4V_RING_DATA_F_SUFFICIENT	sufficient space for space_required is there
 * V4V_RING_DATA_F_EXISTS	ring exists
 *
 * v4v_hypercall(V4VOP_notify,
 *               XEN_GUEST_HANDLE(v4v_ring_data_ent) ent,
 *               NULL, nent, 0)
 */

#define V4VOP_sendv		5
/*
 * Identical to V4VOP_send except rather than buf and len it takes
 * an array of v4v_iov and a length of the array.
 *
 * v4v_hypercall(V4VOP_sendv,
 *               v4v_send_addr_t addr,
 *               v4v_iov iov,
 *               uint32_t niov,
 *               uint32_t protocol)
 */

#define V4VOP_viptables_add     6
/*
 * Insert a filtering rules after a given position.
 *
 * v4v_hypercall(V4VOP_viptables_add,
 *               v4v_viptables_rule_t rule,
 *               NULL,
 *               uint32_t position, 0)
 */

#define V4VOP_viptables_del     7
/*
 * Delete a filtering rules at a position or the rule
 * that matches "rule".
 *
 * v4v_hypercall(V4VOP_viptables_del,
 *               v4v_viptables_rule_t rule,
 *               NULL,
 *               uint32_t position, 0)
 */

#define V4VOP_viptables_list    8
/*
 * Delete a filtering rules at a position or the rule
 * that matches "rule".
 *
 * v4v_hypercall(V4VOP_viptables_list,
 *               v4v_vitpables_list_t list,
 *               NULL, 0, 0)
 */

#define V4VOP_info              9
/*
 * v4v_hypercall(V4VOP_info,
 *               XEN_GUEST_HANDLE(v4v_info_t) info,
 *               NULL, 0, 0)
 */

#endif /* __XEN_PUBLIC_V4V_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
