/******************************************************************************
 * drivers/xen/v4v/v4v.c
 *
 * V4V interdomain communication driver.
 *
 * Copyright (c) 2012 Jean Guyader
 * Copyright (c) 2009 Ross Philipson
 * Copyright (c) 2009 James McKenzie
 * Copyright (c) 2009 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/inet.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <xen/events.h>
#include <xen/evtchn.h>
#include <xen/page.h>
#include <xen/xen.h>
#include <linux/fs.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/major.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/mount.h>


//#include <xen/interface/v4v.h>
//#include <xen/v4vdev.h>
#include <public/v4v.h>
#include "v4v.h"
#include "v4vdev.h"
#include "v4v_utils.h"

unsigned long start = 0, stop = 0, total=0;
#define DEFAULT_RING_SIZE \
    (V4V_ROUNDUP((((PAGE_SIZE)*256) - sizeof(v4v_ring_t)-V4V_ROUNDUP(1))))
/* The type of a ring*/
typedef enum {
        V4V_RTYPE_IDLE = 0,
        V4V_RTYPE_DGRAM,
        V4V_RTYPE_LISTENER,
        V4V_RTYPE_CONNECTOR,
} v4v_rtype;

/* the state of a v4V_private*/
typedef enum {
        V4V_STATE_IDLE = 0,
        V4V_STATE_BOUND,
        V4V_STATE_LISTENING,
        V4V_STATE_ACCEPTED,
        V4V_STATE_CONNECTING,
        V4V_STATE_CONNECTED,
        V4V_STATE_DISCONNECTED
} v4v_state;

typedef enum {
        V4V_PTYPE_DGRAM = 1,
        V4V_PTYPE_STREAM,
} v4v_ptype;

static rwlock_t list_lock;
static struct list_head ring_list;

struct v4v_private;



struct v4v_sock {
  struct sock             sk;
  unsigned char           is_server, is_client;
  domid_t                 otherend_id;
  struct v4v_ring_id      ring_id;
  struct sockaddr_v4v     local_addr;
  struct sockaddr_v4v     remote_addr;
  struct descriptor_page *descriptor_addr;    /* server and client */
  int                     descriptor_gref;    /* server only */
  struct vm_struct       *descriptor_area;    /* client only */
  grant_handle_t          descriptor_handle;  /* client only */
  unsigned int            evtchn_local_port;
  unsigned int            irq;
  unsigned long           buffer_addr;    /* server and client */
  int                    *buffer_grefs;   /* server */
  struct vm_struct       *buffer_area;    /* client */
  grant_handle_t         *buffer_handles; /* client */
  int                     buffer_order;
  /* v4v_private_data */
  struct v4v_private     *priv_data;
};


/* Socket stuff */
static struct proto v4v_proto = {
	.name = "AF_XEN",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct v4v_sock),
	//.connect = v4v_sock_stream_connect,
	//.disconnect = my_disconnect,
	//.accept = v4v_sock_accept,
	//.ioctl = my_ioctl,
	//.init = my_init_sock,
	//.shutdown = my_shutdown,
	//.setsockopt = v4v_sock_stream_setsockopt,
	//.getsockopt = v4v_sock_stream_getsockopt,
	//.sendmsg = v4v_sock_stream_sendmsg,
	//.recvmsg = v4v_sock_stream_recvmsg,
	//.unhash = my_unhash,
	//.get_port = my_get_port,
	//.enter_memory_pressure = my_enter_memory_pressure,
	//.sockets_allocated = &sockets_allocated,
	//.memory_allocated = &memory_allocated,
	//.memory_pressure = &memory_pressure,
	//.orphan_count = &orphan_count,
	//.sysctl_mem = sysctl_tcp_mem,
	//.sysctl_wmem = sysctl_tcp_wmem,
	//.sysctl_rmem = sysctl_tcp_rmem,
	.max_header = 0,
};


/*
 * Ring pointer itself is protected by the refcnt the lists its in by list_lock.
 *
 * It's permittable to decrement the refcnt whilst holding the read lock, and then
 * clean up refcnt=0 rings later.
 *
 * If a ring has refcnt!=0 we expect ->ring to be non NULL, and for the ring to
 * be registered with Xen.
 */

struct ring {
        struct list_head node;
        atomic_t refcnt;

        spinlock_t lock;        /* Protects the data in the v4v_ring_t also privates and sponsor */

        struct list_head privates;      /* Protected by lock */
        struct v4v_private *sponsor;    /* Protected by lock */

        v4v_rtype type;

        /* Ring */
        v4v_ring_t *ring;
        v4v_pfn_t *pfn_list;
        size_t pfn_list_npages;
        int order;
};

struct v4v_private {
        struct list_head node;
        v4v_state state;
        v4v_ptype ptype;
        uint32_t desired_ring_size;
        struct ring *r;
        wait_queue_head_t readq;
        wait_queue_head_t writeq;
        v4v_addr_t peer;
        uint32_t conid;
        spinlock_t pending_recv_lock;   /* Protects pending messages, and pending_error */
        struct list_head pending_recv_list;     /* For LISTENER contains only ... */
        atomic_t pending_recv_count;
        int pending_error;
        int full;
        int send_blocked;
        int rx;
};

struct pending_recv {
        struct list_head node;
        v4v_addr_t from;
        size_t data_len, data_ptr;
        struct v4v_stream_header sh;
        uint8_t data[0];
} V4V_PACKED;

static spinlock_t interrupt_lock;
static spinlock_t pending_xmit_lock;
static struct list_head pending_xmit_list;
static atomic_t pending_xmit_count;

enum v4v_pending_xmit_type {
        V4V_PENDING_XMIT_INLINE = 1,    /* Send the inline xmit */
        V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR,   /* Wake up writeq of sponsor of the ringid from */
        V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES,  /* Wake up writeq of a private of ringid from with conid */
};

struct pending_xmit {
        struct list_head node;
        enum v4v_pending_xmit_type type;
        uint32_t conid;
        struct v4v_ring_id from;
        v4v_addr_t to;
        size_t len;
        uint32_t protocol;
        uint8_t data[0];
};

static void v4v_atomic_inc(atomic_t *refcnt) 
{
	printk(KERN_INFO "inc: %d\n", atomic_read(refcnt));
	atomic_inc(refcnt);
	printk(KERN_INFO "inc: %d\n", atomic_read(refcnt));
}

static void v4v_atomic_dec(atomic_t *refcnt) 
{
	printk(KERN_INFO "dec: %d\n", atomic_read(refcnt));
	atomic_dec(refcnt);
	printk(KERN_INFO "dec: %d\n", atomic_read(refcnt));
}

static inline int v4v_atomic_dec_and_test(atomic_t *refcnt) 
{
	int ret = 0;
	printk(KERN_INFO "decand_test: %d\n", atomic_read(refcnt));
	ret = atomic_dec_and_test(refcnt);
	printk(KERN_INFO "decand_test: %d, ret:%d\n", atomic_read(refcnt), ret);
	return ret;
}

static inline int v4v_atomic_add_unless(atomic_t *refcnt, int v, int u) 
{
	int ret = 0;
	printk(KERN_INFO "add_unless: %d, v:%d, u:%d\n", atomic_read(refcnt), v, u);
	ret = atomic_add_unless(refcnt, v, u);
	printk(KERN_INFO "add_unless: %d, v:%d, u:%d\n", atomic_read(refcnt), v, u);
	return ret;
}

static void dump_msghdr(struct msghdr *m)
{
	struct msghdr msg;
	struct iovec iov;

	memcpy(&msg, m, sizeof(*m));
	memcpy(&iov, m->msg_iov, sizeof(iov));

        dprintk("iov.iov_base:%p\n", iov.iov_base);
        dprintk("iov.iov_len :%#lx\n", iov.iov_len);
        dprintk("msg_name %p\n", msg.msg_name);
        dprintk("msg_iov %p\n", msg.msg_iov);
        dprintk("msg_iov %#lx\n", msg.msg_iovlen);
        dprintk("msg_flags:%#lx\n", msg.msg_flags);


}

static void dump_sockaddr(struct sockaddr_v4v *addr)
{
	dprintk("family:%#lx, domain:%#lx, port:%#lx\n", addr->sa_family, addr->domain, addr->port);
}
static void dump_sockaddr_in(struct sockaddr *addr)
{
	struct sockaddr_in * in_addr = addr;
	//char *ipv4 = inet_pton(in_addr->sin_addr);
	dprintk("family:%#lx, domain:%#lx, port:%#lx\n", in_addr->sin_family, in_addr->sin_addr, in_addr->sin_port);
}

static void sockaddr_to_v4v(struct sockaddr *addr, struct sockaddr_v4v *vm_addr)
{
	struct sockaddr_in *in_addr = addr;

	dump_sockaddr_in(addr);
	vm_addr->sa_family = in_addr->sin_family;
	if (in_addr->sin_addr.s_addr == 0x381a8c0) {
		vm_addr->domain = 3;
	}
	else 
		vm_addr->domain = 1;
	vm_addr->port = in_addr->sin_port;
	dump_sockaddr(vm_addr);
}

static void v4v_to_sockaddr(struct sockaddr_in *addr, struct sockaddr_v4v *vm_addr)
{
	dump_sockaddr(vm_addr);
	addr->sin_family = vm_addr->sa_family;
	if (vm_addr->domain == 3) {
		addr->sin_addr.s_addr = 0x381a8c0;
	}
	else 
		addr->sin_addr.s_addr = 0x281a8c0;
	addr->sin_port = vm_addr->port;
	dump_sockaddr_in(addr);
}



static void dump_socket(struct socket *sock)
{
	dprintk("state:%#lx\n", sock->state);
	dprintk("type:%#x\n", sock->type);
	dprintk("flags:%#lx\n", sock->flags);
	dprintk("file:%p\n", sock->file);
	dprintk("sk:%p\n", sock->sk);
	dprintk("ops:%p\n", sock->ops);
}


#define MAX_PENDING_RECVS        512

/* Hypercalls */

static inline int __must_check
HYPERVISOR_v4v_op(int cmd, void *arg1, void *arg2,
                  uint32_t arg3, uint32_t arg4)
{
        return _hypercall5(int, v4v_op, cmd, arg1, arg2, arg3, arg4);
}

static int v4v_info(v4v_info_t *info)
{
        (void)(*(volatile int*)info);
	dprintk_info("Going to issue V4V_INFO hypercall\n");
        return HYPERVISOR_v4v_op (V4VOP_info, info, NULL, 0, 0);
}

static int H_v4v_register_ring(v4v_ring_t * r, v4v_pfn_t * l, size_t npages)
{
        (void)(*(volatile int *)r);
 	dprintk_info("Going to issue REGISTER hypercall\n");       
	return HYPERVISOR_v4v_op(V4VOP_register_ring, r, l, npages, 0);
}

static int H_v4v_unregister_ring(v4v_ring_t * r)
{
        (void)(*(volatile int *)r);
	dprintk_info("Going to issue UNREGISTER hypercall\n");
        return HYPERVISOR_v4v_op(V4VOP_unregister_ring, r, NULL, 0, 0);
}


static int
H_v4v_sendv(v4v_addr_t * s, v4v_addr_t * d, const v4v_iov_t * iovs,
            uint32_t niov, uint32_t protocol)
{
        v4v_send_addr_t addr;
	int ret;
	void *buf;

	dprintk_in();

	dprintk("source port:%i, domain:%i, dest port:%i, domain: %i protocol: %#x\n",
	         s->port, s->domain, d->port, d->domain, protocol);
        addr.src = *s;
        
	addr.dst = *d;
	dprintk_info("Going to issue SEND hypercall\n");
        ret = HYPERVISOR_v4v_op(V4VOP_sendv, &addr, (void *)iovs, niov,
                                 protocol);
#ifdef V4V_DEBUG
	if (niov > 1) {
	    v4v_iov_t * iov = &iovs[1];
	    buf = (void*)iov->iov_base;
	    //printk(KERN_INFO "%s: buf:%p, len:%#lx\n", __func__, buf, iov->iov_len);
	    //v4v_hexdump(buf, iov->iov_len);
	}
#endif

	dprintk("%s: ret: %d\n", __func__, ret);
	if (ret < 0 && ret != -EAGAIN) {
		dprintk_err("hypercall_fault, ret = %d\n", ret);
	}
	dprintk_out();
	return ret;
}

static int
H_v4v_send(v4v_addr_t * s, v4v_addr_t * d, const void *buf, uint32_t len,
           uint32_t protocol)
{
        v4v_send_addr_t addr;
	int ret;
	v4v_iov_t *iovs = kmalloc(sizeof(v4v_iov_t), GFP_KERNEL);
	BUG();

        addr.src = *s;
        addr.dst = *d;

	/*jo : modification*/
	iovs->iov_base = (uintptr_t)buf;
	iovs->iov_len = len;
	ret = H_v4v_sendv(s, d, iovs, 1, protocol);
	//printk(KERN_INFO "%s: buf:%p, len:%#lx\n", __func__, buf, iovs->iov_len);
	//v4v_hexdump((char*)iovs->iov_base, iovs->iov_len);
        //return HYPERVISOR_v4v_op(V4VOP_send, &addr, (void *)buf, len, protocol);
	//printk(KERN_INFO "%s:ret = %d", __func__, ret);

	return ret;
}

static int H_v4v_notify(v4v_ring_data_t * rd)
{
	dprintk_info("Going to issue NOTIFY hypercall\n");
        return HYPERVISOR_v4v_op(V4VOP_notify, rd, NULL, 0, 0);
}

static int H_v4v_viptables_add(v4vtables_rule_t * rule, int position)
{
	return HYPERVISOR_v4v_op(V4VOP_tables_add, rule, NULL,
                                 position, 0);
}

static int H_v4v_viptables_del(v4vtables_rule_t * rule, int position)
{
        return HYPERVISOR_v4v_op(V4VOP_tables_del, rule, NULL,
                                 position, 0);
}

static int H_v4v_viptables_list(struct v4vtables_list *list)
{
        return HYPERVISOR_v4v_op(V4VOP_tables_list, list, NULL, 0, 0);
}

#ifdef V4V_DEBUG
static char * v4v_ioctl2text(unsigned int cmd)
{
        char *rc = "BLAH";

        dprintk_in();

        if (_IOC_TYPE(cmd) != V4V_TYPE) {
                goto out;
        }

        switch (cmd) {
        case V4VIOCSETRINGSIZE:
		rc = "V4VIOCSETRINGSIZE";
                break;
        case V4VIOCBIND:
		rc = "V4VIOCBIND";
                break;
        case V4VIOCGETSOCKNAME:
		rc = "V4VIOCGETSOCKNAME";
                break;
        case V4VIOCGETPEERNAME:
		rc = "V4VIOCGETPEERNAME";
                break;
        case V4VIOCCONNECT:
		rc = "V4VIOCCONNECT";
                break;
        case V4VIOCGETCONNECTERR:
		rc = "V4VIOCGETCONNECTERR";
                break;
        case V4VIOCLISTEN:
		rc = "V4VIOCLISTEN";
                break;
        case V4VIOCACCEPT:
		rc = "V4VIOCACCEPT";
                break;
        case V4VIOCSEND:
		rc = "V4VIOCSEND";
                break;
        case V4VIOCRECV:
		rc = "V4VIOCRECV";
                break;
        case V4VIOCVIPTABLESADD:
		rc = "V4VIOCVIPTABLESADD";
                break;
        case V4VIOCVIPTABLESDEL:
		rc = "V4VIOCVIPTABLESDEL";
                break;
        case V4VIOCVIPTABLESLIST:
		rc = "V4VIOCVIPTABLESLIST";
                break;
        default:
		break;
        }

out:
        dprintk_out();
        return rc;
}
#endif
/* Port/Ring uniqueness */

/* Need to hold write lock for all of these */

static int v4v_id_in_use(struct v4v_ring_id *id)
{
        struct ring *r;

        list_for_each_entry(r, &ring_list, node) {
                if ((r->ring->id.addr.port == id->addr.port)
                    && (r->ring->id.partner == id->partner))
                        return 1;
        }

        return 0;
}

static int v4v_port_in_use(uint32_t port, uint32_t * max)
{
        uint32_t ret = 0;
        struct ring *r;

        list_for_each_entry(r, &ring_list, node) {
                if (r->ring->id.addr.port == port)
                        ret++;
                if (max && (r->ring->id.addr.port > *max))
                        *max = r->ring->id.addr.port;
        }

        return ret;
}

static uint32_t v4v_random_port(void)
{
        uint32_t port;

        port = prandom_u32();
        port |= 0x80000000U;
        if (port > 0xf0000000U) {
                port -= 0x10000000;
        }

        return port;
}

/* Caller needs to hold lock */
static uint32_t v4v_find_spare_port_number(void)
{
        uint32_t port, max = 0x80000000U;

        port = v4v_random_port();
        if (!v4v_port_in_use(port, &max)) {
                return port;
        } else {
                port = max + 1;
        }

        return port;
}

/* Ring Goo */

static int register_ring(struct ring *r)
{
        return H_v4v_register_ring((void *)r->ring,
                                   r->pfn_list,
                                   r->pfn_list_npages);
}

static int unregister_ring(struct ring *r)
{
        return H_v4v_unregister_ring((void *)r->ring);
}

static void refresh_pfn_list(struct ring *r)
{
        uint8_t *b = (void *)r->ring;
        int i;

        for (i = 0; i < r->pfn_list_npages; ++i) {
                r->pfn_list[i] = pfn_to_mfn(vmalloc_to_pfn(b));
                b += PAGE_SIZE;
        }
}

static void allocate_pfn_list(struct ring *r)
{
        int n = (r->ring->len + sizeof(v4v_ring_t) + PAGE_SIZE - 1) >> PAGE_SHIFT;
        int len = sizeof(v4v_pfn_t) * n;

	dprintk_in();
        r->pfn_list = kmalloc(len, GFP_KERNEL);
        if (!r->pfn_list)
                goto out;
        r->pfn_list_npages = n;

        refresh_pfn_list(r);
	dprintk("pfn_list_npages = %d\n", n);
out:
	dprintk_out();
}

static int allocate_ring(struct ring *r, int ring_len)
{
        int len = ring_len + sizeof(v4v_ring_t);
        int ret = 0;

	dprintk_in();
        if (ring_len != V4V_ROUNDUP(ring_len)) {
                ret = -EINVAL;
                goto fail;
        }

        r->ring = NULL;
        r->pfn_list = NULL;
        r->order = 0;

        r->order = get_order(len);

        r->ring = vmalloc(len);

        if (!r->ring) {
                ret = -ENOMEM;
                goto fail;
        }

        memset((void *)r->ring, 0, len);

        r->ring->magic = V4V_RING_MAGIC;
        r->ring->len = ring_len;
        r->ring->rx_ptr = r->ring->tx_ptr = 0;

        memset((void *)r->ring->ring, 0x5a, ring_len);

        allocate_pfn_list(r);
        if (!r->pfn_list) {

                ret = -ENOMEM;
                goto fail;
        }

	dprintk("ring_len:%#x\n", ring_len);
	dprintk("pfn_list_npages = %#lx\n", r->pfn_list_npages);
	dprintk_out();
        return 0;
 fail:
        if (r->ring)
                vfree(r->ring);
        if (r->pfn_list)
                kfree(r->pfn_list);

        r->ring = NULL;
        r->pfn_list = NULL;

	dprintk_out();
        return ret;
}

/* Caller must hold lock */
static void recover_ring(struct ring *r)
{
        /* It's all gone horribly wrong */
        dprintk_err("horribly wrong ... %p, rx_ptr:%#x, tx_ptr:%#x\n", r->ring, r->ring->rx_ptr, r->ring->tx_ptr);
        r->ring->rx_ptr = r->ring->tx_ptr;
        /* Xen updates tx_ptr atomically to always be pointing somewhere sensible */
}

/* Caller must hold no locks, ring is allocated with a refcnt of 1 */
static int new_ring(struct v4v_private *sponsor, struct v4v_ring_id *pid)
{
        struct v4v_ring_id id = *pid;
        struct ring *r;
        int ret;
        unsigned long flags;

	dprintk_in();
        if (id.addr.domain != V4V_DOMID_NONE)
                return -EINVAL;
	
        r = kmalloc(sizeof(struct ring), GFP_KERNEL);
        memset(r, 0, sizeof(struct ring));

        dprintk("desired_ring_size: %#x\n", sponsor->desired_ring_size);
        ret = allocate_ring(r, sponsor->desired_ring_size);
        if (ret) {
                kfree(r);
                return ret;
        }

        INIT_LIST_HEAD(&r->privates);
        spin_lock_init(&r->lock);
        atomic_set(&r->refcnt, 1);

        write_lock_irqsave(&list_lock, flags);
        if (sponsor->state != V4V_STATE_IDLE) {
                ret = -EINVAL;
                goto fail;
        }

        if (!id.addr.port) {
                id.addr.port = v4v_find_spare_port_number();
        } else if (v4v_id_in_use(&id)) {
                ret = -EADDRINUSE;
                goto fail;
        }

        r->ring->id = id;
        r->sponsor = sponsor;
        sponsor->r = r;
        sponsor->state = V4V_STATE_BOUND;

        dprintk("port:%d domain:%d partner:%d\n", id.addr.port, id.addr.domain, id.partner);
        ret = register_ring(r);
        if (ret)
                goto fail;

        list_add(&r->node, &ring_list);
        write_unlock_irqrestore(&list_lock, flags);
	dprintk_out();
        return 0;

 fail:
        write_unlock_irqrestore(&list_lock, flags);

        vfree(r->ring);
        kfree(r->pfn_list);
        kfree(r);

        sponsor->r = NULL;
        sponsor->state = V4V_STATE_IDLE;

        return ret;
}

/* Cleans up old rings */
static void delete_ring(struct ring *r)
{
        int ret;

	dprintk_in();
        list_del(&r->node);

        if ((ret = unregister_ring(r))) {
                printk(KERN_ERR
                       "unregister_ring hypercall failed: %d. Leaking ring.\n",
                       ret);
        } else {
                vfree(r->ring);
        }

        kfree(r->pfn_list);
        kfree(r);
	dprintk_out();
}

/* Returns !0 if you sucessfully got a reference to the ring */
static int get_ring(struct ring *r)
{
	int ret;	
	dprintk_in();
	printk(KERN_INFO "GETTTTTTTTTTTTTTT RINGGGGGGGGGGGGGGG\n");
        ret = v4v_atomic_add_unless(&r->refcnt, 1, 0);
	dprintk_out();
	return ret;
}

/* Must be called with DEBUG_WRITELOCK; v4v_write_lock */
static void put_ring(struct ring *r)
{
	dprintk_in();
        if (!r) {
		printk(KERN_INFO "RING DOES NOT EXIST\n");
                goto out;
	}

        if (v4v_atomic_dec_and_test(&r->refcnt)) {
		dprintk("delete_ring:%p\n", r);
                delete_ring(r);
        }
out:
	dprintk_out();
	return;
}

/* Caller must hold ring_lock */
static struct ring *find_ring_by_id(struct v4v_ring_id *id)
{
        struct ring *r, *p = NULL;

	dprintk_in();
        list_for_each_entry(r, &ring_list, node) {
                if (!memcmp
                    ((void *)&r->ring->id, id, sizeof(struct v4v_ring_id))){
			p = r;
                        goto out;
		}
        }
out:
	dprintk_out();
        return p;
}

/* Caller must hold ring_lock */
struct ring *find_ring_by_id_type(struct v4v_ring_id *id, v4v_rtype t)
{
        struct ring *r, *p = NULL;

	dprintk_in();
        list_for_each_entry(r, &ring_list, node) {
                if (r->type != t)
                        continue;
                if (!memcmp
                    ((void *)&r->ring->id, id, sizeof(struct v4v_ring_id))) {
                        p = r;
			goto out;
		}
        }

out:
	dprintk_out();
        return p;
}

/* Pending xmits */

/* Caller must hold pending_xmit_lock */

static void
xmit_queue_wakeup_private(struct v4v_ring_id *from,
                          uint32_t conid, v4v_addr_t * to, int len, int delete)
{
        struct pending_xmit *p;
	
	dprintk_in();
        list_for_each_entry(p, &pending_xmit_list, node) {
                if (p->type != V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES)
                        continue;
                if (p->conid != conid)
                        continue;

                if ((!memcmp(from, &p->from, sizeof(struct v4v_ring_id)))
                    && (!memcmp(to, &p->to, sizeof(v4v_addr_t)))) {
                        if (delete) {
                                v4v_atomic_dec(&pending_xmit_count);
                                list_del(&p->node);
				kfree(p);
                        } else {
                                p->len = len;
                        }
                        return;
                }
        }

        if (delete)
                return;

        p = kmalloc(sizeof(struct pending_xmit), GFP_ATOMIC);
        if (!p) {
                printk(KERN_ERR
                       "Out of memory trying to queue an xmit sponsor wakeup\n");
                return;
        }
        p->type = V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES;
        p->conid = conid;
        p->from = *from;
        p->to = *to;
        p->len = len;

        v4v_atomic_inc(&pending_xmit_count);
        list_add_tail(&p->node, &pending_xmit_list);
	dprintk_out();
}

/* Caller must hold pending_xmit_lock */
static void
xmit_queue_wakeup_sponsor(struct v4v_ring_id *from, v4v_addr_t * to,
                          int len, int delete)
{
        struct pending_xmit *p;

	dprintk_in();
        list_for_each_entry(p, &pending_xmit_list, node) {
                if (p->type != V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR)
                        continue;
                if ((!memcmp(from, &p->from, sizeof(struct v4v_ring_id)))
                    && (!memcmp(to, &p->to, sizeof(v4v_addr_t)))) {
                        if (delete) {
                                v4v_atomic_dec(&pending_xmit_count);
                                list_del(&p->node);
				kfree(p);
                        } else {
                                p->len = len;
                        }
                        return;
                }
        }

        if (delete)
                return;

        p = kmalloc(sizeof(struct pending_xmit), GFP_ATOMIC);
        if (!p) {
                printk(KERN_ERR
                       "Out of memory trying to queue an xmit sponsor wakeup\n");
                return;
        }
        p->type = V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR;
        p->from = *from;
        p->to = *to;
        p->len = len;
        v4v_atomic_inc(&pending_xmit_count);
        list_add_tail(&p->node, &pending_xmit_list);
	dprintk_out();
}

static int
xmit_queue_inline(struct v4v_ring_id *from, v4v_addr_t * to,
                  void *buf, size_t len, uint32_t protocol)
{
        ssize_t ret;
        unsigned long flags;
        struct pending_xmit *p;
	v4v_iov_t *iovs;

	dprintk_in();

	iovs = kmalloc(sizeof(v4v_iov_t), GFP_KERNEL);

        spin_lock_irqsave(&pending_xmit_lock, flags);

	/*jo : modification*/
	iovs->iov_base = (uintptr_t)buf;
	iovs->iov_len = len;
        //ret = H_v4v_send(&from->addr, to, buf, len, protocol);
	ret = H_v4v_sendv(&from->addr, to, iovs, 1, protocol);
	/*jo : end*/
	kfree(iovs);

        if (ret != -EAGAIN) {
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                return ret;
        }

        p = kmalloc(sizeof(struct pending_xmit) + len, GFP_ATOMIC);
        //p = kmalloc(sizeof(struct pending_xmit), GFP_ATOMIC);
        if (!p) {
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                printk(KERN_ERR
                       "Out of memory trying to queue an xmit of %zu bytes\n",
                       len);

                return -ENOMEM;
        }

        p->type = V4V_PENDING_XMIT_INLINE;
        p->from = *from;
        p->to = *to;
        p->len = len;
        p->protocol = protocol;

        if (len) {
                //*(char*)p->data = buf;
		//printk(KERN_INFO "p->data:%p\n", p->data);
                memcpy(p->data, buf, len);
	}

        list_add_tail(&p->node, &pending_xmit_list);
        v4v_atomic_inc(&pending_xmit_count);
        spin_unlock_irqrestore(&pending_xmit_lock, flags);

	dprintk_out();
        return len;
}

static void
xmit_queue_rst_to(struct v4v_ring_id *from, uint32_t conid, v4v_addr_t * to)
{
        struct v4v_stream_header sh;
	
	dprintk_in();
        if (!to)
                return;

        sh.conid = conid;
        sh.flags = V4V_SHF_RST;
        xmit_queue_inline(from, to, &sh, sizeof(sh), V4V_PROTO_STREAM);
	dprintk_out();
}

/* RX */

static int
copy_into_pending_recv(struct ring *r, int len, struct v4v_private *p)
{
        struct pending_recv *pending;
        int k, ret = 0, count=0;

	dprintk_in();
        /* Too much queued? Let the ring take the strain */
        if ((count = atomic_read(&p->pending_recv_count)) > MAX_PENDING_RECVS) {
                //printk(KERN_INFO "pending recv count %d, p->full:%d\n", count, p->full);
                spin_lock(&p->pending_recv_lock);
                p->full = 1;
                spin_unlock(&p->pending_recv_lock);

                ret = -1;
                goto out;
        }
	
	/*afairei to sh gt to len to periexei, afou otan klhthei dn exei katharistei akoma to sh*/
        pending =
            kmalloc(sizeof(struct pending_recv) -
                    sizeof(struct v4v_stream_header) + len, GFP_ATOMIC);

        if (!pending) {
		printk(KERN_ERR "out of memory %d\n", len);
                ret = -1;
                goto out;
	}

        pending->data_ptr = 0;
	/*to pragmatiko data_size xwris headers*/
        pending->data_len = len - sizeof(struct v4v_stream_header);

        k = v4v_copy_out(r->ring, &pending->from, NULL, &pending->sh, len, 1);
	if (k < 0) {
	    printk(KERN_ERR "copy_out returned %d\n", k);
	    ret = k;
	}

	dprintk("from:%p, r->ring:%p, len:%#x, buf:%p\n", &pending->from, r->ring, len, &pending->sh);
	dprintk("k:%d\n", k);
	//corrupt!!!
	//v4v_hexdump(&pending->sh, len);
        spin_lock(&p->pending_recv_lock);
        list_add_tail(&pending->node, &p->pending_recv_list);
        v4v_atomic_inc(&p->pending_recv_count);
        p->full = 0;
        spin_unlock(&p->pending_recv_lock);

	//printk(KERN_INFO "enqueueing a pending recv action\n");
	//printk(KERN_INFO "from: %p, data_len: %#lx, sh:%p, data:%p\n", &pending->from, pending->data_len, &pending->sh, pending->data);

out:
	dprintk("ret:%d\n", ret);
	dprintk_out();
        return ret;
}

/* Notify */

/* Caller must hold list_lock */
static void
wakeup_privates(struct v4v_ring_id *id, v4v_addr_t * peer, uint32_t conid)
{
        struct ring *r = find_ring_by_id_type(id, V4V_RTYPE_LISTENER);
        struct v4v_private *p;

	dprintk_in();
        if (!r)
                goto out;

        list_for_each_entry(p, &r->privates, node) {
                if ((p->conid == conid)
                    && !memcmp(peer, &p->peer, sizeof(v4v_addr_t))) {
                        p->send_blocked = 0;
                        wake_up_interruptible_all(&p->writeq);
                        goto out;
                }
        }
out:
	dprintk_out();
	return;
}

/* Caller must hold list_lock */
static void wakeup_sponsor(struct v4v_ring_id *id)
{
        struct ring *r = find_ring_by_id(id);

	dprintk_in();
        if (!r)
                goto out;

        if (!r->sponsor)
                goto out;

        r->sponsor->send_blocked = 0;
        wake_up_interruptible_all(&r->sponsor->writeq);

out:
	dprintk_out();
}

static void v4v_null_notify(void)
{
        H_v4v_notify(NULL);
}

/* Caller must hold list_lock */
static void v4v_notify(void)
{
        unsigned long flags;
        int ret;
        int nent;
        struct pending_xmit *p, *n;
        v4v_ring_data_t *d;
        int i = 0;

	dprintk_in();
        spin_lock_irqsave(&pending_xmit_lock, flags);

        nent = atomic_read(&pending_xmit_count);
        dprintk("nent = %d\n", nent);
        d = kmalloc(sizeof(v4v_ring_data_t) +
                    nent * sizeof(v4v_ring_data_ent_t), GFP_ATOMIC);
        if (!d) {
                dprintk_info("!(d)\n");
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                goto out;
        }
        memset(d, 0, sizeof(v4v_ring_data_t));

        d->magic = V4V_RING_DATA_MAGIC;

        list_for_each_entry(p, &pending_xmit_list, node) {
                dprintk_info("pending_xmit_list\n");
                if (i != nent) {
                	dprintk_info("i!=nent\n");
                        d->data[i].ring = p->to;
                        d->data[i].space_required = p->len;
                        i++;
                }
        }
        d->nent = i;

        if (H_v4v_notify(d)) {
                dprintk_info("kfree(d)\n");
                kfree(d);
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                //MOAN;
                goto out;
        }

        i = 0;
        list_for_each_entry_safe(p, n, &pending_xmit_list, node) {
                int processed = 1;

                if (i == nent)
                        continue;

                if (d->data[i].flags & V4V_RING_DATA_F_EXISTS) {
                        switch (p->type) {
                        case V4V_PENDING_XMIT_INLINE:
				dprintk("%s: v4v_pending_xmit_inline\n",__func__);
                                if (!
                                    (d->data[i].flags &
                                     V4V_RING_DATA_F_SUFFICIENT)) {
                                        processed = 0;
                                        break;
                                }
                                ret =
                                    H_v4v_send(&p->from.addr, &p->to, p->data,
                                               p->len, p->protocol);
                                if (ret == -EAGAIN)
                                        processed = 0;
                                break;
                        case V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR:
				dprintk("%s: v4v_pending_xmit_wait_match_sponsor\n",__func__);
                                if (d->
                                    data[i].flags & V4V_RING_DATA_F_SUFFICIENT)
                                {
                                        wakeup_sponsor(&p->from);
                                } else {
                                        processed = 0;
                                }
                                break;
                        case V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES:
				dprintk("%s: v4v_pending_xmit_wait_match_privates\n", __func__);
                                if (d->
                                    data[i].flags & V4V_RING_DATA_F_SUFFICIENT)
                                {
                                        wakeup_privates(&p->from, &p->to,
                                                        p->conid);
                                } else {
                                        processed = 0;
                                }
                                break;
                        }
                }
                if (processed) {
			dprintk("%s: No one to talk to\n", __func__);
                        list_del(&p->node);     /* No one to talk to */
                        v4v_atomic_dec(&pending_xmit_count);
                        kfree(p);
                }
                i++;
        }

        spin_unlock_irqrestore(&pending_xmit_lock, flags);
        kfree(d);
out:
	dprintk_out();
}

/* VIPtables */
static void
v4v_viptables_add(struct v4v_private *p, struct v4vtables_rule *rule,
                  int position)
{
        H_v4v_viptables_add(rule, position);
}

static void
v4v_viptables_del(struct v4v_private *p, struct v4vtables_rule *rule,
                  int position)
{
        H_v4v_viptables_del(rule, position);
}

static int v4v_viptables_list(struct v4v_private *p, struct v4vtables_list *list)
{
        return H_v4v_viptables_list(list);
}

/* State Machines */
static int
connector_state_machine(struct v4v_private *p, struct v4v_stream_header *sh)
{
	/*jo : trace*/
	int ret = 0;
	dprintk_in();
        if (sh->flags & V4V_SHF_ACK) {
                switch (p->state) {
                case V4V_STATE_CONNECTING:

			dprintk_info("IN V4V_SHF_ACK && STATE CONNECTING\n");
                        p->state = V4V_STATE_CONNECTED;

                        spin_lock(&p->pending_recv_lock);
                        p->pending_error = 0;
                        spin_unlock(&p->pending_recv_lock);
                        wake_up_interruptible_all(&p->writeq);
                        ret = 0;
                        goto out;
                case V4V_STATE_CONNECTED:
                case V4V_STATE_DISCONNECTED:
			dprintk_info("IN V4V_SHF_ACK && STATE DISCONNECTED\n");
                        p->state = V4V_STATE_DISCONNECTED;

                        wake_up_interruptible_all(&p->readq);
                        wake_up_interruptible_all(&p->writeq);
                        ret = 1;       /* Send RST */
                        goto out;
                default:
			dprintk_info("IN V4V_SHF_ACK && DEFAULT\n");
                        break;
                }
        }

        if (sh->flags & V4V_SHF_RST) {
                switch (p->state) {
                case V4V_STATE_CONNECTING:
			dprintk_info("IN V4V_SHF_RST && STATE CONNECTING\n");
                        spin_lock(&p->pending_recv_lock);
                        p->pending_error = -ECONNREFUSED;
                        spin_unlock(&p->pending_recv_lock);
                case V4V_STATE_CONNECTED:
			dprintk_info("IN V4V_SHF_RST && STATE CONNECTED\n");
                        wake_up_interruptible_all(&p->readq);
                        wake_up_interruptible_all(&p->writeq);
                        p->state = V4V_STATE_DISCONNECTED;
                        ret = 0;
                        goto out;
                default:
			dprintk_info("IN V4V_SHF_RST && STATE DEFAULT\n");
                        break;
                }
        }
out:
	dprintk_err("state:%d\n", p->state);
	dprintk_out();
        return ret;
}

static void
acceptor_state_machine(struct v4v_private *p, struct v4v_stream_header *sh)
{
	dprintk_in();
        if ((sh->flags & V4V_SHF_RST)
            && ((p->state == V4V_STATE_ACCEPTED))) {
                p->state = V4V_STATE_DISCONNECTED;
                wake_up_interruptible_all(&p->readq);
                wake_up_interruptible_all(&p->writeq);
        }
	dprintk_err("state:%d\n", p->state);
	dprintk_out();
}

/* Interrupt handler */

static int connector_interrupt(struct ring *r)
{
        ssize_t msg_len;
        uint32_t protocol;
        struct v4v_stream_header sh;
        v4v_addr_t from;
        int ret = 0;

	dprintk_in();

        if (!r->sponsor) {
                //MOAN;
		printk(KERN_ERR "MOAN\n");
                ret = -1;
                goto out;
        }

	dprintk_info("Before Peek the header\n");
	/*koitaei ton header xwris na ton kanei consume*/
	/*epistrefei to len xwris to mh (se ks)*/
        msg_len = v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 0);  /* Peek the header */
        if (msg_len == -1) {
		dprintk_err("Peek the header: rx_ptr: %#lx, tx_ptr: %#lx\n", r->ring->rx_ptr, r->ring->tx_ptr);
                recover_ring(r);
                goto out;
        }



        if ((protocol != V4V_PROTO_STREAM) || (msg_len < sizeof(sh))) {
                /* Wrong protocol bin it */
	        printk(KERN_ERR "Wrong protocol bin it\n");
                v4v_copy_out(r->ring, NULL, NULL, NULL, 0, 1);
		goto out;
        }

        if (sh.flags & V4V_SHF_SYN) {   /* This is a connector no-one should send SYN, send RST back */
		dprintk_info("This is a connector no-one should send SYN\n");
                msg_len =
                    v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 1);
                if (msg_len == sizeof(sh)){
			dprintk_info("This is a connector no-one should send SYN, nested if\n");
                        xmit_queue_rst_to(&r->ring->id, sh.conid, &from);
		}
		goto out;
        }

        /* Right connexion? */
        if (sh.conid != r->sponsor->conid) {
		dprintk_info("Right connection\n");
                msg_len =
                    v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 1);
                xmit_queue_rst_to(&r->ring->id, sh.conid, &from);
                goto out;
        }

        /* Any messages to eat? */
        dprintk("%s: flags = %#x\n",__func__,  sh.flags);
        if (sh.flags & (V4V_SHF_ACK | V4V_SHF_RST)) {
		dprintk_info("Any messages to eat\n");
		/*trwei ton sh se periptwsh pou einai ACK*/
                msg_len =
                    v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 1);
                if (msg_len == sizeof(sh)) {
			dprintk_info("Any messages to eat,2nd if\n");
                        if (connector_state_machine(r->sponsor, &sh)){
				dprintk_info("Any messages to eat, 3rd if\n");
                                xmit_queue_rst_to(&r->ring->id, sh.conid,
                                                  &from);
			}
                }
                goto out;
        }
        //FIXME set a flag to say wake up the userland process next time, and do that rather than copy
	dprintk_info("FIXME\n");
	/*edw ftanei otan thelei na steilei pragmatika data 
	* me to wake_up_interruptible ksekollaei h recv_stream
	*to munhma proxwraei sthn copy_into_pending_recv 
	*mazi me to sh
	*/
        ret = copy_into_pending_recv(r, msg_len, r->sponsor);
        wake_up_interruptible_all(&r->sponsor->readq);

out:
	dprintk_out();
        return ret;
}

/*o acceptor_interrupt kaleitai mono mesa ap ton listener*/
static int
acceptor_interrupt(struct v4v_private *p, struct ring *r,
                   struct v4v_stream_header *sh, ssize_t msg_len)
{
        v4v_addr_t from;
        int ret = 0;

	dprintk_in();
        if (sh->flags & (V4V_SHF_SYN | V4V_SHF_ACK)) {  /* This is an  acceptor no-one should send SYN or ACK, send RST back */
                msg_len =
                    v4v_copy_out(r->ring, &from, NULL, sh, sizeof(*sh), 1);
                if (msg_len == sizeof(*sh))
                        xmit_queue_rst_to(&r->ring->id, sh->conid, &from);
		goto out;
        }

        /* Is it all over */
        if (sh->flags & V4V_SHF_RST) {
                /* Consume the RST */
                msg_len =
                    v4v_copy_out(r->ring, &from, NULL, sh, sizeof(*sh), 1);
                if (msg_len == sizeof(*sh))
                        acceptor_state_machine(p, sh);
                goto out;
        }

        /* Copy the message out */
	/*edw logika einai to recieve gia ton server*/
        ret = copy_into_pending_recv(r, msg_len, p);
	if (ret < 0) {
		dprintk("copy failed, r:%p, msg_len:%#lx, p:%p, ret: %d\n", r, msg_len, p, ret);
	}
        wake_up_interruptible_all(&p->readq);

out:
	dprintk_out();
        return ret;
}

static int listener_interrupt(struct ring *r)
{
        int ret = 0;
        ssize_t msg_len;
        uint32_t protocol;
        struct v4v_stream_header sh;
        struct v4v_private *p;
        v4v_addr_t from;

	dprintk_in();
        msg_len = v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 0);  /* Peek the header */
        if (msg_len == -1) {
		//dprintk_err("Peek the header, r->ring:%p, from=(port:%#x, domain:%#x)\n", r->ring, from.port, from.domain);
		dprintk_err("Peek the header: rx_ptr: %#lx, tx_ptr: %#lx\n", r->ring->rx_ptr, r->ring->tx_ptr);
                recover_ring(r);
                goto out;
        }
	dprintk("%s: msg_len = %#lx\n", __func__, msg_len);

        if ((protocol != V4V_PROTO_STREAM) || (msg_len < sizeof(sh))) {
                /* Wrong protocol bin it */
		dprintk_err("Wrong protocol: %#x\n",protocol);
                v4v_copy_out(r->ring, NULL, NULL, NULL, 0, 1);
		goto out;
        }

        list_for_each_entry(p, &r->privates, node) {
		dprintk("list for each, p->conid:%#lx, sh.conid:%#lx\n", p->conid, sh.conid);
                if ((p->conid == sh.conid)
                    && (!memcmp(&p->peer, &from, sizeof(v4v_addr_t)))) {
                        ret = acceptor_interrupt(p, r, &sh, msg_len);
                        goto out;
                }
        }

        /* Consume it */
        if (r->sponsor && (sh.flags & V4V_SHF_RST)) {
                /*
                 * If we previously received a SYN which has not been pulled by
                 * v4v_accept() from the pending queue yet, the RST will be dropped here
                 * and the connection will never be closed.
                 * Hence we must make sure to evict the SYN header from the pending queue
                 * before it gets picked up by v4v_accept().
                 */
                struct pending_recv *pending, *t;
		dprintk("%s: Consume it\n", __func__);

                spin_lock(&r->sponsor->pending_recv_lock);
                list_for_each_entry_safe(pending, t,
                                         &r->sponsor->pending_recv_list, node) {
                        if (pending->sh.flags & V4V_SHF_SYN
                            && pending->sh.conid == sh.conid) {
                                list_del(&pending->node);
                                v4v_atomic_dec(&r->sponsor->pending_recv_count);
                                kfree(pending);
                                break;
                        }
                }
                spin_unlock(&r->sponsor->pending_recv_lock);

                /* Rst to a listener, should be picked up above for the connexion, drop it */
		dprintk("%s: RST to a listener\n",__func__);
                v4v_copy_out(r->ring, NULL, NULL, NULL, sizeof(sh), 1);
                goto out;
        }

        if (sh.flags & V4V_SHF_SYN) {
                /* Syn to new connexion */
		dprintk("%s: Syn to new connection\n",__func__);
                if ((!r->sponsor) || (msg_len != sizeof(sh))) {
			dprintk("%s: Syn to new connection if\n",__func__);
                        v4v_copy_out(r->ring, NULL, NULL, NULL,
                                           sizeof(sh), 1);
                        goto out;
                }
		dprintk_info("Edw einai gia to SYN???????\n");
                ret = copy_into_pending_recv(r, msg_len, r->sponsor);
		if (ret < 0) {
			dprintk("copy failed, r:%p, msg_len:%#lx, r->sponsor:%p, ret: %d\n", r, msg_len, r->sponsor, ret);
		}
                wake_up_interruptible_all(&r->sponsor->readq);
                goto out;
        }

	dprintk("%s: Before data to new destination\n",__func__);
        v4v_copy_out(r->ring, NULL, NULL, NULL, sizeof(sh), 1);
        /* Data for unknown destination, RST them */
	dprintk("%s: After data to new destination\n",__func__);
        xmit_queue_rst_to(&r->ring->id, sh.conid, &from);

out:
	dprintk_out();
        return ret;
}

static void v4v_interrupt_rx(void)
{
        struct ring *r;
	int cnt=0;

	dprintk_in();
	dprintk_info("INTERRUPT_RX\n");
        read_lock(&list_lock);

        /* Wake up anyone pending */
        list_for_each_entry(r, &ring_list, node) {
		dprintk("tx_ptr:%#lx, rx_ptr:%#lx\n", r->ring->tx_ptr, r->ring->rx_ptr);
                if (r->ring->tx_ptr == r->ring->rx_ptr) {
			dprintk("will continue tx_ptr:%#lx, rx_ptr:%#lx\n", r->ring->tx_ptr, r->ring->rx_ptr);
                        continue;
		}
                switch (r->type) {
                case V4V_RTYPE_IDLE:
                        v4v_copy_out(r->ring, NULL, NULL, NULL, 1, 1);
                        break;
                case V4V_RTYPE_DGRAM:  /* For datagrams we just wake up the reader */
                        if (r->sponsor)
                                wake_up_interruptible_all(&r->sponsor->readq);
                        break;
                case V4V_RTYPE_CONNECTOR:
			dprintk("%s: V4V_RTYPE_CONNECTOR\n",__func__);
                        spin_lock(&r->lock);
                        while ((r->ring->tx_ptr != r->ring->rx_ptr)
                               && !connector_interrupt(r)) ;
                        spin_unlock(&r->lock);
                        break;
                case V4V_RTYPE_LISTENER:
			dprintk("%s: V4V_RTYPE_LISTENER\n",__func__);
                        spin_lock(&r->lock);
                        while ((r->ring->tx_ptr != r->ring->rx_ptr)
                               && !listener_interrupt(r)) {
				dprintk("%s: V4V_RTYPE_LISTENER, cnt= %d\n",__func__,cnt);
				cnt++;
			}
                        spin_unlock(&r->lock);
                        break;
                default:       /* enum warning */
                        break;
                }
        }
        read_unlock(&list_lock);
	dprintk_out();
}

static irqreturn_t v4v_interrupt(int irq, void *dev_id)
{
        unsigned long flags;

	/*jo : trace*/
	dprintk_in();
	//printk("INTERRUPT\n");
        spin_lock_irqsave(&interrupt_lock, flags);
        v4v_interrupt_rx();
        v4v_notify();
        spin_unlock_irqrestore(&interrupt_lock, flags);
	dprintk_out();

        return IRQ_HANDLED;
}

static void v4v_fake_irq(void)
{
        unsigned long flags;
	dprintk_in();
        spin_lock_irqsave(&interrupt_lock, flags);
        v4v_interrupt_rx();
        v4v_null_notify();
        spin_unlock_irqrestore(&interrupt_lock, flags);
	dprintk_out();
}

/* Filesystem gunge */

#define V4VFS_MAGIC 0x56345644  /* "V4VD" */

static struct vfsmount *v4v_mnt = NULL;
static const struct file_operations v4v_fops_stream;

static struct dentry *v4vfs_mount_pseudo(struct file_system_type *fs_type,
                                         int flags, const char *dev_name,
                                         void *data)
{
        return mount_pseudo(fs_type, "v4v:", NULL, NULL, V4VFS_MAGIC);
}

static struct file_system_type v4v_fs = {
        /* No owner field so module can be unloaded */
        .name = "v4vfs",
        .mount = v4vfs_mount_pseudo,
        .kill_sb = kill_litter_super
};

static int setup_fs(void)
{
        int ret;

        ret = register_filesystem(&v4v_fs);
        if (ret) {
                printk(KERN_ERR
                       "v4v: couldn't register tedious filesystem thingy\n");
                return ret;
        }

        v4v_mnt = kern_mount(&v4v_fs);
        if (IS_ERR(v4v_mnt)) {
                unregister_filesystem(&v4v_fs);
                ret = PTR_ERR(v4v_mnt);
                printk(KERN_ERR
                       "v4v: couldn't mount tedious filesystem thingy\n");
                return ret;
        }

        return 0;
}

static void unsetup_fs(void)
{
        mntput(v4v_mnt);
        unregister_filesystem(&v4v_fs);
}

/* Methods */

static int stream_connected(struct v4v_private *p)
{
        switch (p->state) {
        case V4V_STATE_ACCEPTED:
        case V4V_STATE_CONNECTED:
                return 1;
        default:
                return 0;
        }
}

static size_t
v4v_try_send_sponsor(struct v4v_private *p,
                     v4v_addr_t * dest,
                     const void *buf, size_t len, uint32_t protocol)
{
        size_t ret;
        unsigned long flags;

	dprintk_in();
        ret = H_v4v_send(&p->r->ring->id.addr, dest, buf, len, protocol);
	dprintk("%s : ret = %#lx\n", __func__, ret);
        spin_lock_irqsave(&pending_xmit_lock, flags);
        if (ret == -EAGAIN) {
                /* Add pending xmit */
                xmit_queue_wakeup_sponsor(&p->r->ring->id, dest, len, 0);
                p->send_blocked++;

        } else {
                /* Remove pending xmit */
                xmit_queue_wakeup_sponsor(&p->r->ring->id, dest, len, 1);
                p->send_blocked = 0;
        }

        spin_unlock_irqrestore(&pending_xmit_lock, flags);
	dprintk_out();
        return ret;
}

static size_t
v4v_try_sendv_sponsor(struct v4v_private *p,
                      v4v_addr_t * dest,
                      const v4v_iov_t * iovs, size_t niov, size_t len,
                      uint32_t protocol)
{
        size_t ret;
        unsigned long flags;

	dprintk_in();

        ret = H_v4v_sendv(&p->r->ring->id.addr, dest, iovs, niov, protocol);

        spin_lock_irqsave(&pending_xmit_lock, flags);
        if (ret == -EAGAIN) {
                /* Add pending xmit */
                xmit_queue_wakeup_sponsor(&p->r->ring->id, dest, len, 0);
                p->send_blocked++;

        } else {
                /* Remove pending xmit */
                xmit_queue_wakeup_sponsor(&p->r->ring->id, dest, len, 1);
                p->send_blocked = 0;
        }
        spin_unlock_irqrestore(&pending_xmit_lock, flags);

	dprintk_out();

        return ret;
}

/*
 * Try to send from one of the ring's privates (not its sponsor),
 * and queue an writeq wakeup if we fail
 */
static size_t
v4v_try_sendv_privates(struct v4v_private *p,
                       v4v_addr_t * dest,
                       const v4v_iov_t * iovs, size_t niov, size_t len,
                       uint32_t protocol)
{
        size_t ret;
        unsigned long flags;

	dprintk_in();

        ret = H_v4v_sendv(&p->r->ring->id.addr, dest, iovs, niov, protocol);

        spin_lock_irqsave(&pending_xmit_lock, flags);
        if (ret == -EAGAIN) {
                /* Add pending xmit */
                xmit_queue_wakeup_private(&p->r->ring->id, p->conid, dest, len,
                                          0);
                p->send_blocked++;
        } else {
                /* Remove pending xmit */
                xmit_queue_wakeup_private(&p->r->ring->id, p->conid, dest, len,
                                          1);
                p->send_blocked = 0;
        }
        spin_unlock_irqrestore(&pending_xmit_lock, flags);

	dprintk_out();

        return ret;
}

static ssize_t
v4v_sendto_from_sponsor(struct v4v_private *p,
                        const void *buf, size_t len,
                        int nonblock, v4v_addr_t * dest, uint32_t protocol)
{
        size_t ret = 0, ts_ret;

	dprintk_in();

        switch (p->state) {
        case V4V_STATE_CONNECTING:
                ret = -ENOTCONN;
		goto out;
                break;
        case V4V_STATE_DISCONNECTED:
                ret = -EPIPE;
		goto out;
                break;
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
                break;
        default:
                ret = -EINVAL;
		goto out;
        }

        if (len > (p->r->ring->len - sizeof(struct v4v_ring_message_header))) {
		dprintk_err("message size: %#lx vs. %#lx\n", len, p->r->ring->len - sizeof(struct v4v_ring_message_header));
                len = p->r->ring->len - sizeof(struct v4v_ring_message_header);
                //ret = -EMSGSIZE;
		//goto out;
	}
	dprintk("%s len = %#lx, ring_len = %#x, mh = %#lx\n", __func__, len, p->r->ring->len, sizeof(struct v4v_ring_message_header));
        if (ret)
                return ret;

        if (nonblock) {
                return H_v4v_send(&p->r->ring->id.addr, dest, buf, len,
                                  protocol);;
        }
        /*
         * I happen to know that wait_event_interruptible will never
         * evaluate the 2nd argument once it has returned true but
         * I shouldn't.
         *
         * The EAGAIN will cause xen to send an interrupt which will
         * via the pending_xmit_list and writeq wake us up.
         */
        ret = wait_event_interruptible(p->writeq,
                                       ((ts_ret =
                                         v4v_try_send_sponsor
                                         (p, dest,
                                          buf, len, protocol)) != -EAGAIN));
        if (ret)
                ret = ts_ret;
	
out:
	dprintk_out();

        return ret;
}

static ssize_t
v4v_stream_sendvto_from_sponsor(struct v4v_private *p,
                                const v4v_iov_t * iovs, size_t niov,
                                size_t len, int nonblock,
                                v4v_addr_t * dest, uint32_t protocol)
{
        size_t ret = 0, ts_ret;

	dprintk_in();
        switch (p->state) {
        case V4V_STATE_CONNECTING:
                ret = -ENOTCONN;
		goto out;
        case V4V_STATE_DISCONNECTED:
                ret = -EPIPE;
		goto out;
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
                break;
        default:
                ret = -EINVAL;
		goto out;
        }

        if (len > (p->r->ring->len - sizeof(struct v4v_ring_message_header))) {
		dprintk_err("message size: %#lx vs. %#lx\n", len, p->r->ring->len - sizeof(struct v4v_ring_message_header));
                len = p->r->ring->len - sizeof(struct v4v_ring_message_header);
                //ret = -EMSGSIZE;
		//goto out;
	}

        if (ret)
		goto out;

        if (nonblock) {
                ret = H_v4v_sendv(&p->r->ring->id.addr, dest, iovs, niov,
                                   protocol);
		goto out;
        }
        /*
         * I happen to know that wait_event_interruptible will never
         * evaluate the 2nd argument once it has returned true but
         * I shouldn't.
         *
         * The EAGAIN will cause xen to send an interrupt which will
         * via the pending_xmit_list and writeq wake us up.
         */
        ret = wait_event_interruptible(p->writeq,
                                       ((ts_ret =
                                         v4v_try_sendv_sponsor
                                         (p, dest,
                                          iovs, niov, len,
                                          protocol)) != -EAGAIN)
                                       || !stream_connected(p));
        if (ret == 0)
                ret = ts_ret;

out:
	dprintk_out();
        return ret;
}
static ssize_t
v4v_stream_sendvto_from_private(struct v4v_private *p,
                                const v4v_iov_t * iovs, size_t niov,
                                size_t len, int nonblock,
                                v4v_addr_t * dest, uint32_t protocol)
{
        size_t ret = 0, ts_ret;

	dprintk_in();

        switch (p->state) {
        case V4V_STATE_DISCONNECTED:
                return -EPIPE;
        case V4V_STATE_ACCEPTED:
                break;
        default:
                return -EINVAL;
        }

        if (len > (p->r->ring->len - sizeof(struct v4v_ring_message_header)))
                return -EMSGSIZE;

        if (ret)
                return ret;

        if (nonblock) {
                return H_v4v_sendv(&p->r->ring->id.addr, dest, iovs, niov,
                                   protocol);
        }
        /*
         * I happen to know that wait_event_interruptible will never
         * evaluate the 2nd argument once it has returned true but
         * I shouldn't.
         *
         * The EAGAIN will cause xen to send an interrupt which will
         * via the pending_xmit_list and writeq wake us up.
         */
        ret = wait_event_interruptible(p->writeq,
                                       ((ts_ret =
                                         v4v_try_sendv_privates
                                         (p, dest,
                                          iovs, niov, len,
                                          protocol)) != -EAGAIN)
                                       || !stream_connected(p));
        if (ret == 0)
                ret = ts_ret;
	
	dprintk_out();

        return ret;
}

static int v4v_get_sock_name(struct v4v_private *p, struct v4v_ring_id *id)
{
        int rc = 0;

        read_lock(&list_lock);
        if ((p->r) && (p->r->ring)) {
                *id = p->r->ring->id;
        } else {
                rc = -EINVAL;
        }
        read_unlock(&list_lock);

        return rc;
}

static int v4v_get_peer_name(struct v4v_private *p, v4v_addr_t * id)
{
        int rc = 0;
        read_lock(&list_lock);

        switch (p->state) {
        case V4V_STATE_CONNECTING:
        case V4V_STATE_CONNECTED:
        case V4V_STATE_ACCEPTED:
                *id = p->peer;
                break;
        default:
                rc = -ENOTCONN;
        }

        read_unlock(&list_lock);
        return rc;
}

static int v4v_set_ring_size(struct v4v_private *p, uint32_t ring_size)
{
	
	dprintk_in();

        if (ring_size <
            (sizeof(struct v4v_ring_message_header) + V4V_ROUNDUP(1)))
                return -EINVAL;

        if (ring_size != V4V_ROUNDUP(ring_size))
                return -EINVAL;
        read_lock(&list_lock);
        if (p->state != V4V_STATE_IDLE) {
                read_unlock(&list_lock);
                return -EINVAL;
        }

        p->desired_ring_size = ring_size;
        read_unlock(&list_lock);

	dprintk_out();

        return 0;
}

static ssize_t
v4v_recvfrom_dgram(struct v4v_private *p, void *buf, size_t len,
                   int nonblock, int peek, v4v_addr_t * src)
{
        ssize_t ret;
        v4v_addr_t lsrc;
        uint32_t protocol;

	dprintk_in();

        if (!src)
                src = &lsrc;

	dprintk("source port: %#x, domain: %#x\n",
	         src->port, src->domain);
retry:
        if (!nonblock) {
                ret = wait_event_interruptible(p->readq,
                                               (p->r->ring->rx_ptr !=
                                                p->r->ring->tx_ptr));
                if (ret)
                        return ret;
        }

        read_lock(&list_lock);

        /*
         * For datagrams, we know the interrrupt handler will never use
         * the ring, leave irqs on
         */
        spin_lock(&p->r->lock);
        if (p->r->ring->rx_ptr == p->r->ring->tx_ptr) {
                spin_unlock(&p->r->lock);
                if (nonblock) {
                        ret = -EAGAIN;
                        goto unlock;
                }
                read_unlock(&list_lock);
                goto retry;
        }
        ret = v4v_copy_out(p->r->ring, src, &protocol, buf, len, !peek);
				/*jo : trace*/
        if (ret < 0) {
                recover_ring(p->r);
                spin_unlock(&p->r->lock);
                read_unlock(&list_lock);
                goto retry;
        }
        spin_unlock(&p->r->lock);

        if (!peek) {
		dprintk_info("Is going to v4v_null_notify\n");
                v4v_null_notify();
	}

        if (protocol != V4V_PROTO_DGRAM) {
                /* If peeking consume the rubbish */
                if (peek) {
			dprintk_info("consume the rubbish\n");
                        v4v_copy_out(p->r->ring, NULL, NULL, NULL, 1, 1);
		}
                read_unlock(&list_lock);
                goto retry;
        }

        if ((p->state == V4V_STATE_CONNECTED) &&
            memcmp(src, &p->peer, sizeof(v4v_addr_t))) {
                /* Wrong source - bin it */
                if (peek) {
			dprintk_info("wrong source - bin it\n");
                        v4v_copy_out(p->r->ring, NULL, NULL, NULL, 1, 1);
		}
                read_unlock(&list_lock);
                goto retry;
        }

unlock:
        read_unlock(&list_lock);

	dprintk_out();

        return ret;
}

static ssize_t
v4v_recv_stream(struct v4v_private *p, void *_buf, int len, int recv_flags,
                int nonblock)
{
        size_t count = 0;
        int ret = 0;
        unsigned long flags;
        int schedule_irq = 0;
        uint8_t *buf = (void *)_buf;

	dprintk_in();

        read_lock(&list_lock);

        switch (p->state) {
        case V4V_STATE_DISCONNECTED:
		dprintk_info("DISCONNECTED\n");
                ret = -EPIPE;
                goto unlock;
        case V4V_STATE_CONNECTING:
		dprintk_info("CONNECTING\n");
                ret = -ENOTCONN;
                goto unlock;
        case V4V_STATE_CONNECTED:
		dprintk_info("CONNECTED\n");
        case V4V_STATE_ACCEPTED:
		dprintk_info("ACCEPTED\n");
                break;
        default:
                ret = -EINVAL;
                goto unlock;
        }

        do {
                if (!nonblock) {
			struct timeval tv;
			dprintk_info("!nonblock\n");
			do_gettimeofday(&tv);
			start = tv.tv_sec * 1000000 + tv.tv_usec;
        		read_unlock(&list_lock);
                        ret = wait_event_interruptible(p->readq,
                                                       (!list_empty(&p->pending_recv_list)
                                                        || !stream_connected(p)));

        		read_lock(&list_lock);
			do_gettimeofday(&tv);
			stop = tv.tv_sec * 1000000 + tv.tv_usec;
			total += stop - start;
                        if (ret) {
				dprintk_err("break in !nonblock, ret:%d\n", ret);
                                break;
			}
                }

                spin_lock_irqsave(&p->pending_recv_lock, flags);

                while (!list_empty(&p->pending_recv_list) && len) {
                        size_t to_copy;
                        struct pending_recv *pending;
                        int unlink = 0;

                        pending = list_first_entry(&p->pending_recv_list,
                                                   struct pending_recv, node);

                        if ((pending->data_len - pending->data_ptr) > len) {
				//printk(KERN_INFO "len: %#lx, data: %#lx, data_ptr:%p\n", (len), (pending->data_len), (pending->data_ptr));
                                to_copy = len;
                        } else {
                                unlink = 1;
                                to_copy = pending->data_len - pending->data_ptr;
				//printk(KERN_INFO "unlinked ;-) len: %#lx, data: %#lx, data_ptr:%p\n", (len), (pending->data_len), (pending->data_ptr));
                        }

#if 1
                        if (!access_ok(VERIFY_WRITE, buf, to_copy)) {
                                printk(KERN_ERR
                                       "V4V - ERROR: buf invalid _buf=%p buf=%p len=%d to_copy=%zu count=%zu\n",
                                       _buf, buf, len, to_copy, count);
                                spin_unlock_irqrestore(&p->pending_recv_lock, flags);
                                read_unlock(&list_lock);
                                ret = -EFAULT;
                                goto unlock;
                        }
#endif

                        dprintk("buf:%#lx, data:%#lx, data_ptr:%#lx, to_copy:%#lx\n",
			         (unsigned long) buf, (unsigned long) pending->data,
			         (unsigned long) pending->data_ptr, (unsigned long) to_copy);
                	//spin_unlock_irqrestore(&p->pending_recv_lock, flags);
			dprintk_info("before copy to user\n");
                        if ((ret = copy_to_user(buf, pending->data + pending->data_ptr, to_copy)))
                        {
				int ret2 = 0;
				dprintk(" in error copy_to_user, %d\n", ret);
				ret2 = copy_to_user(buf + to_copy - ret, pending->data + pending->data_ptr + to_copy - ret, ret);
				if (ret2) {
					printk(KERN_INFO "%s: fatal... %d\n", __func__, ret2);
				
					spin_unlock_irqrestore(&p->pending_recv_lock, flags);
					ret = -EFAULT;
					goto unlock;
				}
				dprintk(" continuing ;-) %d\n", ret2);
                        }
			dprintk_info("after copy_to_user\n");
                	//spin_lock_irqsave(&p->pending_recv_lock, flags);

                        if (unlink) {
                                list_del(&pending->node);
                                kfree(pending);
                                v4v_atomic_dec(&p->pending_recv_count);
                                if (p->full) {
<<<<<<< Updated upstream
                                        //printk(KERN_INFO "freeing up some stuff, pending recv count %d, p->full:%d\n", p->pending_recv_count, p->full);
=======
                                        dprintk(KERN_INFO "freeing up some stuff, pending recv count %d, p->full:%d\n", p->full);
>>>>>>> Stashed changes
                                        schedule_irq = 1;
				}
                        } else
                                pending->data_ptr += to_copy;

                        buf += to_copy;
                        count += to_copy;
                        len -= to_copy;
                }

                spin_unlock_irqrestore(&p->pending_recv_lock, flags);
		dprintk_info("after spinlock\n");

                if (p->state == V4V_STATE_DISCONNECTED) {
                        ret = -EPIPE;
                        break;
                }

                if (nonblock)
                        ret = -EAGAIN;

        } while ((recv_flags & MSG_WAITALL) && len);
	//printk(KERN_INFO "TIME spent waiting: %lu %lu %lu\n", start, stop, stop - start);

unlock:
        read_unlock(&list_lock);

        if (schedule_irq)
                v4v_fake_irq();

	dprintk_out();
        return count ? count : ret;
}

static ssize_t
v4v_send_stream(struct v4v_private *p, const void *_buf, int len, int nonblock)
{
        unsigned long write_lump;
        const uint8_t *buf = _buf;
        size_t count = 0;
        ssize_t ret;
        int to_send;

	dprintk_in();

        //write_lump = (len >= p->r->ring->len + sizeof(struct v4v_ring_message_header) + sizeof(struct v4v_stream_header) ? p->r->ring->len >> 1 : (DEFAULT_RING_SIZE) >> 2); //DEFAULT_RING_SIZE >> 2;
        write_lump = (p->r->ring->len ? p->r->ring->len >> 4 : (DEFAULT_RING_SIZE) >> 2); //DEFAULT_RING_SIZE >> 2;
        //printk(KERN_INFO "write_lump: %#lx\n", write_lump);

        switch (p->state) {
        case V4V_STATE_DISCONNECTED:
                return -EPIPE;
        case V4V_STATE_CONNECTING:
                return -ENOTCONN;
        case V4V_STATE_CONNECTED:
        case V4V_STATE_ACCEPTED:
                break;
        default:
                return -EINVAL;
        }

        while (len) {
                struct v4v_stream_header sh;
                v4v_iov_t iovs[2];

                to_send = len > write_lump ? write_lump : len;
        	dprintk("to_send: %#lx, write_lump:%#lx\n", (unsigned long) to_send, write_lump);
                sh.flags = 0;
                sh.conid = p->conid;

                iovs[0].iov_base = (uintptr_t)&sh;
                iovs[0].iov_len = sizeof (sh);

                iovs[1].iov_base = (uintptr_t)buf;
                iovs[1].iov_len = to_send;

                if (p->state == V4V_STATE_CONNECTED)
                    ret = v4v_stream_sendvto_from_sponsor(
                                p, iovs, 2,
                                to_send + sizeof(struct v4v_stream_header),
                                nonblock, &p->peer, V4V_PROTO_STREAM);
                else
                    ret = v4v_stream_sendvto_from_private(
                                p, iovs, 2,
                                to_send + sizeof(struct v4v_stream_header),
                                nonblock, &p->peer, V4V_PROTO_STREAM);

                if (ret < 0) {
                        return count ? count : ret;
                }

                len -= to_send;
                buf += to_send;
                count += to_send;

                if (nonblock)
                        return count;
        }
	
	dprintk_out();
        return count;
}


static int v4v_bind(struct v4v_private *p, struct v4v_ring_id *ring_id)
{
        int ret = 0;

	/*jo : trace*/
	dprintk_in();
	dprintk("domain = %d malakia = %d\n", ring_id->addr.domain, V4V_DOMID_NONE);

        if (ring_id->addr.domain != V4V_DOMID_NONE) {
		dprintk_err("domain_id:%#lx\n", ring_id->addr.domain);
                ret = -EINVAL;
		goto out;
        }
	/*jo : trace*/
	printk(KERN_INFO "ring_id->addr.domain = %d, port:%d\n",ring_id->addr.domain, ring_id->addr.port);

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                ret = new_ring(p, ring_id);
                if (!ret)
                        p->r->type = V4V_RTYPE_DGRAM;
                break;
        case V4V_PTYPE_STREAM:
                ret = new_ring(p, ring_id);
                break;
	default:
		dprintk_err("default, type:%#lx\n", p->ptype);
        }
	/*jo : trace*/
	dprintk("after registration domain = %d, ret:%d\n",ring_id->addr.domain, ret);
out:
	dprintk_out();
        return ret;
}

static int v4v_listen(struct v4v_private *p)
{
	int ret = 0;
	dprintk_in();
        if (p->ptype != V4V_PTYPE_STREAM) {
                ret = -EINVAL;
                goto out;
	}

        if (p->state != V4V_STATE_BOUND) {
                ret = -EINVAL;
                goto out;
        }

        p->r->type = V4V_RTYPE_LISTENER;
        p->state = V4V_STATE_LISTENING;

out:
        dprintk_out();
        return ret;
}

static int v4v_connect(struct v4v_private *p, v4v_addr_t * peer, int nonblock)
{
        struct v4v_stream_header sh;
        int ret = -EINVAL;

        dprintk_in();
        if (p->ptype == V4V_PTYPE_DGRAM) {
                switch (p->state) {
                case V4V_STATE_BOUND:
                case V4V_STATE_CONNECTED:
                        if (peer) {
                                p->state = V4V_STATE_CONNECTED;
                                memcpy(&p->peer, peer, sizeof(v4v_addr_t));
                        } else {
                                p->state = V4V_STATE_BOUND;
                        }
                        ret = 0;
                        goto out;
                default:
			dprintk_info("default\n");
                        ret = -EINVAL;
                        goto out;
                }
        }
        if (p->ptype != V4V_PTYPE_STREAM) {
		dprintk_info("!stream\n");
                ret = -EINVAL;
                goto out;
        }

        /* Irritiatingly we need to be restartable */
        switch (p->state) {
        case V4V_STATE_BOUND:
		/*jo : trace*/
		dprintk("%s: state_bound", __func__);
                p->r->type = V4V_RTYPE_CONNECTOR;
                p->state = V4V_STATE_CONNECTING;
                p->conid = prandom_u32();
                p->peer = *peer;

                sh.flags = V4V_SHF_SYN;
                sh.conid = p->conid;

                ret =
                    xmit_queue_inline(&p->r->ring->id, &p->peer, &sh,
                                      sizeof(sh), V4V_PROTO_STREAM);
                if (ret == sizeof(sh))
                        ret = 0;
		dprintk("ret = %d\n",ret);

                if (ret ) {
			if (ret == -EAGAIN)
				goto out;
                        p->state = V4V_STATE_BOUND;
                        p->r->type = V4V_RTYPE_DGRAM;
                        ret = ret;
                        goto out;
                }

                break;
        case V4V_STATE_CONNECTED:
		/*jo : trace*/
		dprintk_info("mpainei sto connected\n");

                if (memcmp(peer, &p->peer, sizeof(v4v_addr_t))) {
			dprintk_info("!memcmp\n");
                        ret = -EINVAL;
                        goto out;
                } else {
                        ret = 0;
                        goto out;
                }
        case V4V_STATE_CONNECTING:
                /*jo : trace*/
		dprintk_info("mpainei sto connecting\n");
                if (memcmp(peer, &p->peer, sizeof(v4v_addr_t))) {
                        ret = -EINVAL;
                        goto out;
                }
                break;
        default:
		/*jo : trace*/
		dprintk_info("mpainei sto default\n");
                ret = -EINVAL;
                goto out;
        }

        if (nonblock) {
                return -EINPROGRESS;
        }

        while (p->state != V4V_STATE_CONNECTED) {
		dprintk_info("mpainei sthn connect sto while\n");
                ret =
                    wait_event_interruptible(p->writeq,
                                             (p->state !=
                                              V4V_STATE_CONNECTING));
		dprintk("meta to while state = %d, ret = %d", p->state,ret);
                if (ret)
                        goto out;

                if (p->state == V4V_STATE_DISCONNECTED) {
                        p->state = V4V_STATE_BOUND;
                        p->r->type = V4V_RTYPE_DGRAM;
                        ret = -ECONNREFUSED;
			/*jo : trace */
			dprintk_info("mpanei edw mesa\n");
                        break;
                }
        }

out:
        dprintk_out();
        return ret;
}

static int allocate_fd_with_private(void *private)
{
        int fd;
        struct file *f;
        struct qstr name = {.name = "" };
        struct path path;
        struct inode *ind;

        dprintk_in();
        fd = get_unused_fd();
        if (fd < 0)
                return fd;

        path.dentry = d_alloc_pseudo(v4v_mnt->mnt_sb, &name);
        if (unlikely(!path.dentry)) {
                put_unused_fd(fd);
                return -ENOMEM;
        }
        ind = new_inode(v4v_mnt->mnt_sb);
        ind->i_ino = get_next_ino();
        ind->i_fop = v4v_mnt->mnt_root->d_inode->i_fop;
        ind->i_state = v4v_mnt->mnt_root->d_inode->i_state;
        ind->i_mode = v4v_mnt->mnt_root->d_inode->i_mode;
        ind->i_uid = current_fsuid();
        ind->i_gid = current_fsgid();
        d_instantiate(path.dentry, ind);

        path.mnt = mntget(v4v_mnt);

        f = alloc_file(&path, FMODE_READ | FMODE_WRITE, &v4v_fops_stream);
        if (!f) {
                /* Put back fd ? */
                return -ENFILE;
        }

        f->private_data = private;
        fd_install(fd, f);

        dprintk_out();
        return fd;
}

static int
v4v_accept(struct v4v_private *p, struct v4v_addr *peer, int nonblock, struct v4v_private **new)
{
        int fd = -1;
        int ret = 0;
        struct v4v_private *a = NULL;
        struct pending_recv *r = NULL;
        unsigned long flags;
        struct v4v_stream_header sh;


        dprintk_in();
        if (p->ptype != V4V_PTYPE_STREAM) {
                dprintk("private data ptype invalid:%#lx\n", p->ptype);
                ret = -ENOTTY;
                goto out;
	}

        if (p->state != V4V_STATE_LISTENING) {
		dprintk("private data state invalid:%#lx\n", p->state);
                ret = -EINVAL;
                goto out;
        }


        /* FIXME: leak! */
        for (;;) {
		/*jo : trace*/
		printk("%s: entering infinite loop\n", __func__);
                ret =
                    wait_event_interruptible(p->readq,
                                             (!list_empty
                                              (&p->pending_recv_list))
                                             || nonblock);
                if (ret) {
			dprintk("%s: got ret: %d from wait_event\n", __func__, ret);
			goto out;
		}

                /* Write lock implicitly has pending_recv_lock */
                write_lock_irqsave(&list_lock, flags);

                if (!list_empty(&p->pending_recv_list)) {
			dprintk("%s: looping around pending_recv_list\n", __func__);
                        r = list_first_entry(&p->pending_recv_list,
                                             struct pending_recv, node);

                        list_del(&r->node);
                        v4v_atomic_dec(&p->pending_recv_count);

                        if ((!r->data_len) && (r->sh.flags & V4V_SHF_SYN)) {
				dprintk("%s: len zero of SYN FLAGS set\n", __func__);
                                break;
			}
			dprintk("%s: Is going to kfree(r)\n", __func__);
                        kfree(r);
                }

                write_unlock_irqrestore(&list_lock, flags);
                if (nonblock) {
			dprintk("%s: non-block set\n", __func__);
                        ret = -EAGAIN;
                        goto out;
		}
        }
	dprintk("%s: WILL unlock here\n", __func__);

        write_unlock_irqrestore(&list_lock, flags);

        a = kmalloc(sizeof(struct v4v_private), GFP_KERNEL);
        if (!a) {
                ret = -ENOMEM;
                goto release;
        }

        memset(a, 0, sizeof(struct v4v_private));
        a->state = V4V_STATE_ACCEPTED;
        a->ptype = V4V_PTYPE_STREAM;
        a->r = p->r;
        if (!get_ring(a->r)) {
                a->r = NULL;
                ret = -EINVAL;
                goto release;
        }

	dprintk("%s: init waitqueues/lists\n", __func__);
        init_waitqueue_head(&a->readq);
        init_waitqueue_head(&a->writeq);
        spin_lock_init(&a->pending_recv_lock);
        INIT_LIST_HEAD(&a->pending_recv_list);
        atomic_set(&a->pending_recv_count, 0);

        a->send_blocked = 0;
        a->peer = r->from;
        a->conid = r->sh.conid;

#if 1
        if (peer) {
		dprintk("%s: into peers\n", __func__);
                *peer = r->from;
		dprintk("peer->port = %lu, peer->domain = %d\n", r->from.port, r->from.domain);
	}
#endif

#if 0
        fd = allocate_fd_with_private(a);
        if (fd < 0) {
                ret = fd;
                goto release;
        }
#endif

        write_lock_irqsave(&list_lock, flags);
        list_add(&a->node, &a->r->privates);
        write_unlock_irqrestore(&list_lock, flags);

	dprintk("%s: shipping the ack\n", __func__);
        /* Ship the ACK */
        sh.conid = a->conid;
        sh.flags = V4V_SHF_ACK;

	dprintk("%s: conid = %#x, flag = %#x\n", __func__, sh.conid, sh.flags);

        xmit_queue_inline(&a->r->ring->id, &a->peer, &sh,
                          sizeof(sh), V4V_PROTO_STREAM);
	dprintk("%s: freeing pending recvs\n", __func__);
        kfree(r);
	if (new)
		*new = a;
	else
		dprintk_err("new is NULL!!!: ret:%d\n", ret);

out:
        dprintk_out();
        return ret;

 release:
        kfree(r);
        if (a) {
                write_lock_irqsave(&list_lock, flags);
                if (a->r)
                        put_ring(a->r);
                write_unlock_irqrestore(&list_lock, flags);
                kfree(a);
        }
        dprintk_out();
        return ret;
}

ssize_t
v4v_sendto(struct v4v_private * p, const void *buf, size_t len, int flags,
           v4v_addr_t * addr, int nonblock)
{
        ssize_t rc;
	int ret = 0; 

        dprintk_in();
        if (!access_ok(VERIFY_READ, buf, len)) {
		dprintk_err("Access not OK %p\n", buf);
                ret = -EFAULT;
		goto out;
	}
        if (!access_ok(VERIFY_READ, addr, len)) {
		dprintk_err("Access not OK %p\n", buf);
                ret = -EFAULT;
		goto out;
	}

        if (flags & MSG_DONTWAIT)
                nonblock++;

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                dprintk_info("dgram\n");
                switch (p->state) {
                case V4V_STATE_BOUND:
                	dprintk_info("bound\n");
                        if (!addr) {
                		dprintk_info("not addr\n");
                                ret = -ENOTCONN;
                                goto out;
                        }
                        rc = v4v_sendto_from_sponsor(p, buf, len, nonblock,
                                                     addr, V4V_PROTO_DGRAM);
                        break;

                case V4V_STATE_CONNECTED:
                	dprintk_info("connected\n");
                        if (addr) {
                		dprintk_info("addr\n");
                                ret = -EISCONN;
                                goto out;
			}

                        rc = v4v_sendto_from_sponsor(p, buf, len, nonblock,
                                                     &p->peer, V4V_PROTO_DGRAM);
                        break;

                default:
                	dprintk_info("default\n");
                        ret = -EINVAL;
                        goto out;
                }
                break;
        case V4V_PTYPE_STREAM:
                dprintk_info("stream\n");
                if (addr) {
                	dprintk_info("addr\n");
                        ret = -EISCONN;
                        goto out;
                }
                switch (p->state) {
                case V4V_STATE_CONNECTING:
                	dprintk_info("connecting\n");
                case V4V_STATE_BOUND: {
                	dprintk_info("bound\n");
                        ret = -ENOTCONN;
                        goto out;
		}
                case V4V_STATE_CONNECTED:
                	dprintk_info("connected\n");
                case V4V_STATE_ACCEPTED:
                	dprintk_info("accepted\n");
                        rc = v4v_send_stream(p, buf, len, nonblock);
                        break;
                case V4V_STATE_DISCONNECTED:

                	dprintk_info("disconnected\n");
                        rc = -EPIPE;
                        break;
                default:
                	dprintk_info("default\n");

                        ret = -EINVAL;
                        goto out;
                }
                break;
        default:
                dprintk_info("default\n");

                return -ENOTTY;
        }

        if ((rc == -EPIPE) && !(flags & MSG_NOSIGNAL)) {
                dprintk_info("EPIPE\n");
                send_sig(SIGPIPE, current, 0);
	}

	ret = rc;
out:
        dprintk_out();
        return ret;
}

ssize_t
v4v_recvfrom(struct v4v_private * p, void *buf, size_t len, int flags,
             v4v_addr_t * addr, int nonblock)
{
        int peek = 0;
        ssize_t rc = 0;
        int ret = 0;

        dprintk_in();

        dprintk("buf: %#lx, len: %#lx, flags: %#lx, addr: %#lx, nonblock: %#lx",
	         (unsigned long) buf, (unsigned long) len, (unsigned long) flags, 
                 (unsigned long) addr, (unsigned long) nonblock);

        if (!access_ok(VERIFY_WRITE, buf, len)) {
		dprintk_err("Access not OK %p\n", buf);
                ret = -EFAULT;
                goto out;
	}
        if ((addr) && (!access_ok(VERIFY_WRITE, addr, sizeof(v4v_addr_t)))) {
		dprintk_err("addr && Access not OK :%p\n", buf);
                ret = -EFAULT;
                goto out;
	}

        if (flags & MSG_DONTWAIT)
                nonblock++;
        if (flags & MSG_PEEK)
                peek++;

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
		dprintk_info("dgram\n");
                rc = v4v_recvfrom_dgram(p, buf, len, nonblock, peek, addr);
                break;
        case V4V_PTYPE_STREAM:
		dprintk_info("STREAM\n");
                if (peek) {
			dprintk_info("peek\n");
                        ret = -EINVAL;
                        goto out;
		}

                switch (p->state) {
                case V4V_STATE_BOUND: {
			dprintk_info("BOUND state\n");
                        ret = -ENOTCONN;
			goto out;
                        }
                case V4V_STATE_CONNECTED:
			dprintk_info("CONNECTED state\n");
                case V4V_STATE_ACCEPTED:
			dprintk_info("ACCEPTED state\n");
                        if (addr)
                                *addr = p->peer;
                        rc = v4v_recv_stream(p, buf, len, flags, nonblock);
                        break;
                case V4V_STATE_DISCONNECTED:
			dprintk_info("DISCONNECTED state\n");
                        rc = 0;
                        break;
                default:
			dprintk_info("DEFAULT state\n");
                        rc = -EINVAL;
                }
        }

        if ((rc > (ssize_t) len) && !(flags & MSG_TRUNC)) {
		printk("if clause, rc = len\n");
                rc = len;
	}

	ret = rc;
out:
        dprintk_out();
        return ret;
}

/* fops */

static int v4v_open_dgram(struct inode *inode, struct file *f)
{
        struct v4v_private *p;
	/*jo : mpainei sthn open*/
        dprintk_in();

        p = kmalloc(sizeof(struct v4v_private), GFP_KERNEL);
        if (!p)
                return -ENOMEM;

        memset(p, 0, sizeof(struct v4v_private));
        p->state = V4V_STATE_IDLE;
        p->desired_ring_size = DEFAULT_RING_SIZE;
        p->r = NULL;
        p->ptype = V4V_PTYPE_DGRAM;
        p->send_blocked = 0;

        init_waitqueue_head(&p->readq);
        init_waitqueue_head(&p->writeq);

        spin_lock_init(&p->pending_recv_lock);
        INIT_LIST_HEAD(&p->pending_recv_list);
        atomic_set(&p->pending_recv_count, 0);

        f->private_data = p;
        dprintk_out();
        return 0;
}

static int v4v_open_stream(struct inode *inode, struct file *f)
{
        struct v4v_private *p;

        dprintk_in();
        p = kmalloc(sizeof(struct v4v_private), GFP_KERNEL);
        if (!p)
                return -ENOMEM;
	total = 0;

        memset(p, 0, sizeof(struct v4v_private));
        p->state = V4V_STATE_IDLE;
        p->desired_ring_size = DEFAULT_RING_SIZE;
        p->r = NULL;
        p->ptype = V4V_PTYPE_STREAM;
        p->send_blocked = 0;

        init_waitqueue_head(&p->readq);
        init_waitqueue_head(&p->writeq);

        spin_lock_init(&p->pending_recv_lock);
        INIT_LIST_HEAD(&p->pending_recv_list);
        atomic_set(&p->pending_recv_count, 0);

        f->private_data = p;
        dprintk_out();
        return 0;
}

static int v4v_release(struct inode *inode, struct file *f)
{
        struct v4v_private *p = (struct v4v_private *)f->private_data;
        unsigned long flags;
        struct pending_recv *pending;
        dprintk_in();
	/*jo : trace*/
	printk(KERN_INFO "TIME spent waiting: %lu\n", total);
        if (p->ptype == V4V_PTYPE_STREAM) {
                switch (p->state) {
                case V4V_STATE_CONNECTED:
                case V4V_STATE_CONNECTING:
                case V4V_STATE_ACCEPTED:
                        xmit_queue_rst_to(&p->r->ring->id, p->conid, &p->peer);
                        break;
                default:
                        break;
                }
        }

        write_lock_irqsave(&list_lock, flags);
        if (!p->r) {
                write_unlock_irqrestore(&list_lock, flags);
                goto release;
        }

        if (p != p->r->sponsor) {
                put_ring(p->r);
                list_del(&p->node);
                write_unlock_irqrestore(&list_lock, flags);
                goto release;
        }

        p->r->sponsor = NULL;
        put_ring(p->r);
        write_unlock_irqrestore(&list_lock, flags);

        while (!list_empty(&p->pending_recv_list)) {
                pending =
                    list_first_entry(&p->pending_recv_list,
                                     struct pending_recv, node);

                list_del(&pending->node);
                kfree(pending);
                v4v_atomic_dec(&p->pending_recv_count);
        }

 release:
        kfree(p);

        dprintk_out();
        return 0;
}

static ssize_t
v4v_write(struct file *f, const char __user * buf, size_t count, loff_t * ppos)
{
        struct v4v_private *p = f->private_data;
        int nonblock = f->f_flags & O_NONBLOCK;

        return v4v_sendto(p, buf, count, 0, NULL, nonblock);
}

static ssize_t
v4v_read(struct file *f, char __user * buf, size_t count, loff_t * ppos)
{
        struct v4v_private *p = f->private_data;
        int nonblock = f->f_flags & O_NONBLOCK;

        return v4v_recvfrom(p, (void *)buf, count, 0, NULL, nonblock);
}

static long v4v_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
        int rc = -ENOTTY;

        int nonblock = f->f_flags & O_NONBLOCK;
        struct v4v_private *p = f->private_data;

        dprintk_in();

        if (_IOC_TYPE(cmd) != V4V_TYPE) {
                goto out;
        }

        switch (cmd) {
        case V4VIOCSETRINGSIZE:
                if (!access_ok(VERIFY_READ, arg, sizeof(uint32_t))) {
			dprintk_err("Access not ok %#lx\n", arg);
			rc = -EFAULT;
			goto out;
		}
                rc = v4v_set_ring_size(p, *(uint32_t *) arg);
		dprintk("%s: args=%#x\n", v4v_ioctl2text(cmd), *(uint32_t *) arg);
                break;
        case V4VIOCBIND: {
		struct v4v_ring_id * ring_id = (struct v4v_ring_id *)arg;
		struct v4v_addr * addr = &ring_id->addr;
		uint32_t port = addr->port;
		uint32_t domain = addr->domain;
		uint32_t partner = ring_id->partner;

                if (!access_ok(VERIFY_READ, arg, sizeof(struct v4v_ring_id))) {
			dprintk_err("Access not ok %#lx\n", arg);
			rc = -EFAULT;
			goto out;
		}
		dprintk("%s: addr=(port:%#x, domain:%#x), partner=%#x\n", v4v_ioctl2text(cmd), port, domain, partner);
                rc = v4v_bind(p, (struct v4v_ring_id *)arg);
                break;
	}
        case V4VIOCGETSOCKNAME: {
		struct v4v_ring_id * ring_id = (struct v4v_ring_id *)arg;
		struct v4v_addr * addr = &ring_id->addr;
		uint32_t port = addr->port;
		uint32_t domain = addr->domain;
		uint32_t partner = ring_id->partner;
                if (!access_ok(VERIFY_WRITE, arg, sizeof(struct v4v_ring_id))) {
			dprintk_err("Access not ok %#lx", arg);
			rc = -EFAULT;
			goto out;
		}
                rc = v4v_get_sock_name(p, (struct v4v_ring_id *)arg);
		dprintk("%s: addr=(port:%#x, domain:%#x), partner=%#x\n", v4v_ioctl2text(cmd), port, domain, partner);
                break;
	}
        case V4VIOCGETPEERNAME: {
		struct v4v_ring_id * ring_id = (struct v4v_ring_id *)arg;
		struct v4v_addr * addr = &ring_id->addr;
		uint32_t port = addr->port;
		uint32_t domain = addr->domain;
		uint32_t partner = ring_id->partner;
                if (!access_ok(VERIFY_WRITE, arg, sizeof(v4v_addr_t))) {
			dprintk_err("Access not ok %#lx", arg);
			rc = -EFAULT;
			goto out;
		}
                /* Bind if not done */
                rc = v4v_get_peer_name(p, (v4v_addr_t *) arg);
                if (p->state == V4V_STATE_IDLE) {
                        struct v4v_ring_id id;
                        dprintk("%s: IOCCONNECT, STATE_IDLE\n", __func__);
                        memset(&id, 0, sizeof(id));
                        id.partner = V4V_DOMID_NONE;
                        id.addr.domain = V4V_DOMID_NONE;
                        id.addr.port = 0;
                        rc = v4v_bind(p, &id);
                        if (rc) {
				dprintk_info("paparia\n");
                                break;
                                }
                }
		dprintk("%s: addr=(port:%#x, domain:%#x), partner=%#x\n", v4v_ioctl2text(cmd), port, domain, partner);
                break;
	}
        case V4VIOCCONNECT: {
		struct v4v_addr * addr = (v4v_addr_t*)arg;
		uint32_t port = addr->port;
		uint32_t domain = addr->domain;
                if (!access_ok(VERIFY_READ, arg, sizeof(v4v_addr_t))) {
			dprintk_err("Access not ok %#lx", arg);
			rc = -EFAULT;
			goto out;
		}
                /* Bind if not done */
                if (p->state == V4V_STATE_IDLE) {
                        struct v4v_ring_id id;
                        dprintk("%s: IOCCONNECT, STATE_IDLE\n", __func__);
                        memset(&id, 0, sizeof(id));
                        id.partner = V4V_DOMID_NONE;
                        id.addr.domain = V4V_DOMID_NONE;
                        id.addr.port = 0;
                        rc = v4v_bind(p, &id);
                        if (rc) {
				dprintk_info("paparia\n");
                                break;
                                }
                }
		/*jo : trace*/
		dprintk("%s: addr=(port:%#x, domain:%#x)\n", v4v_ioctl2text(cmd), port, domain);
                rc = v4v_connect(p, (v4v_addr_t *) arg, nonblock);
                break;
	}
        case V4VIOCGETCONNECTERR:
                {
                        unsigned long flags;
                        if (!access_ok(VERIFY_WRITE, arg, sizeof(int))) {
				dprintk_err("Access not ok %#lx", arg);
				rc = -EFAULT;
				goto out;
			}

                        spin_lock_irqsave(&p->pending_recv_lock, flags);
                        *(int *)arg = p->pending_error;
                        p->pending_error = 0;
                        spin_unlock_irqrestore(&p->pending_recv_lock, flags);
                        rc = 0;
			dprintk("%s: pending_error:%d)\n", v4v_ioctl2text(cmd), *(int *)arg);
                }
                break;
        case V4VIOCLISTEN: {
                rc = v4v_listen(p);
		dprintk("%s: rc:%d)\n", v4v_ioctl2text(cmd), rc);
                break;
	}
        case V4VIOCACCEPT: {
		struct v4v_addr * addr = (v4v_addr_t *) arg;
		uint32_t port = addr->port;
		uint32_t domain = addr->domain;
                if (!access_ok(VERIFY_WRITE, arg, sizeof(v4v_addr_t))) {
			dprintk_err("Access not ok %#lx", arg);
                        rc = -EFAULT;
                        goto out;
                }
                rc = v4v_accept(p, (v4v_addr_t *) arg, nonblock, NULL);
		dprintk("%s: addr=(port:%#x, domain:%#x), rc:%d\n", v4v_ioctl2text(cmd), port, domain, rc);
                break;
	}
        case V4VIOCSEND:
                if (!access_ok(VERIFY_READ, arg, sizeof(struct v4v_dev))) {
			dprintk_err("Access not ok %#lx", arg);
                        rc = -EFAULT;
                        goto out;
                }
                {
                        struct v4v_dev a = *(struct v4v_dev *)arg;
			struct v4v_addr * addr = (v4v_addr_t * ) &a.addr;
			uint32_t port = addr->port;
			uint32_t domain = addr->domain;

                        rc = v4v_sendto(p, a.buf, a.len, a.flags, a.addr,
                                        nonblock);

			dprintk("%s: addr=(port:%#x, domain:%#x), buf:%p, len:%#lx, rc:%d\n", v4v_ioctl2text(cmd), port, domain, a.buf, a.len, rc);
                }
                break;
        case V4VIOCRECV:
                if (!access_ok(VERIFY_READ, arg, sizeof(struct v4v_dev))) {
			dprintk_err("Access not ok %#lx", arg);
                        rc = -EFAULT;
                        goto out;
                }
                {
                        struct v4v_dev a = *(struct v4v_dev *)arg;
			struct v4v_addr * addr = (v4v_addr_t *) &a.addr;
			uint32_t port = addr->port;
			uint32_t domain = addr->domain;
                        rc = v4v_recvfrom(p, a.buf, a.len, a.flags, a.addr,
                                          nonblock);
			dprintk("%s: addr=(port:%#x, domain:%#x), buf:%p, len:%#lx, rc:%d\n", v4v_ioctl2text(cmd), port, domain, a.buf, a.len, rc);
                }
                break;
        case V4VIOCVIPTABLESADD:
                if (!access_ok
                    (VERIFY_READ, arg, sizeof(struct v4v_viptables_rule_pos))) {
			dprintk_err("Access not ok %#lx", arg);
                        rc = -EFAULT;
                        goto out;
                }
                {
                        struct v4v_viptables_rule_pos *rule =
                            (struct v4v_viptables_rule_pos *)arg;
                        v4v_viptables_add(p, rule->rule, rule->position);
                        rc = 0;
                }
                break;
        case V4VIOCVIPTABLESDEL:
                if (!access_ok
                    (VERIFY_READ, arg, sizeof(struct v4v_viptables_rule_pos))) {
			dprintk_err("Access not ok %#lx", arg);
                        rc = -EFAULT;
                        goto out;
                }
                {
                        struct v4v_viptables_rule_pos *rule =
                            (struct v4v_viptables_rule_pos *)arg;
                        v4v_viptables_del(p, rule->rule, rule->position);
                        rc = 0;
                }
                break;
        case V4VIOCVIPTABLESLIST:
                if (!access_ok
                    (VERIFY_READ, arg, sizeof(struct v4vtables_list))) {
			dprintk_err("Access not ok %#lx", arg);
                        rc = -EFAULT;
                        goto out;
                }
                {
                        struct v4vtables_list *list =
                            (struct v4vtables_list *)arg;
                        rc = v4v_viptables_list(p, list);
                }
                break;
        default:
                printk(KERN_ERR "v4v: unkown ioctl, cmd:0x%x nr:%d size:0x%x\n",
                       cmd, _IOC_NR(cmd), _IOC_SIZE(cmd));
        }

out:
        dprintk("v4v: ioctl, cmd:0x%x nr:%d size:0x%x, ret= %d\n",
                       cmd, _IOC_NR(cmd), _IOC_SIZE(cmd), rc);
        dprintk_out();
        return rc;
}

static unsigned int v4v_poll(struct file *f, poll_table * pt)
{
        unsigned int mask = 0;
        struct v4v_private *p = f->private_data;

        dprintk_in();
        read_lock(&list_lock);

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                switch (p->state) {
                case V4V_STATE_CONNECTED:
			dprintk_info("CONNECTED\n");
                case V4V_STATE_BOUND:
			dprintk_info("BOUND\n");
                        poll_wait(f, &p->readq, pt);
			dprintk_info("AFTER WAIT\n");
                        mask |= POLLOUT | POLLWRNORM;
                        if (p->r->ring->tx_ptr != p->r->ring->rx_ptr)
                                mask |= POLLIN | POLLRDNORM;
                        break;
                default:
			dprintk_info("DEFAULT \n");
                        break;
                }
                break;
        case V4V_PTYPE_STREAM:
                switch (p->state) {
                case V4V_STATE_BOUND:
			dprintk_info("BOUND\n");
                        break;
                case V4V_STATE_LISTENING:
			dprintk_info("LISTENING\n");
                        poll_wait(f, &p->readq, pt);
			dprintk_info("AFTER WAIT\n");
                        if (!list_empty(&p->pending_recv_list))
                                mask |= POLLIN | POLLRDNORM;
                        break;
                case V4V_STATE_ACCEPTED:
			dprintk_info("ACCEPTED\n");
                case V4V_STATE_CONNECTED:
			dprintk_info("CONNECTED\n");
                        poll_wait(f, &p->readq, pt);
			dprintk_info("after read wait\n");
                        poll_wait(f, &p->writeq, pt);
			dprintk_info("after write wait\n");
                        if (!p->send_blocked)
                                mask |= POLLOUT | POLLWRNORM;
                        if (!list_empty(&p->pending_recv_list))
                                mask |= POLLIN | POLLRDNORM;
                        break;
                case V4V_STATE_CONNECTING:
			dprintk_info("CONNECTING\n");
                        poll_wait(f, &p->writeq, pt);
                        break;
                case V4V_STATE_DISCONNECTED:
			dprintk_info("DISC\n");
                        mask |= POLLOUT | POLLWRNORM;
                        mask |= POLLIN | POLLRDNORM;
                        break;
                case V4V_STATE_IDLE:
			dprintk_info("IDLE\n");
                        break;
                }
                break;
        }

        read_unlock(&list_lock);
        dprintk_out();
        return mask;
}

#if 0
static const struct file_operations v4v_fops_stream = {
        .owner = THIS_MODULE,
        .write = v4v_write,
        .read = v4v_read,
        .unlocked_ioctl = v4v_ioctl,
        .open = v4v_open_stream,
        .release = v4v_release,
        .poll = v4v_poll,
};

static const struct file_operations v4v_fops_dgram = {
        .owner = THIS_MODULE,
        .write = v4v_write,
        .read = v4v_read,
        .unlocked_ioctl = v4v_ioctl,
        .open = v4v_open_dgram,
        .release = v4v_release,
        .poll = v4v_poll,
};

#endif
/* Xen VIRQ */
static int v4v_irq = -1;

static void unbind_virq(void)
{
	if (v4v_irq < 0) {
		printk (KERN_ERR "error in v4v_irq = %d\n", v4v_irq);
	}
	else
        	unbind_from_irqhandler (v4v_irq, NULL);
        v4v_irq = -1;
}

static int bind_evtchn(void)
{
        v4v_info_t info;
        int result;
        int ret = 0;

        dprintk_in();
        v4v_info(&info);
        if (info.ring_magic != V4V_RING_MAGIC) {
		printk(KERN_ERR "ring magic diff!, info.ring_magic = %#lx, %#lx\n", (unsigned long) info.ring_magic, (unsigned long) V4V_RING_MAGIC);
                ret = 1;
		goto out;
	}
	/*jo : DOMID_SELF ok*/
        result =
                bind_interdomain_evtchn_to_irqhandler(
                        DOMID_SELF, info.evtchn,
                        v4v_interrupt, 0, "v4v", NULL);

        if (result < 0) {
		printk (KERN_INFO "result = %d\n", result);
                unbind_virq();
                ret = result;
                goto out;
        }

        v4v_irq = result;

out:
        dprintk_out();
        return ret;
}


static int get_ring_id(struct v4v_sock *xs, struct sockaddr *addr, struct v4v_ring_id *ring_id)
{
	int ret = 0;
	struct sockaddr_in *sa_v4v = addr;
	struct sockaddr_v4v vm_addr;
	dprintk_in();
	
	if (!xs) {
		ret = -EINVAL;
		dprintk_err("xs is NULL: %d\n", ret);
		goto out;
	}
	dprintk("addr.port:%#lx, addr.domain:%#lx\n", sa_v4v->sin_port, sa_v4v->sin_addr.s_addr);
	if (sa_v4v->sin_port == 0)
		sa_v4v->sin_port = prandom_u32() % 10000 + 20000;
	ring_id->addr.domain = V4V_DOMID_NONE;
	sockaddr_to_v4v(addr, &vm_addr);
	ring_id->partner = vm_addr.domain;
	ring_id->addr.port= vm_addr.port;
out:
	dprintk_out();
	return ret;
}

static struct v4v_private *get_priv_data(struct v4v_sock *xsk)
{
	struct v4v_private *priv_data;
	dprintk_in();
	priv_data = xsk->priv_data;
	if (!priv_data) {
		dprintk_info("null private data\n");
	}
	dprintk_out();
	return priv_data;
}

static int
v4v_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int ret = 0;
        struct sock *sk;
        struct v4v_sock *xsk;
	struct v4v_private *priv_data;
	struct v4v_ring_id ring_id;

	dprintk_in();

	sk = sock->sk;
	xsk = xen_sk(sk);

	//lock_sock(sk);
	ret = get_ring_id(xsk, addr, &ring_id);
	if (ret < 0) {
		ret = -EINVAL;
		dprintk_err("get_ring_id returned: %d\n", ret);
	}
	priv_data = get_priv_data(xsk);

	ret = v4v_bind(priv_data, &ring_id);
	if (ret < 0) {
		dprintk_err("v4v_bind returns: %d\n", ret);
	}
	if (addr) {
		dump_sockaddr(addr);
		sockaddr_to_v4v(addr, &xsk->local_addr);
	}

	//memcpy(&xsk->local_addr, addr, addr_len);
	dump_sockaddr(&xsk->local_addr);
out:
	//release_sock(sk);
	dprintk_out();
	return ret;
}


#if 0
static int get_sockaddr_v4v(struct *v4v_address, struct sockaddr_v4v *addr)
{
	int ret = 0;
	dprintk_in();

	
	addr->sa_family = AF_XEN;
	addr->domain = v4v_address->domain;
	addr->port = v4v_address->port;

	dprintk("family:%#lx, domain:%#lx, port:%#lx\n", addr->sa_family, addr->domain, addr->port);
out:
	dprintk_out();
	return ret;
}
#endif

static int v4v_sock_getname(struct socket *sock,
			    struct sockaddr *addr, int *addr_len, int peer)
{
	int ret;
        struct sock *sk;
        struct v4v_sock *xsk;
	struct sockaddr_v4v *vm_addr;
	struct sockaddr_in in_addr;

	dprintk_in();
        sk = sock->sk;
        xsk = xen_sk(sk);
        ret = 0;

	dprintk("sock:%p\n", sock);
	dprintk("sockaddr:%p\n", addr);
	dump_socket(sock);
	
        //lock_sock(sk);

        if (peer) {
                if (sock->state != SS_CONNECTED) {
                        ret = -ENOTCONN;
                	dprintk_err("sock state is :%d\n", ret);
                        goto out;
                }
                vm_addr = &xsk->remote_addr;
                dprintk("peer yes:%d\n", ret);
		dump_sockaddr(vm_addr);
        } else {
                dprintk("peer no:%d\n", ret);
                vm_addr = &xsk->local_addr;
		dump_sockaddr(vm_addr);
        }

        if (!vm_addr) {
                ret = -EINVAL;
                dprintk_err("v4v_addr is NULL:%d\n", ret);
                goto out;
        }
#if 0
	ret = get_sockaddr_v4v(v4v_address, &vm_addr);
	if (ret < 0) {
                ret = -EINVAL;
                dprintk_err("v4v_addr is NULL:%d\n", ret);
                goto out;
	}
#endif

        /* sys_getsockname() and sys_getpeername() pass us a
         * MAX_SOCK_ADDR-sized buffer and don't set addr_len.  Unfortunately
         * that macro is defined in socket.c instead of .h, so we hardcode its
         * value here.
         */
	v4v_to_sockaddr(&in_addr, vm_addr);
        BUILD_BUG_ON(sizeof(in_addr) > 128);
        memcpy(addr, &in_addr, sizeof(struct sockaddr_in));
        *addr_len = sizeof(struct sockaddr);
	if (addr) {
	    dprintk_info("getname:\n");
	    dump_sockaddr_in(addr);
	}

out:
	//release_sock(sk);
	dprintk("returns:%d\n", ret);
	dprintk_out();
	return ret;
}

static int v4v_sock_shutdown(struct socket *sock, int mode)
{
	int ret = 0;
        struct sock *sk;

	dprintk_in();
        /* User level uses SHUT_RD (0) and SHUT_WR (1), but the kernel uses
         * RCV_SHUTDOWN (1) and SEND_SHUTDOWN (2), so we must increment mode
         * here like the other address families do.  Note also that the
         * increment makes SHUT_RDWR (2) into RCV_SHUTDOWN | SEND_SHUTDOWN (3),
         * which is what we want.
         */
        mode++;

        if ((mode & ~SHUTDOWN_MASK) || !mode) {
                ret = -EINVAL;
                goto out;
	}

        /* If this is a STREAM socket and it is not connected then bail out
         * immediately.  If it is a DGRAM socket then we must first kick the
         * socket so that it wakes up from any sleeping calls, for example
         * recv(), and then afterwards return the error.
         */

        sk = sock->sk;
        if (sock->state == SS_UNCONNECTED) {
                ret = -ENOTCONN;
                if (sk->sk_type == SOCK_STREAM) {
			goto out;
		}
        } else {
                sock->state = SS_DISCONNECTING;
                ret = 0;
        }

        /* Receive and send shutdowns are treated alike. */
        mode = mode & (RCV_SHUTDOWN | SEND_SHUTDOWN);
        if (mode) {
                lock_sock(sk);
                sk->sk_shutdown |= mode;
                sk->sk_state_change(sk);
                release_sock(sk);

                if (sk->sk_type == SOCK_STREAM) {
                        sock_reset_flag(sk, SOCK_DONE);
                        //vsock_send_shutdown(sk, mode);
                }
        }

out:
	dprintk_out();
	return ret;
}

static unsigned int v4v_sock_poll(struct file *file, struct socket *sock,
				  poll_table * wait)
{
	unsigned int ret = 0;
        struct sock *sk;
        struct v4v_sock *xsk;
	void * old_priv_data;

	dprintk_in();

	sk = sock->sk;
	xsk = xen_sk(sk);

	old_priv_data = file->private_data;
	file->private_data = get_priv_data(xsk);
	ret = v4v_poll(file, wait);
	file->private_data = old_priv_data;
out:
	dprintk_out();
	return ret;
}

static int v4v_sock_stream_recvmsg(struct kiocb *kiocb, struct socket *sock,
				   struct msghdr *msg, size_t len, int flags)
{
	int ret = 0;

        struct sock *sk;
        struct v4v_sock *xsk;
	int nonblock = flags & O_NONBLOCK;

	dprintk_in();

	sk = sock->sk;
	xsk = xen_sk(sk);
	dump_msghdr(msg);
	ret = v4v_recv_stream(xsk->priv_data, msg->msg_iov->iov_base, msg->msg_iov->iov_len, flags, nonblock);
	//v4v_hexdump(msg->msg_iov->iov_base, msg->msg_iov->iov_len);
	if (ret < 0) {
		dprintk_err("recv_stream error, msg: %p, len:%#lx, ret:%d\n", msg, len, ret);
	}
out:
	dprintk_out();
	return ret;
}

static void v4v_sock_connect_timeout(struct work_struct *work)
{
	dprintk_in();

	dprintk_out();
}


static int v4v_sock_stream_connect(struct socket *sock, struct sockaddr *addr,
				   int addr_len, int flags)
{
	int ret = 0;
        struct sock *sk;
        struct v4v_sock *xsk;
	struct sockaddr_v4v vm_addr;
	int nonblock = 0;
	struct v4v_private *priv_data;
	v4v_addr_t v4v_address;

	dprintk_in();
	sk = sock->sk;
	xsk = xen_sk(sk);
	
	lock_sock(sk);
	sockaddr_to_v4v(addr, &vm_addr);
	v4v_address.domain = vm_addr.domain;
	v4v_address.port = vm_addr.port;

	priv_data = get_priv_data(xsk);
#if 1
        /* Bind if not done */
        if (priv_data->state == V4V_STATE_IDLE) {
                ret = v4v_sock_bind(sock, addr, addr_len);
                if (ret ) {
                        dprintk_info("paparia\n");
                        goto out;
                }
        }
#endif


	memcpy(&xsk->remote_addr, &vm_addr, sizeof(struct sockaddr_v4v));
	ret = v4v_connect(priv_data, &v4v_address, nonblock);
	if (ret < 0) {
		dprintk("connect returns:%d\n", ret);
		goto out;
	}
	
out:
	release_sock(sk);
	dprintk_out();
	return ret;
}

#define SS_LISTEN 255
#if 0
void v4v_sock_enqueue_accept(struct sock *listener, struct sock *connected)
{
        struct v4v_sock *vlistener;
        struct v4v_sock *vconnected;

        vlistener = xen_sk(listener);
        vconnected = xen_sk(connected);

        sock_hold(connected);
        sock_hold(listener);
        list_add_tail(&vconnected->accept_queue, &vlistener->accept_queue);
}

static struct sock *v4v_sock_dequeue_accept(struct sock *listener)
{
        struct v4v_sock *vlistener;
        struct v4v_sock *vconnected;

        vlistener = xen_sk(listener);

        if (list_empty(&vlistener->accept_queue))
                return NULL;

        vconnected = list_entry(vlistener->accept_queue.next,
                                struct v4v_sock, accept_queue);

        list_del_init(&vconnected->accept_queue);
        sock_put(listener);
        /* The caller will need a reference on the connected socket so we let
         * it call sock_put().
         */

        return sk_v4v_sock(vconnected);
}
#endif

static int v4v_sock_accept(struct socket *sock, struct socket *newsock,
			   int flags)
{
	int ret = 0;
        struct sock *listener;

        struct sock *sk, *new_sk;
        struct v4v_sock *xsk, *new_xsk;
	v4v_addr_t *vm_addr;
	int nonblock = flags & O_NONBLOCK;
	struct v4v_private *priv_data;
	v4v_addr_t v4v_address;
	struct sockaddr_v4v v4v_addr;

	dprintk_in();
	sk = sock->sk;
	xsk = xen_sk(sk);

        listener = sock->sk;

	dprintk_info("before lock\n");
        lock_sock(listener);
	dprintk_info("after lock\n");
	
        if (sock->type != SOCK_STREAM) {
		dprintk("sock type invalid:%#lx\n", sock->type);
                ret = -EOPNOTSUPP;
                goto out;
        }

        if (listener->sk_state != SS_LISTEN) {
		dprintk("sock state invalid:%#lx\n", listener->sk_state);
                ret = -EINVAL;
                goto out;
        }

	//v4v_address.domain = vm_addr->domain;
	//v4v_address.port = vm_addr->port;


	priv_data = get_priv_data(xsk);

	dump_socket(sock);
	dump_socket(newsock);
#if 1
	//newsock->sk = 
	struct net *net = sock_net(sk);
	new_sk = sk_alloc(net, sk->sk_family, GFP_ATOMIC, sk->sk_prot);
	sock_init_data(newsock, new_sk);
	printk(KERN_INFO "%s: family:%#lx\n", __func__, new_sk->sk_family);
	new_xsk = xen_sk(new_sk);
	v4v_accept(priv_data, &v4v_address, nonblock, &new_xsk->priv_data);
	if (!new_xsk->priv_data) {
		ret = -EINVAL;
		dprintk("accept returns:%d\n", ret);
		goto out;
	}
	v4v_addr.sa_family = AF_XEN;
	v4v_addr.domain = v4v_address.domain;
	v4v_addr.port = v4v_address.port;
	memcpy(&new_xsk->local_addr, &xsk->local_addr, sizeof(struct sockaddr_v4v));
	memcpy(&new_xsk->remote_addr, &v4v_addr, sizeof(struct sockaddr_v4v));
	dprintk_info("before graft\n");
	newsock->state = SS_CONNECTED;
	sock_graft(new_sk, newsock);
	dprintk_info("after graft\n");
	//dump_socket(sock);
	//dump_socket(newsock);
	dump_sockaddr(&xsk->local_addr);
	dump_sockaddr(&new_xsk->local_addr);
	
#endif
out:
	dprintk_info("before release\n");
	release_sock(listener);
	dprintk_info("after release\n");
	dprintk("accept returns:%d\n", ret);
	dprintk_out();
	return ret;
}

static int v4v_sock_listen(struct socket *sock, int backlog)
{
	int ret = 0;
        struct sock *sk;
        struct v4v_sock *xsk;
	struct v4v_private *priv_data;
	dprintk_in();

        sk = sock->sk;

        //lock_sock(sk);

        if (sock->type != SOCK_STREAM) {
		dprintk("sock type invalid:%#lx\n", sock->type);
                ret = -EOPNOTSUPP;
                goto out;
        }

        if (sock->state != SS_UNCONNECTED) {
		dprintk("sock state invalid:%#lx\n", sock->state);
                ret = -EINVAL;
                goto out;
        }

        xsk = xen_sk(sk);
	priv_data = get_priv_data(xsk);

#if 0 /* FIXME */
        if (!vsock_addr_bound(&vsk->local_addr)) {
                err = -EINVAL;
                goto out;
        }
#endif

        //sk->sk_max_ack_backlog = backlog;
        sk->sk_state = SS_LISTEN;
	ret = v4v_listen(priv_data);

        ret = 0;

out:
        //release_sock(sk);
	dprintk_out();
	return ret;
}

static int v4v_sock_stream_setsockopt(struct socket *sock, int level,
				      int optname, char __user * optval,
				      unsigned int optlen)
{
	int ret = 0;
	dprintk_in();
out:
	dprintk_out();
	return ret;
}

static int v4v_sock_stream_getsockopt(struct socket *sock, int level,
				      int optname, char __user * optval,
				      int __user * optlen)
{
	int ret = 0;
	dprintk_in();
out:
	dprintk_out();
	return ret;
}


static int v4v_sock_stream_sendmsg(struct kiocb *kiocb, struct socket *sock,
				   struct msghdr *msg, size_t len)
{
	int ret = 0;
        struct sock *sk;
        struct v4v_sock *xsk;

	dprintk_in();
	dump_msghdr(msg);

	sk = sock->sk;
	xsk = xen_sk(sk);
	dump_msghdr(msg);
	ret = v4v_send_stream(xsk->priv_data, msg->msg_iov->iov_base, msg->msg_iov->iov_len, 0);
out:
	dprintk_out();
	return ret;
}
/* V4V Device */

#if 0
static struct miscdevice v4v_miscdev_dgram = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "v4v_dgram",
        .fops = &v4v_fops_dgram,
};

static struct miscdevice v4v_miscdev_stream = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "v4v_stream",
        .fops = &v4v_fops_stream,
};
#endif

#if 0
static int v4v_suspend(struct platform_device *dev, pm_message_t state)
{
        unbind_virq();
        return 0;
}

static int v4v_resume(struct platform_device *dev)
{
        struct ring *r;

        read_lock(&list_lock);
        list_for_each_entry(r, &ring_list, node) {
                refresh_pfn_list(r);
                if (register_ring(r)) {
                        printk(KERN_ERR
                               "Failed to re-register a v4v ring on resume, port=0x%08x\n",
                               r->ring->id.addr.port);
                }
        }
        read_unlock(&list_lock);

        if (bind_evtchn()) {
                printk(KERN_ERR "v4v_resume: failed to bind v4v evtchn\n");
                return -ENODEV;
        }

        return 0;
}

#endif
static void v4v_shutdown(struct platform_device *dev)
{

}

static int v4v_probe(struct platform_device *dev)
{
        int err = 0;
        int ret;

        dprintk_in();
        ret = setup_fs();
        if (ret)
                goto out;

        INIT_LIST_HEAD(&ring_list);
        rwlock_init(&list_lock);
        INIT_LIST_HEAD(&pending_xmit_list);
        spin_lock_init(&pending_xmit_lock);
        spin_lock_init(&interrupt_lock);
        atomic_set(&pending_xmit_count, 0);

        if (bind_evtchn()) {
                printk(KERN_ERR "failed to bind v4v evtchn\n");
                unsetup_fs();
                ret = -ENODEV;
                goto out;
        }

#if 0
        err = misc_register(&v4v_miscdev_dgram);
        if (err != 0) {
                printk(KERN_ERR "Could not register /dev/v4v_dgram\n");
                unsetup_fs();
                ret = err;
                goto out;
        }

        err = misc_register(&v4v_miscdev_stream);
        if (err != 0) {
                printk(KERN_ERR "Could not register /dev/v4v_stream\n");
                unsetup_fs();
                ret = err;
                goto out;
        }

#endif
        printk(KERN_INFO "Xen V4V device installed.\n");
out:
        dprintk_out();
        return ret;
}

/* Platform Gunge */

static int v4v_remove(struct platform_device *dev)
{

        dprintk_in();

        unbind_virq();
        //misc_deregister(&v4v_miscdev_dgram);
        //misc_deregister(&v4v_miscdev_stream);
        unsetup_fs();

        dprintk_out();

        return 0;
}

#if 0
static struct platform_driver v4v_driver = {
        .driver = {
                   .name = "v4v",
                   .owner = THIS_MODULE,
                   },
        .probe = v4v_probe,
        .remove = v4v_remove,
        .shutdown = v4v_shutdown,
        .suspend = v4v_suspend,
        .resume = v4v_resume,
};

static struct platform_device *v4v_platform_device;
#endif

/* Notes for implementing recvmsg:
 * ===============================
 * msg->msg_namelen should get updated by the recvmsg handlers
 * iff msg_name != NULL. It is by default 0 to prevent
 * returning uninitialized memory to user space.  The recvfrom
 * handlers can assume that msg.msg_name is either NULL or has
 * a minimum size of sizeof(struct sockaddr_storage).
 */
#if 0
int my_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	return 0;
}
ssize_t my_sendpage(struct socket *sock, struct page *page,
		    int offset, size_t size, int flags)
{
	return 0;
}
ssize_t my_splice_read(struct socket *sock, loff_t * ppos,
		       struct pipe_inode_info *pipe, size_t len,
		       unsigned int flags)
{
	return 0;
}
int my_set_peek_off(struct sock *sk, int val)
{
	return 0;
}
int my_init_sock(struct sock *sk, int val)
{
	return 0;
}
int my_disconnect(struct sock *sk, int val)
{
	return 0;
}
#endif

static int v4v_sock_release (struct socket *sock)
{
	struct sock *sk;
	struct v4v_sock *xsk;
	struct v4v_private *priv_data;
        struct v4v_private *p;
        unsigned long flags;
        struct pending_recv *pending;

        dprintk_in();

	printk(KERN_INFO "%s: releasing sock:%p\n", __func__, sock);
	sk = sock->sk;
	if (!sk) {
		printk(KERN_INFO "%s: socket is null ;-)\n", __func__);
		goto out;
	}
	xsk = xen_sk(sk);
	priv_data = get_priv_data(xsk);
	p = priv_data;
        if (p->ptype == V4V_PTYPE_STREAM) {
                switch (p->state) {
                case V4V_STATE_CONNECTED:
                case V4V_STATE_CONNECTING:
                case V4V_STATE_ACCEPTED:
			dprintk_err("state:%d\n", p->state);
                        xmit_queue_rst_to(&p->r->ring->id, p->conid, &p->peer);
                        break;
                default:
                        break;
                }
        }

        write_lock_irqsave(&list_lock, flags);
        if (!p->r) {
		dprintk_err("NO RING p:%p\n", p);
                write_unlock_irqrestore(&list_lock, flags);
                goto release;
        }

        if (p != p->r->sponsor) {
		dprintk_err("sponsor not equal:%p\n", p);
                put_ring(p->r);
                list_del(&p->node);
                write_unlock_irqrestore(&list_lock, flags);
                goto release;
        }

        p->r->sponsor = NULL;
        put_ring(p->r);
        write_unlock_irqrestore(&list_lock, flags);

        while (!list_empty(&p->pending_recv_list)) {
                pending =
                    list_first_entry(&p->pending_recv_list,
                                     struct pending_recv, node);
		dprintk_err("empty pending receives:%p\n", pending);

                list_del(&pending->node);
                kfree(pending);
                v4v_atomic_dec(&p->pending_recv_count);
        }

release:
        dprintk_err("pending_recv:%d\n", list_empty(&p->pending_recv_list));
        dprintk_err("pending_xmit:%d\n", list_empty(&pending_xmit_list));
        dprintk_err("ring_list:%d\n", list_empty(&ring_list));
        kfree(p);

out:
        dprintk_out();
        return 0;
}

static const struct proto_ops v4v_stream_ops = {
	.family = PF_XEN,
	.owner = THIS_MODULE,
	.release = v4v_sock_release,
	.bind = v4v_sock_bind,
	.connect = v4v_sock_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = v4v_sock_accept,
	.getname = v4v_sock_getname,
	.poll = v4v_sock_poll,
	.ioctl = sock_no_ioctl,
	.listen = v4v_sock_listen,
	.shutdown = v4v_sock_shutdown,
	.getsockopt = v4v_sock_stream_getsockopt,
	.setsockopt = v4v_sock_stream_setsockopt,
	.sendmsg= v4v_sock_stream_sendmsg,
	.recvmsg = v4v_sock_stream_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static void initialize_v4v_sock(struct v4v_sock *x)
{
	struct v4v_private *p;

	dprintk_in();

	x->is_server = 0;
	x->is_client = 0;
	x->otherend_id = -1;
	x->descriptor_addr = NULL;
	x->descriptor_gref = -ENOSPC;
	x->descriptor_area = NULL;
	x->descriptor_handle = -1;
	x->evtchn_local_port = -1;
	x->irq = -1;
	x->buffer_addr = 0;
	x->buffer_area = NULL;
	x->buffer_handles = NULL;
	x->buffer_order = -1;

        p = kmalloc(sizeof(struct v4v_private), GFP_KERNEL);
        if (!p)
                return -ENOMEM;
	total = 0;

        memset(p, 0, sizeof(struct v4v_private));
        p->state = V4V_STATE_IDLE;
        p->desired_ring_size = DEFAULT_RING_SIZE;
        p->r = NULL;
        p->ptype = V4V_PTYPE_STREAM;
        p->send_blocked = 0;

        init_waitqueue_head(&p->readq);
        init_waitqueue_head(&p->writeq);

        spin_lock_init(&p->pending_recv_lock);
        INIT_LIST_HEAD(&p->pending_recv_list);
        atomic_set(&p->pending_recv_count, 0);

        x->priv_data = p;

	dprintk_out();
}

static int v4v_sock_create(struct net *net, struct socket *sock,
                        int protocol, int kern)
{
	int rc = 0;
	struct sock *sk;
	struct v4v_sock *x;

	dprintk_in();

        if (!sock) {
		printk(KERN_ERR "%s: sock is null\n", __func__);
                rc = -EINVAL;
		goto out;
	}

	printk("%s: protocol:%#lx \n", __func__, protocol);
#if 0
        if (protocol && protocol != PF_XEN) {
		printk("%s: !protocol \n", __func__);
                return -EPROTONOSUPPORT;
	}
#endif

        switch (sock->type) {
        case SOCK_DGRAM:
		printk("%s: \n", __func__);
                sock->ops = &v4v_stream_ops;
                break;
        case SOCK_STREAM:
                sock->ops = &v4v_stream_ops;
                break;
        default:
		printk("%s: default \n", __func__);
                rc = -ESOCKTNOSUPPORT;
                goto out;
        }

        sock->state = SS_UNCONNECTED;

        sk = sk_alloc(net, AF_XEN, GFP_KERNEL, &v4v_proto);
        if (!sk) {
                rc = -ENOMEM;
                printk (KERN_ERR "%s: cannot allocate socket: ret = %d\n", __func__, rc);
                goto out;
        }

        sock_init_data(sock, sk);
        sk->sk_family = PF_XEN;
        sk->sk_protocol = protocol;
        x = xen_sk(sk);
        initialize_v4v_sock(x);

out:
        dprintk_out();
        return rc;
}

static struct net_proto_family v4v_family_ops = {
  .family         = AF_XEN,
  .create         = v4v_sock_create,
  .owner          = THIS_MODULE,
};

static int __init v4v_init(void)
{
        int ret = 0, error;

        dprintk_in();
        if (!xen_domain())
        {
                printk(KERN_ERR "v4v only works under Xen\n");
                ret = -ENODEV;
                goto out;
        }

#if 0
        error = platform_driver_register(&v4v_driver);
        if (error) {
                ret = error;
                goto out;
	}

        v4v_platform_device = platform_device_alloc("v4v", -1);
        if (!v4v_platform_device) {
                platform_driver_unregister(&v4v_driver);
                ret = -ENOMEM;
                goto out;
        }

        error = platform_device_add(v4v_platform_device);
        if (error) {
                platform_device_put(v4v_platform_device);
                platform_driver_unregister(&v4v_driver);
                ret = error;
                goto out;
        }

#endif
	v4v_probe(NULL);
	ret = proto_register(&v4v_proto, 1);
	if (ret != 0) {
		printk(KERN_CRIT "%s: Cannot create v4v_sock SLAB cache!\n", __func__);
		goto out;
	}

	sock_register(&v4v_family_ops);

out:
        dprintk_out();
        return ret;
}

static void __exit v4v_cleanup(void)
{
	dprintk_in();


	v4v_remove(NULL);
	sock_unregister(AF_XEN);
        //platform_driver_unregister(&v4v_driver);
        //platform_device_unregister(v4v_platform_device);
	proto_unregister(&v4v_proto);


	dprintk_out();
}


module_init(v4v_init);
module_exit(v4v_cleanup);
MODULE_LICENSE("GPL");

