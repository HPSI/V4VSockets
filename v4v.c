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
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/socket.h>
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
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/mount.h>

//#include <xen/interface/v4v.h>
//#include <xen/v4vdev.h>
#include "v4v.h"
#include "v4vdev.h"
#include "v4v_utils.h"

unsigned long start = 0, stop = 0, total=0;
#define DEFAULT_RING_SIZE \
    (V4V_ROUNDUP((((PAGE_SIZE)*32) - sizeof(v4v_ring_t)-V4V_ROUNDUP(1))))

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

#define MAX_PENDING_RECVS        16

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
        return HYPERVISOR_v4v_op (V4VOP_info, info, NULL, 0, 0);
}

static int H_v4v_register_ring(v4v_ring_t * r, v4v_pfn_t * l, size_t npages)
{
        (void)(*(volatile int *)r);
        return HYPERVISOR_v4v_op(V4VOP_register_ring, r, l, npages, 0);
}

static int H_v4v_unregister_ring(v4v_ring_t * r)
{
        (void)(*(volatile int *)r);
        return HYPERVISOR_v4v_op(V4VOP_unregister_ring, r, NULL, 0, 0);
}


static int
H_v4v_sendv(v4v_addr_t * s, v4v_addr_t * d, const v4v_iov_t * iovs,
            uint32_t niov, uint32_t protocol)
{
        v4v_send_addr_t addr;
        addr.src = *s;
        addr.dst = *d;
        return HYPERVISOR_v4v_op(V4VOP_sendv, &addr, (void *)iovs, niov,
                                 protocol);
}

static int
H_v4v_send(v4v_addr_t * s, v4v_addr_t * d, const void *buf, uint32_t len,
           uint32_t protocol)
{
        v4v_send_addr_t addr;
	int ret;
	char *temp;
	v4v_iov_t *iovs = kmalloc(sizeof(v4v_iov_t), GFP_KERNEL);

        addr.src = *s;
        addr.dst = *d;

	temp = (char*)buf;
	/*jo : modification*/
	iovs->iov_base = (uintptr_t)buf;
	iovs->iov_len = len;
	ret = H_v4v_sendv(s, d, iovs, 1, protocol);
        //return HYPERVISOR_v4v_op(V4VOP_send, &addr, (void *)buf, len, protocol);
	//printk(KERN_INFO "%s:ret = %d", __func__, ret);

	return ret;
}

static int H_v4v_notify(v4v_ring_data_t * rd)
{
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

        port = random32();
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
        int n = (r->ring->len + PAGE_SIZE - 1) >> PAGE_SHIFT;
        int len = sizeof(v4v_pfn_t) * n;

        r->pfn_list = kmalloc(len, GFP_KERNEL);
        if (!r->pfn_list)
                return;
        r->pfn_list_npages = n;

        refresh_pfn_list(r);
}

static int allocate_ring(struct ring *r, int ring_len)
{
        int len = ring_len + sizeof(v4v_ring_t);
        int ret = 0;

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

        return 0;
 fail:
        if (r->ring)
                vfree(r->ring);
        if (r->pfn_list)
                kfree(r->pfn_list);

        r->ring = NULL;
        r->pfn_list = NULL;

        return ret;
}

/* Caller must hold lock */
static void recover_ring(struct ring *r)
{
        /* It's all gone horribly wrong */
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

        if (id.addr.domain != V4V_DOMID_NONE)
                return -EINVAL;

        r = kmalloc(sizeof(struct ring), GFP_KERNEL);
        memset(r, 0, sizeof(struct ring));

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

        ret = register_ring(r);
        if (ret)
                goto fail;

        list_add(&r->node, &ring_list);
        write_unlock_irqrestore(&list_lock, flags);
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
}

/* Returns !0 if you sucessfully got a reference to the ring */
static int get_ring(struct ring *r)
{
        return atomic_add_unless(&r->refcnt, 1, 0);
}

/* Must be called with DEBUG_WRITELOCK; v4v_write_lock */
static void put_ring(struct ring *r)
{
        if (!r)
                return;

        if (atomic_dec_and_test(&r->refcnt)) {
                delete_ring(r);
        }
}

/* Caller must hold ring_lock */
static struct ring *find_ring_by_id(struct v4v_ring_id *id)
{
        struct ring *r;

        list_for_each_entry(r, &ring_list, node) {
                if (!memcmp
                    ((void *)&r->ring->id, id, sizeof(struct v4v_ring_id)))
                        return r;
        }
        return NULL;
}

/* Caller must hold ring_lock */
struct ring *find_ring_by_id_type(struct v4v_ring_id *id, v4v_rtype t)
{
        struct ring *r;

        list_for_each_entry(r, &ring_list, node) {
                if (r->type != t)
                        continue;
                if (!memcmp
                    ((void *)&r->ring->id, id, sizeof(struct v4v_ring_id)))
                        return r;
        }

        return NULL;
}

/* Pending xmits */

/* Caller must hold pending_xmit_lock */

static void
xmit_queue_wakeup_private(struct v4v_ring_id *from,
                          uint32_t conid, v4v_addr_t * to, int len, int delete)
{
        struct pending_xmit *p;

        list_for_each_entry(p, &pending_xmit_list, node) {
                if (p->type != V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES)
                        continue;
                if (p->conid != conid)
                        continue;

                if ((!memcmp(from, &p->from, sizeof(struct v4v_ring_id)))
                    && (!memcmp(to, &p->to, sizeof(v4v_addr_t)))) {
                        if (delete) {
                                atomic_dec(&pending_xmit_count);
                                list_del(&p->node);
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

        atomic_inc(&pending_xmit_count);
        list_add_tail(&p->node, &pending_xmit_list);
}

/* Caller must hold pending_xmit_lock */
static void
xmit_queue_wakeup_sponsor(struct v4v_ring_id *from, v4v_addr_t * to,
                          int len, int delete)
{
        struct pending_xmit *p;

        list_for_each_entry(p, &pending_xmit_list, node) {
                if (p->type != V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR)
                        continue;
                if ((!memcmp(from, &p->from, sizeof(struct v4v_ring_id)))
                    && (!memcmp(to, &p->to, sizeof(v4v_addr_t)))) {
                        if (delete) {
                                atomic_dec(&pending_xmit_count);
                                list_del(&p->node);
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
        atomic_inc(&pending_xmit_count);
        list_add_tail(&p->node, &pending_xmit_list);
}

static int
xmit_queue_inline(struct v4v_ring_id *from, v4v_addr_t * to,
                  void *buf, size_t len, uint32_t protocol)
{
        ssize_t ret;
        unsigned long flags;
        struct pending_xmit *p;
	v4v_iov_t *iovs = kmalloc(sizeof(v4v_iov_t), GFP_KERNEL);

        spin_lock_irqsave(&pending_xmit_lock, flags);
							
	/*jo : modification*/
	iovs->iov_base = (uintptr_t)buf;
	iovs->iov_len = len;
        //ret = H_v4v_send(&from->addr, to, buf, len, protocol);
	ret = H_v4v_sendv(&from->addr, to, iovs, 1, protocol);
	/*jo : end*/

        if (ret != -EAGAIN) {
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                return ret;
        }

        p = kmalloc(sizeof(struct pending_xmit) + len, GFP_ATOMIC);
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

        if (len)
                memcpy(p->data, buf, len);

        list_add_tail(&p->node, &pending_xmit_list);
        atomic_inc(&pending_xmit_count);
        spin_unlock_irqrestore(&pending_xmit_lock, flags);

        return len;
}

static void
xmit_queue_rst_to(struct v4v_ring_id *from, uint32_t conid, v4v_addr_t * to)
{
        struct v4v_stream_header sh;

        if (!to)
                return;

        sh.conid = conid;
        sh.flags = V4V_SHF_RST;
        xmit_queue_inline(from, to, &sh, sizeof(sh), V4V_PROTO_STREAM);
}

/* RX */

static int
copy_into_pending_recv(struct ring *r, int len, struct v4v_private *p)
{
        struct pending_recv *pending;
        int k;

        /* Too much queued? Let the ring take the strain */
        if (atomic_read(&p->pending_recv_count) > MAX_PENDING_RECVS) {
                spin_lock(&p->pending_recv_lock);
                p->full = 1;
                spin_unlock(&p->pending_recv_lock);

                return -1;
        }

        pending =
            kmalloc(sizeof(struct pending_recv) -
                    sizeof(struct v4v_stream_header) + len, GFP_ATOMIC);

        if (!pending)
                return -1;

        pending->data_ptr = 0;
        pending->data_len = len - sizeof(struct v4v_stream_header);

        k = v4v_copy_out(r->ring, &pending->from, NULL, &pending->sh, len, 1);

        spin_lock(&p->pending_recv_lock);
        list_add_tail(&pending->node, &p->pending_recv_list);
        atomic_inc(&p->pending_recv_count);
        p->full = 0;
        spin_unlock(&p->pending_recv_lock);

        return 0;
}

/* Notify */

/* Caller must hold list_lock */
static void
wakeup_privates(struct v4v_ring_id *id, v4v_addr_t * peer, uint32_t conid)
{
        struct ring *r = find_ring_by_id_type(id, V4V_RTYPE_LISTENER);
        struct v4v_private *p;

        if (!r)
                return;

        list_for_each_entry(p, &r->privates, node) {
                if ((p->conid == conid)
                    && !memcmp(peer, &p->peer, sizeof(v4v_addr_t))) {
                        p->send_blocked = 0;
                        wake_up_interruptible_all(&p->writeq);
                        return;
                }
        }
}

/* Caller must hold list_lock */
static void wakeup_sponsor(struct v4v_ring_id *id)
{
        struct ring *r = find_ring_by_id(id);

        if (!r)
                return;

        if (!r->sponsor)
                return;

        r->sponsor->send_blocked = 0;
        wake_up_interruptible_all(&r->sponsor->writeq);
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

	//printk(KERN_INFO "%s: Entering\n", __func__);
        spin_lock_irqsave(&pending_xmit_lock, flags);

        nent = atomic_read(&pending_xmit_count);
        d = kmalloc(sizeof(v4v_ring_data_t) +
                    nent * sizeof(v4v_ring_data_ent_t), GFP_ATOMIC);
        if (!d) {
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                return;
        }
        memset(d, 0, sizeof(v4v_ring_data_t));

        d->magic = V4V_RING_DATA_MAGIC;

        list_for_each_entry(p, &pending_xmit_list, node) {
                if (i != nent) {
                        d->data[i].ring = p->to;
                        d->data[i].space_required = p->len;
                        i++;
                }
        }
        d->nent = i;

        if (H_v4v_notify(d)) {
                kfree(d);
                spin_unlock_irqrestore(&pending_xmit_lock, flags);
                //MOAN;
                return;
        }

        i = 0;
        list_for_each_entry_safe(p, n, &pending_xmit_list, node) {
                int processed = 1;

                if (i == nent)
                        continue;

                if (d->data[i].flags & V4V_RING_DATA_F_EXISTS) {
                        switch (p->type) {
                        case V4V_PENDING_XMIT_INLINE:
				//printk(KERN_INFO "%s: v4v_pending_xmit_inline\n",__func__);
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
				//printk(KERN_INFO "%s: v4v_pending_xmit_wait_match_sponsor\n",__func__);
                                if (d->
                                    data[i].flags & V4V_RING_DATA_F_SUFFICIENT)
                                {
                                        wakeup_sponsor(&p->from);
                                } else {
                                        processed = 0;
                                }
                                break;
                        case V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES:
				//printk(KERN_INFO "%s: v4v_pending_xmit_wait_match_privates\n", __func__);
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
			//printk(KERN_INFO "%s: No one to talk to\n", __func__);
                        list_del(&p->node);     /* No one to talk to */
                        atomic_dec(&pending_xmit_count);
                        kfree(p);
                }
                i++;
        }

        spin_unlock_irqrestore(&pending_xmit_lock, flags);
        kfree(d);
	//printk(KERN_INFO "%s: Exiting\n", __func__);
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
	//printk(KERN_INFO "In connector state machine\n");
        if (sh->flags & V4V_SHF_ACK) {
                switch (p->state) {
                case V4V_STATE_CONNECTING:

			//printk(KERN_INFO "IN V4V_SHF_ACK && STATE CONNECTING\n");
                        p->state = V4V_STATE_CONNECTED;

                        spin_lock(&p->pending_recv_lock);
                        p->pending_error = 0;
                        spin_unlock(&p->pending_recv_lock);
                        wake_up_interruptible_all(&p->writeq);
                        ret = 0;
                        goto out;
                case V4V_STATE_CONNECTED:
                case V4V_STATE_DISCONNECTED:
			//printk(KERN_INFO "IN V4V_SHF_ACK && STATE DISCONNECTED\n");
                        p->state = V4V_STATE_DISCONNECTED;

                        wake_up_interruptible_all(&p->readq);
                        wake_up_interruptible_all(&p->writeq);
                        ret = 1;       /* Send RST */
                        goto out;
                default:
			//printk(KERN_INFO "IN V4V_SHF_ACK && DEFAULT\n");
                        break;
                }
        }

        if (sh->flags & V4V_SHF_RST) {
                switch (p->state) {
                case V4V_STATE_CONNECTING:
			//printk(KERN_INFO "IN V4V_SHF_RST && STATE CONNECTING\n");
                        spin_lock(&p->pending_recv_lock);
                        p->pending_error = -ECONNREFUSED;
                        spin_unlock(&p->pending_recv_lock);
                case V4V_STATE_CONNECTED:
			//printk(KERN_INFO "IN V4V_SHF_RST && STATE CONNECTED\n");
                        p->state = V4V_STATE_DISCONNECTED;
                        wake_up_interruptible_all(&p->readq);
                        wake_up_interruptible_all(&p->writeq);
                        ret = 0;
                        goto out;
                default:
			//printk(KERN_INFO "IN V4V_SHF_RST && STATE DEFAULT\n");
                        break;
                }
        }
out:
	//printk(KERN_INFO "EXITING CONNECTOR STATE MACHINE %d \n", ret);
        return ret;
}

static void
acceptor_state_machine(struct v4v_private *p, struct v4v_stream_header *sh)
{
	//printk(KERN_INFO "ACCEPTOR_STATE_MACHINE\n");
        if ((sh->flags & V4V_SHF_RST)
            && ((p->state == V4V_STATE_ACCEPTED))) {
                p->state = V4V_STATE_DISCONNECTED;
                wake_up_interruptible_all(&p->readq);
                wake_up_interruptible_all(&p->writeq);
        }
}

/* Interrupt handler */

static int connector_interrupt(struct ring *r)
{
        ssize_t msg_len;
        uint32_t protocol;
        struct v4v_stream_header sh;
        v4v_addr_t from;
        int ret = 0;

	//printk(KERN_INFO "%s: Entering...\n", __func__);
        if (!r->sponsor) {
                //MOAN;
		//printk(KERN_INFO "MOAN\n");
                return -1;
        }
	
	//printk(KERN_INFO "Before Peek the header\n");
        msg_len = v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 0);  /* Peek the header */
        if (msg_len == -1) {
		//printk(KERN_INFO "Peek the header\n");
                recover_ring(r);
                return ret;
        }



        if ((protocol != V4V_PROTO_STREAM) || (msg_len < sizeof(sh))) {
                /* Wrong protocol bin it */
	        //printk(KERN_INFO "Wrong protocol bin it\n");
                v4v_copy_out(r->ring, NULL, NULL, NULL, 0, 1);
                return ret;
        }

        if (sh.flags & V4V_SHF_SYN) {   /* This is a connector no-one should send SYN, send RST back */
		//printk(KERN_INFO "This is a connector no-one should send SYN\n");
                msg_len =
                    v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 1);
                if (msg_len == sizeof(sh)){
			//printk(KERN_INFO "This is a connector no-one should send SYN, nested if\n");
                        xmit_queue_rst_to(&r->ring->id, sh.conid, &from);
		}
                return ret;
        }

        /* Right connexion? */
        if (sh.conid != r->sponsor->conid) {
		//printk(KERN_INFO "Right connection\n");
                msg_len =
                    v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 1);
                xmit_queue_rst_to(&r->ring->id, sh.conid, &from);
                return ret;
        }

        /* Any messages to eat? */
        //printk(KERN_INFO "%s: flags = %#lx\n",__func__,  sh.flags);
        if (sh.flags & (V4V_SHF_ACK | V4V_SHF_RST)) {
		//printk(KERN_INFO "Any messages to eat\n");
                msg_len =
                    v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 1);
                if (msg_len == sizeof(sh)) {
			//printk(KERN_INFO "Any messages to eat,2nd if\n");
                        if (connector_state_machine(r->sponsor, &sh)){
				//printk(KERN_INFO "Any messages to eat, 3rd if\n");
                                xmit_queue_rst_to(&r->ring->id, sh.conid,
                                                  &from);
			}
                }
                return ret;
        }
        //FIXME set a flag to say wake up the userland process next time, and do that rather than copy
	//printk(KERN_INFO "FIXME\n");
        ret = copy_into_pending_recv(r, msg_len, r->sponsor);
        wake_up_interruptible_all(&r->sponsor->readq);

	//printk(KERN_INFO "Bgainei apo ton connector_interrupt\n");

        return ret;
}

static int
acceptor_interrupt(struct v4v_private *p, struct ring *r,
                   struct v4v_stream_header *sh, ssize_t msg_len)
{
        v4v_addr_t from;
        int ret = 0;

	//printk(KERN_INFO "%s: Entering\n", __func__);

        if (sh->flags & (V4V_SHF_SYN | V4V_SHF_ACK)) {  /* This is an  acceptor no-one should send SYN or ACK, send RST back */
                msg_len =
                    v4v_copy_out(r->ring, &from, NULL, sh, sizeof(*sh), 1);
                if (msg_len == sizeof(*sh))
                        xmit_queue_rst_to(&r->ring->id, sh->conid, &from);
                return ret;
        }

        /* Is it all over */
        if (sh->flags & V4V_SHF_RST) {
                /* Consume the RST */
                msg_len =
                    v4v_copy_out(r->ring, &from, NULL, sh, sizeof(*sh), 1);
                if (msg_len == sizeof(*sh))
                        acceptor_state_machine(p, sh);
                return ret;
        }

        /* Copy the message out */
        ret = copy_into_pending_recv(r, msg_len, p);
        wake_up_interruptible_all(&p->readq);

	//printk(KERN_INFO "%s: Exiting\n", __func__);

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

	//printk(KERN_INFO "%s: Entring\n",__func__);
        msg_len = v4v_copy_out(r->ring, &from, &protocol, &sh, sizeof(sh), 0);  /* Peek the header */
        if (msg_len == -1) {
		//printk(KERN_INFO "%s: Peek the header\n", __func__);
                recover_ring(r);
                return ret;
        }
	//printk(KERN_INFO "%s: msg_len = %d\n", __func__, msg_len);
	
        if ((protocol != V4V_PROTO_STREAM) || (msg_len < sizeof(sh))) {
                /* Wrong protocol bin it */
		//printk(KERN_INFO "%s: Wrong protocol\n",__func__);
                v4v_copy_out(r->ring, NULL, NULL, NULL, 0, 1);
                return ret;
        }

        list_for_each_entry(p, &r->privates, node) {
		//printk(KERN_INFO "%s: list for each\n",__func__);
                if ((p->conid == sh.conid)
                    && (!memcmp(&p->peer, &from, sizeof(v4v_addr_t)))) {
                        ret = acceptor_interrupt(p, r, &sh, msg_len);
                        return ret;
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
		//printk(KERN_INFO "%s: Consume it\n", __func__);
                struct pending_recv *pending, *t;

                spin_lock(&r->sponsor->pending_recv_lock);
                list_for_each_entry_safe(pending, t,
                                         &r->sponsor->pending_recv_list, node) {
                        if (pending->sh.flags & V4V_SHF_SYN
                            && pending->sh.conid == sh.conid) {
                                list_del(&pending->node);
                                atomic_dec(&r->sponsor->pending_recv_count);
                                kfree(pending);
                                break;
                        }
                }
                spin_unlock(&r->sponsor->pending_recv_lock);

                /* Rst to a listener, should be picked up above for the connexion, drop it */
		//printk(KERN_INFO "%s: RST to a listener\n",__func__);
                v4v_copy_out(r->ring, NULL, NULL, NULL, sizeof(sh), 1);
                return ret;
        }

        if (sh.flags & V4V_SHF_SYN) {
                /* Syn to new connexion */
		//printk(KERN_INFO "%s: Syn to new connection\n",__func__);
                if ((!r->sponsor) || (msg_len != sizeof(sh))) {
			//printk(KERN_INFO "%s: Syn to new connection if\n",__func__);
                        v4v_copy_out(r->ring, NULL, NULL, NULL,
                                           sizeof(sh), 1);
                        return ret;
                }
                ret = copy_into_pending_recv(r, msg_len, r->sponsor);
                wake_up_interruptible_all(&r->sponsor->readq);
                return ret;
        }

	//printk(KERN_INFO "%s: Before data to new destination\n",__func__);
        v4v_copy_out(r->ring, NULL, NULL, NULL, sizeof(sh), 1);
        /* Data for unknown destination, RST them */
	//printk(KERN_INFO "%s: After data to new destination\n",__func__);
        xmit_queue_rst_to(&r->ring->id, sh.conid, &from);

        return ret;
}

static void v4v_interrupt_rx(void)
{
        struct ring *r;
	int cnt=0;

	//printk(KERN_INFO "%s: entering..\n", __func__);
        read_lock(&list_lock);

        /* Wake up anyone pending */
        list_for_each_entry(r, &ring_list, node) {
                if (r->ring->tx_ptr == r->ring->rx_ptr)
                        continue;

                switch (r->type) {
                case V4V_RTYPE_IDLE:
                        v4v_copy_out(r->ring, NULL, NULL, NULL, 1, 1);
                        break;
                case V4V_RTYPE_DGRAM:  /* For datagrams we just wake up the reader */
                        if (r->sponsor)
                                wake_up_interruptible_all(&r->sponsor->readq);
                        break;
                case V4V_RTYPE_CONNECTOR:
			//printk(KERN_INFO "%s: V4V_RTYPE_CONNECTOR\n",__func__);
                        spin_lock(&r->lock);
                        while ((r->ring->tx_ptr != r->ring->rx_ptr)
                               && !connector_interrupt(r)) ;
                        spin_unlock(&r->lock);
                        break;
                case V4V_RTYPE_LISTENER:
			//printk(KERN_INFO "%s: V4V_RTYPE_LISTENER\n",__func__);
                        spin_lock(&r->lock);
                        while ((r->ring->tx_ptr != r->ring->rx_ptr)
                               && !listener_interrupt(r)) {
				//printk(KERN_INFO "%s: V4V_RTYPE_LISTENER, cnt= %d\n",__func__,cnt);
				cnt++;
			}
                        spin_unlock(&r->lock);
                        break;
                default:       /* enum warning */
                        break;
                }
        }
        read_unlock(&list_lock);
	//printk(KERN_INFO "%s: exiting..\n", __func__);
}

static irqreturn_t v4v_interrupt(int irq, void *dev_id)
{
        unsigned long flags;
				
	/*jo : trace*/
        spin_lock_irqsave(&interrupt_lock, flags);
        v4v_interrupt_rx();
        v4v_notify();
        spin_unlock_irqrestore(&interrupt_lock, flags);

        return IRQ_HANDLED;
}

static void v4v_fake_irq(void)
{
        unsigned long flags;

        spin_lock_irqsave(&interrupt_lock, flags);
        v4v_interrupt_rx();
        v4v_null_notify();
        spin_unlock_irqrestore(&interrupt_lock, flags);
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

        ret = H_v4v_send(&p->r->ring->id.addr, dest, buf, len, protocol);
	//printk(KERN_INFO "%s : ret = %d\n", __func__, ret); 
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

        return ret;
}

static ssize_t
v4v_sendto_from_sponsor(struct v4v_private *p,
                        const void *buf, size_t len,
                        int nonblock, v4v_addr_t * dest, uint32_t protocol)
{
        size_t ret = 0, ts_ret;

        switch (p->state) {
        case V4V_STATE_CONNECTING:
                ret = -ENOTCONN;
                break;
        case V4V_STATE_DISCONNECTED:
                ret = -EPIPE;
                break;
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
                break;
        default:
                ret = -EINVAL;
        }

        if (len > (p->r->ring->len - sizeof(struct v4v_ring_message_header)))
                return -EMSGSIZE;
	//printk(KERN_INFO "%s len = %d, ring_len = %d, mh = %d\n", __func__, len, p->r->ring->len, sizeof(struct v4v_ring_message_header));		
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

        return ret;
}

static ssize_t
v4v_stream_sendvto_from_sponsor(struct v4v_private *p,
                                const v4v_iov_t * iovs, size_t niov,
                                size_t len, int nonblock,
                                v4v_addr_t * dest, uint32_t protocol)
{
        size_t ret = 0, ts_ret;

        switch (p->state) {
        case V4V_STATE_CONNECTING:
                return -ENOTCONN;
        case V4V_STATE_DISCONNECTED:
                return -EPIPE;
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
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
                                         v4v_try_sendv_sponsor
                                         (p, dest,
                                          iovs, niov, len,
                                          protocol)) != -EAGAIN)
                                       || !stream_connected(p));
        if (ret == 0)
                ret = ts_ret;

        return ret;
}
static ssize_t
v4v_stream_sendvto_from_private(struct v4v_private *p,
                                const v4v_iov_t * iovs, size_t niov,
                                size_t len, int nonblock,
                                v4v_addr_t * dest, uint32_t protocol)
{
        size_t ret = 0, ts_ret;

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

        return 0;
}

static ssize_t
v4v_recvfrom_dgram(struct v4v_private *p, void *buf, size_t len,
                   int nonblock, int peek, v4v_addr_t * src)
{
        ssize_t ret;
        uint32_t protocol;
        v4v_addr_t lsrc;

        if (!src)
                src = &lsrc;

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

        if (!peek)
                v4v_null_notify();

        if (protocol != V4V_PROTO_DGRAM) {
                /* If peeking consume the rubbish */
                if (peek)
                        v4v_copy_out(p->r->ring, NULL, NULL, NULL, 1, 1);
                read_unlock(&list_lock);
                goto retry;
        }

        if ((p->state == V4V_STATE_CONNECTED) &&
            memcmp(src, &p->peer, sizeof(v4v_addr_t))) {
                /* Wrong source - bin it */
                if (peek)
                        v4v_copy_out(p->r->ring, NULL, NULL, NULL, 1, 1);
                read_unlock(&list_lock);
                goto retry;
        }

unlock:
        read_unlock(&list_lock);

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

        read_lock(&list_lock);

        switch (p->state) {
        case V4V_STATE_DISCONNECTED:
                ret = -EPIPE;
                goto unlock;
        case V4V_STATE_CONNECTING:
                ret = -ENOTCONN;
                goto unlock;
        case V4V_STATE_CONNECTED:
        case V4V_STATE_ACCEPTED:
                break;
        default:
                ret = -EINVAL;
                goto unlock;
        }

        do {
                if (!nonblock) {
			struct timeval tv;
			do_gettimeofday(&tv);
			start = tv.tv_sec * 1000000 + tv.tv_usec;
                        ret = wait_event_interruptible(p->readq,
                                                       (!list_empty(&p->pending_recv_list)
                                                        || !stream_connected(p)));

			do_gettimeofday(&tv);
			stop = tv.tv_sec * 1000000 + tv.tv_usec;
			total += stop - start;
                        if (ret) {
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
                                to_copy = len;
                        } else {
                                unlink = 1;
                                to_copy = pending->data_len - pending->data_ptr;
                        }

                        if (!access_ok(VERIFY_WRITE, buf, to_copy)) {
                                printk(KERN_ERR
                                       "V4V - ERROR: buf invalid _buf=%p buf=%p len=%d to_copy=%zu count=%zu\n",
                                       _buf, buf, len, to_copy, count);
                                spin_unlock_irqrestore(&p->pending_recv_lock, flags);
                                read_unlock(&list_lock);
                                return -EFAULT;
                        }
                        
                        if (copy_to_user(buf, pending->data + pending->data_ptr, to_copy))
                        {
                                spin_unlock_irqrestore(&p->pending_recv_lock, flags);
                                read_unlock(&list_lock);
                                return -EFAULT;
                        }

                        if (unlink) {
                                list_del(&pending->node);
                                kfree(pending);
                                atomic_dec(&p->pending_recv_count);
                                if (p->full)
                                        schedule_irq = 1;
                        } else
                                pending->data_ptr += to_copy;

                        buf += to_copy;
                        count += to_copy;
                        len -= to_copy;
                }
                        
                spin_unlock_irqrestore(&p->pending_recv_lock, flags);

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

        return count ? count : ret;
}

static ssize_t
v4v_send_stream(struct v4v_private *p, const void *_buf, int len, int nonblock)
{
        int write_lump;
        const uint8_t *buf = _buf;
        size_t count = 0;
        ssize_t ret;
        int to_send;

        write_lump = DEFAULT_RING_SIZE >> 2;

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

        return count;
}

static int v4v_bind(struct v4v_private *p, struct v4v_ring_id *ring_id)
{
        int ret = 0;

	/*jo : trace*/		
	//printk(KERN_INFO "In v4v_bind domain = %d malakia = %d\n", ring_id->addr.domain, V4V_DOMID_NONE);
	
        if (ring_id->addr.domain != V4V_DOMID_NONE) {
                return -EINVAL;
        }
	/*jo : trace*/
	//printk(KERN_INFO "ring_id->addr.domain = %d\n",ring_id->addr.domain);

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                ret = new_ring(p, ring_id);
                if (!ret)
                        p->r->type = V4V_RTYPE_DGRAM;
                break;
        case V4V_PTYPE_STREAM:
                ret = new_ring(p, ring_id);
                break;
        }
	/*jo : trace*/
	//printk(KERN_INFO "after registration domain = %d\n",ring_id->addr.domain);
        return ret;
}

static int v4v_listen(struct v4v_private *p)
{
	//printk(KERN_INFO "%s: Entering\n", __func__);
        if (p->ptype != V4V_PTYPE_STREAM)
                return -EINVAL;

        if (p->state != V4V_STATE_BOUND) {
                return -EINVAL;
        }

        p->r->type = V4V_RTYPE_LISTENER;
        p->state = V4V_STATE_LISTENING;

	//printk(KERN_INFO "%s: Exiting\n", __func__);
        return 0;
}

static int v4v_connect(struct v4v_private *p, v4v_addr_t * peer, int nonblock)
{
        struct v4v_stream_header sh;
        int ret = -EINVAL;

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
                        return 0;
                default:
                        return -EINVAL;
                }
        }
        if (p->ptype != V4V_PTYPE_STREAM) {
                return -EINVAL;
        }
				
	/*jo : trace*/
	//printk(KERN_INFO "ftanei ws edw");

        /* Irritiatingly we need to be restartable */
        switch (p->state) {
        case V4V_STATE_BOUND:
		/*jo : trace*/
		//printk(KERN_INFO "mpainei sthn connect sto bound");
                p->r->type = V4V_RTYPE_CONNECTOR;
                p->state = V4V_STATE_CONNECTING;
                p->conid = random32();
                p->peer = *peer;

                sh.flags = V4V_SHF_SYN;
                sh.conid = p->conid;

                ret =
                    xmit_queue_inline(&p->r->ring->id, &p->peer, &sh,
                                      sizeof(sh), V4V_PROTO_STREAM);
                if (ret == sizeof(sh))
                        ret = 0;
		  /*jo : trace*/
		//printk(KERN_INFO "meta to xmit to ret = %d\n",ret);
								

                if (ret && (ret != -EAGAIN)) {
                        p->state = V4V_STATE_BOUND;
                        p->r->type = V4V_RTYPE_DGRAM;
                        return ret;
                }

                break;
        case V4V_STATE_CONNECTED:	
		/*jo : trace*/
		//printk(KERN_INFO "mpainei sto connected\n");

                if (memcmp(peer, &p->peer, sizeof(v4v_addr_t))) {
                        return -EINVAL;
                } else {
                        return 0;
                }
        case V4V_STATE_CONNECTING:
                /*jo : trace*/
		//printk(KERN_INFO "mpainei sto connecting\n");
                if (memcmp(peer, &p->peer, sizeof(v4v_addr_t))) {
                        return -EINVAL;
                }
                break;
        default:
		/*jo : trace*/
		//printk(KERN_INFO "mpainei sto default\n");
               return -EINVAL;
        }

        if (nonblock) {
                return -EINPROGRESS;
        }

        while (p->state != V4V_STATE_CONNECTED) {
		//printk(KERN_INFO "mpainei sthn connect sto while\n");
                ret =
                    wait_event_interruptible(p->writeq,
                                             (p->state !=
                                              V4V_STATE_CONNECTING));
		//printk(KERN_INFO "%s:meta to while state = %d, ret = %d",__func__, p->state,ret);
                if (ret)
                        return ret;

                if (p->state == V4V_STATE_DISCONNECTED) {
                        p->state = V4V_STATE_BOUND;
                        p->r->type = V4V_RTYPE_DGRAM;
                        ret = -ECONNREFUSED;
			/*jo : trace */									
			//printk(KERN_INFO "mpanei edw mesa\n");
                        break;
                }
        }

        return ret;
}

static int allocate_fd_with_private(void *private)
{
        int fd;
        struct file *f;
        struct qstr name = {.name = "" };
        struct path path;
        struct inode *ind;

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

        return fd;
}

static int
v4v_accept(struct v4v_private *p, struct v4v_addr *peer, int nonblock)
{
        int fd;
        int ret = 0;
        struct v4v_private *a = NULL;
        struct pending_recv *r = NULL;
        unsigned long flags;
        struct v4v_stream_header sh;
	

	//printk(KERN_INFO "%s: Entering\n", __func__);
        if (p->ptype != V4V_PTYPE_STREAM)
                return -ENOTTY;

        if (p->state != V4V_STATE_LISTENING) {
                return -EINVAL;
        }


        /* FIXME: leak! */
        for (;;) {
		/*jo : trace*/
                ret =
                    wait_event_interruptible(p->readq,
                                             (!list_empty
                                              (&p->pending_recv_list))
                                             || nonblock);
                if (ret)
                        return ret;

                /* Write lock implicitly has pending_recv_lock */
                write_lock_irqsave(&list_lock, flags);

                if (!list_empty(&p->pending_recv_list)) {
                        r = list_first_entry(&p->pending_recv_list,
                                             struct pending_recv, node);

                        list_del(&r->node);
                        atomic_dec(&p->pending_recv_count);

                        if ((!r->data_len) && (r->sh.flags & V4V_SHF_SYN))
                                break;
			//printk(KERN_INFO "%s: Is going to kfree(r)\n", __func__);
                        kfree(r);
                }

                write_unlock_irqrestore(&list_lock, flags);
                if (nonblock)
                        return -EAGAIN;
        }
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

        init_waitqueue_head(&a->readq);
        init_waitqueue_head(&a->writeq);
        spin_lock_init(&a->pending_recv_lock);
        INIT_LIST_HEAD(&a->pending_recv_list);
        atomic_set(&a->pending_recv_count, 0);

        a->send_blocked = 0;
        a->peer = r->from;
        a->conid = r->sh.conid;

        if (peer) {
                *peer = r->from;
	//	printk(KERN_INFO "%s: peer->port = %lu, peer->domain = %d\n", r->from.port, r->from.domain);
	}

        fd = allocate_fd_with_private(a);
        if (fd < 0) {
                ret = fd;
                goto release;
        }

        write_lock_irqsave(&list_lock, flags);
        list_add(&a->node, &a->r->privates);
        write_unlock_irqrestore(&list_lock, flags);

        /* Ship the ACK */
        sh.conid = a->conid;
        sh.flags = V4V_SHF_ACK;

	//printk(KERN_INFO "%s: it s going to ship the ack conid = %#lx, flag = %#lx\n", __func__, sh.conid, sh.flags);

        xmit_queue_inline(&a->r->ring->id, &a->peer, &sh,
                          sizeof(sh), V4V_PROTO_STREAM);
        kfree(r);

        return fd;

 release:
        kfree(r);
        if (a) {
                write_lock_irqsave(&list_lock, flags);
                if (a->r)
                        put_ring(a->r);
                write_unlock_irqrestore(&list_lock, flags);
                kfree(a);
        }
        return ret;
}

ssize_t
v4v_sendto(struct v4v_private * p, const void *buf, size_t len, int flags,
           v4v_addr_t * addr, int nonblock)
{
        ssize_t rc;

        if (!access_ok(VERIFY_READ, buf, len))
                return -EFAULT;
        if (!access_ok(VERIFY_READ, addr, len))
                return -EFAULT;

        if (flags & MSG_DONTWAIT)
                nonblock++;

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                switch (p->state) {
                case V4V_STATE_BOUND:
                        if (!addr)
                                return -ENOTCONN;
                        rc = v4v_sendto_from_sponsor(p, buf, len, nonblock,
                                                     addr, V4V_PROTO_DGRAM);
                        break;

                case V4V_STATE_CONNECTED:
                        if (addr)
                                return -EISCONN;

                        rc = v4v_sendto_from_sponsor(p, buf, len, nonblock,
                                                     &p->peer, V4V_PROTO_DGRAM);
                        break;

                default:
                        return -EINVAL;
                }
                break;
        case V4V_PTYPE_STREAM:
                if (addr)
                        return -EISCONN;
                switch (p->state) {
                case V4V_STATE_CONNECTING:
                case V4V_STATE_BOUND:
                        return -ENOTCONN;
                case V4V_STATE_CONNECTED:
                case V4V_STATE_ACCEPTED:
                        rc = v4v_send_stream(p, buf, len, nonblock);
                        break;
                case V4V_STATE_DISCONNECTED:

                        rc = -EPIPE;
                        break;
                default:

                        return -EINVAL;
                }
                break;
        default:

                return -ENOTTY;
        }

        if ((rc == -EPIPE) && !(flags & MSG_NOSIGNAL))
                send_sig(SIGPIPE, current, 0);

        return rc;
}

ssize_t
v4v_recvfrom(struct v4v_private * p, void *buf, size_t len, int flags,
             v4v_addr_t * addr, int nonblock)
{
        int peek = 0;
        ssize_t rc = 0;

        if (!access_ok(VERIFY_WRITE, buf, len))
                return -EFAULT;
        if ((addr) && (!access_ok(VERIFY_WRITE, addr, sizeof(v4v_addr_t))))
                return -EFAULT;

        if (flags & MSG_DONTWAIT)
                nonblock++;
        if (flags & MSG_PEEK)
                peek++;

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                rc = v4v_recvfrom_dgram(p, buf, len, nonblock, peek, addr);
                break;
        case V4V_PTYPE_STREAM:
                if (peek)
                        return -EINVAL;

                switch (p->state) {
                case V4V_STATE_BOUND:
                        return -ENOTCONN;
                case V4V_STATE_CONNECTED:
                case V4V_STATE_ACCEPTED:
                        if (addr)
                                *addr = p->peer;
                        rc = v4v_recv_stream(p, buf, len, flags, nonblock);
                        break;
                case V4V_STATE_DISCONNECTED:
                        rc = 0;
                        break;
                default:
                        rc = -EINVAL;
                }
        }

        if ((rc > (ssize_t) len) && !(flags & MSG_TRUNC))
                rc = len;

        return rc;
}

/* fops */

static int v4v_open_dgram(struct inode *inode, struct file *f)
{
        struct v4v_private *p;
	/*jo : mpainei sthn open*/
	//printk(KERN_INFO "mpanei sthn open\n");

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
        return 0;
}

static int v4v_open_stream(struct inode *inode, struct file *f)
{
        struct v4v_private *p;

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
        return 0;
}

static int v4v_release(struct inode *inode, struct file *f)
{
        struct v4v_private *p = (struct v4v_private *)f->private_data;
        unsigned long flags;
        struct pending_recv *pending;
	/*jo : trace*/
	//printk(KERN_INFO "Entering function : %s\n", __func__);
	//printk(KERN_INFO "TIME spent waiting: %lu\n", total);
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
                atomic_dec(&p->pending_recv_count);
        }

 release:
        kfree(p);

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

        if (_IOC_TYPE(cmd) != V4V_TYPE)
                return rc;

        switch (cmd) {
        case V4VIOCSETRINGSIZE:
                if (!access_ok(VERIFY_READ, arg, sizeof(uint32_t)))
                        return -EFAULT;
                rc = v4v_set_ring_size(p, *(uint32_t *) arg);
                break;
        case V4VIOCBIND:
                if (!access_ok(VERIFY_READ, arg, sizeof(struct v4v_ring_id)))
                        return -EFAULT;
                rc = v4v_bind(p, (struct v4v_ring_id *)arg);
                break;
        case V4VIOCGETSOCKNAME:
                if (!access_ok(VERIFY_WRITE, arg, sizeof(struct v4v_ring_id)))
                        return -EFAULT;
                rc = v4v_get_sock_name(p, (struct v4v_ring_id *)arg);
                break;
        case V4VIOCGETPEERNAME:
                if (!access_ok(VERIFY_WRITE, arg, sizeof(v4v_addr_t)))
                        return -EFAULT;
                rc = v4v_get_peer_name(p, (v4v_addr_t *) arg);
                break;
        case V4VIOCCONNECT:
                if (!access_ok(VERIFY_READ, arg, sizeof(v4v_addr_t)))
                        return -EFAULT;
                /* Bind if not done */
                if (p->state == V4V_STATE_IDLE) {
                        struct v4v_ring_id id;
                        memset(&id, 0, sizeof(id));
                        id.partner = V4V_DOMID_NONE;
                        id.addr.domain = V4V_DOMID_NONE;
                        id.addr.port = 0;
                        rc = v4v_bind(p, &id);
                        if (rc)
                                break;
                }
		/*jo : trace*/
		//printk(KERN_INFO "mpainei sto connect tou ioctl");
                rc = v4v_connect(p, (v4v_addr_t *) arg, nonblock);
                break;
        case V4VIOCGETCONNECTERR:
                {
                        unsigned long flags;
                        if (!access_ok(VERIFY_WRITE, arg, sizeof(int)))
                                return -EFAULT;

                        spin_lock_irqsave(&p->pending_recv_lock, flags);
                        *(int *)arg = p->pending_error;
                        p->pending_error = 0;
                        spin_unlock_irqrestore(&p->pending_recv_lock, flags);
                        rc = 0;
                }
                break;
        case V4VIOCLISTEN:
                rc = v4v_listen(p);
                break;
        case V4VIOCACCEPT:
                if (!access_ok(VERIFY_WRITE, arg, sizeof(v4v_addr_t)))
                        return -EFAULT;
                rc = v4v_accept(p, (v4v_addr_t *) arg, nonblock);
                break;
        case V4VIOCSEND:
                if (!access_ok(VERIFY_READ, arg, sizeof(struct v4v_dev)))
                        return -EFAULT;
                {
                        struct v4v_dev a = *(struct v4v_dev *)arg;

                        rc = v4v_sendto(p, a.buf, a.len, a.flags, a.addr,
                                        nonblock);
                }
                break;
        case V4VIOCRECV:
                if (!access_ok(VERIFY_READ, arg, sizeof(struct v4v_dev)))
                        return -EFAULT;
                {
                        struct v4v_dev a = *(struct v4v_dev *)arg;
                        rc = v4v_recvfrom(p, a.buf, a.len, a.flags, a.addr,
                                          nonblock);
                }
                break;
        case V4VIOCVIPTABLESADD:
                if (!access_ok
                    (VERIFY_READ, arg, sizeof(struct v4v_viptables_rule_pos)))
                        return -EFAULT;
                {
                        struct v4v_viptables_rule_pos *rule =
                            (struct v4v_viptables_rule_pos *)arg;
                        v4v_viptables_add(p, rule->rule, rule->position);
                        rc = 0;
                }
                break;
        case V4VIOCVIPTABLESDEL:
                if (!access_ok
                    (VERIFY_READ, arg, sizeof(struct v4v_viptables_rule_pos)))
                        return -EFAULT;
                {
                        struct v4v_viptables_rule_pos *rule =
                            (struct v4v_viptables_rule_pos *)arg;
                        v4v_viptables_del(p, rule->rule, rule->position);
                        rc = 0;
                }
                break;
        case V4VIOCVIPTABLESLIST:
                if (!access_ok
                    (VERIFY_READ, arg, sizeof(struct v4vtables_list)))
                        return -EFAULT;
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

        return rc;
}

static unsigned int v4v_poll(struct file *f, poll_table * pt)
{
        unsigned int mask = 0;
        struct v4v_private *p = f->private_data;

        read_lock(&list_lock);

        switch (p->ptype) {
        case V4V_PTYPE_DGRAM:
                switch (p->state) {
                case V4V_STATE_CONNECTED:
                case V4V_STATE_BOUND:
                        poll_wait(f, &p->readq, pt);
                        mask |= POLLOUT | POLLWRNORM;
                        if (p->r->ring->tx_ptr != p->r->ring->rx_ptr)
                                mask |= POLLIN | POLLRDNORM;
                        break;
                default:
                        break;
                }
                break;
        case V4V_PTYPE_STREAM:
                switch (p->state) {
                case V4V_STATE_BOUND:
                        break;
                case V4V_STATE_LISTENING:
                        poll_wait(f, &p->readq, pt);
                        if (!list_empty(&p->pending_recv_list))
                                mask |= POLLIN | POLLRDNORM;
                        break;
                case V4V_STATE_ACCEPTED:
                case V4V_STATE_CONNECTED:
                        poll_wait(f, &p->readq, pt);
                        poll_wait(f, &p->writeq, pt);
                        if (!p->send_blocked)
                                mask |= POLLOUT | POLLWRNORM;
                        if (!list_empty(&p->pending_recv_list))
                                mask |= POLLIN | POLLRDNORM;
                        break;
                case V4V_STATE_CONNECTING:
                        poll_wait(f, &p->writeq, pt);
                        break;
                case V4V_STATE_DISCONNECTED:
                        mask |= POLLOUT | POLLWRNORM;
                        mask |= POLLIN | POLLRDNORM;
                        break;
                case V4V_STATE_IDLE:
                        break;
                }
                break;
        }

        read_unlock(&list_lock);
        return mask;
}

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

/* Xen VIRQ */
static int v4v_irq = -1;

static void unbind_virq(void)
{
	if (v4v_irq < 0) {
		printk (KERN_INFO "error in v4v_irq = %d\n", v4v_irq);
	}
	else
        	unbind_from_irqhandler (v4v_irq, NULL);
        v4v_irq = -1;
}

static int bind_evtchn(void)
{
        v4v_info_t info;
        int result;
        
        v4v_info(&info);
	//printk(KERN_INFO "echoing ring magic diff!, info.ring_magic = %#lx, %#lx\n", info.ring_magic, V4V_RING_MAGIC);
        if (info.ring_magic != V4V_RING_MAGIC) {
		//printk(KERN_INFO "ring magic diff!, info.ring_magic = %#lx, %#lx\n", info.ring_magic, V4V_RING_MAGIC);
                return 1;
	}
	/*jo : DOMID_SELF ok*/
        result =
                bind_interdomain_evtchn_to_irqhandler(
                        DOMID_SELF, info.evtchn,
                        v4v_interrupt, 0, "v4v", NULL);

        if (result < 0) {
		printk (KERN_INFO "result = %d\n", result);
                unbind_virq();
                return result;
        }

        v4v_irq = result;

        return 0;
}

/* V4V Device */

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

static void v4v_shutdown(struct platform_device *dev)
{
}

static int v4v_probe(struct platform_device *dev)
{
        int err = 0;
        int ret;

        ret = setup_fs();
        if (ret)
                return ret;

        INIT_LIST_HEAD(&ring_list);
        rwlock_init(&list_lock);
        INIT_LIST_HEAD(&pending_xmit_list);
        spin_lock_init(&pending_xmit_lock);
        spin_lock_init(&interrupt_lock);
        atomic_set(&pending_xmit_count, 0);

        if (bind_evtchn()) {
                printk(KERN_ERR "failed to bind v4v evtchn\n");
                unsetup_fs();
                return -ENODEV;
        }

        err = misc_register(&v4v_miscdev_dgram);
        if (err != 0) {
                printk(KERN_ERR "Could not register /dev/v4v_dgram\n");
                unsetup_fs();
                return err;
        }

        err = misc_register(&v4v_miscdev_stream);
        if (err != 0) {
                printk(KERN_ERR "Could not register /dev/v4v_stream\n");
                unsetup_fs();
                return err;
        }

        printk(KERN_INFO "Xen V4V device installed.\n");
        return 0;
}

/* Platform Gunge */

static int v4v_remove(struct platform_device *dev)
{
        unbind_virq();
        misc_deregister(&v4v_miscdev_dgram);
        misc_deregister(&v4v_miscdev_stream);
        unsetup_fs();
        return 0;
}

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

static int __init v4v_init(void)
{
        int error;

        if (!xen_domain())
        {
                printk(KERN_ERR "v4v only works under Xen\n");
                return -ENODEV;
        }

        error = platform_driver_register(&v4v_driver);
        if (error)
                return error;

        v4v_platform_device = platform_device_alloc("v4v", -1);
        if (!v4v_platform_device) {
                platform_driver_unregister(&v4v_driver);
                return -ENOMEM;
        }

        error = platform_device_add(v4v_platform_device);
        if (error) {
                platform_device_put(v4v_platform_device);
                platform_driver_unregister(&v4v_driver);
                return error;
        }

        return 0;
}

static void __exit v4v_cleanup(void)
{
        platform_device_unregister(v4v_platform_device);
        platform_driver_unregister(&v4v_driver);
}

module_init(v4v_init);
module_exit(v4v_cleanup);
MODULE_LICENSE("GPL");
