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

#ifndef __V4V_UTILS_H__
# define __V4V_UTILS_H__

#ifdef V4V_DEBUG
#define dprintk(fmt, args...) printk(KERN_INFO"%s:%d: " fmt, __FUNCTION__, __LINE__, args)
#define dprintk_info(fmt) printk(KERN_INFO "%s:%d: " fmt, __FUNCTION__, __LINE__)
#define dprintk_in() dprintk_info("enter\n")
#define dprintk_out() dprintk_info("exit\n")
#define dprintk_err(fmt, args...) printk(KERN_INFO"ERROR:%s:%d: " fmt, __FUNCTION__, __LINE__, args)
#else
#define dprintk(args...) 
#define dprintk_info(fmt) 
#define dprintk_in()
#define dprintk_out()
#define dprintk_err(fmt, args...) printk(KERN_INFO"ERROR:%s:%d: " fmt, __FUNCTION__, __LINE__, args)
#endif

/* Compiler specific hacks */
#if defined(__GNUC__)
# define V4V_UNUSED __attribute__ ((unused))
# ifndef __STRICT_ANSI__
#  define V4V_INLINE inline
# else
#  define V4V_INLINE
# endif
#else /* !__GNUC__ */
# define V4V_UNUSED
# define V4V_INLINE
#endif


/*
 * Utility functions
 */
static void v4v_hexdump(void *_p, int len)
{
    uint8_t *buf = (uint8_t *)_p;
    int i, j;
	dprintk_in();

    for ( i = 0; i < len; i += 16 )
    {
        printk(KERN_ERR "%p:", &buf[i]);
        for ( j = 0; j < 16; ++j )
        {
            int k = i + j;
            if ( k < len )
                printk(" %02x", buf[k]);
            else
                printk("   ");
        }
        printk(" ");

        for ( j = 0; j < 16; ++j )
        {
            int k = i + j;
            if ( k < len )
                printk("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            else
                printk(" ");
        }
        printk("\n");
    }
	dprintk_out();
}

#ifdef V4V_DEBUG
void dump_ring(struct v4v_ring *r)
{
	uint32_t len = r->len;
	char *p;
	int i;

	dprintk_in();
#if 0
	p = kmalloc(len + 1, GFP_ATOMIC);

	memcpy(p, &r->ring[0], len);
	for (i =0; i<len; i++) {
	    if ((int)p[i] < 65 || p[i] > 90) {
		p[i] = 95;
	    } 
	}
	p[len] = '\0';
#endif
	//printk(KERN_INFO "%s\n", p);
	v4v_hexdump(r, len);
	dprintk_out();

}
void print_msg_header(struct v4v_ring *r, struct v4v_ring_message_header *mh)
{   
	uint32_t len = mh->len;
	v4v_addr_t *source = &mh->source;
	uint32_t message_type = mh->message_type;
	uint8_t *data = mh->data;
	int i;
#if 0
	char *p = kmalloc(r->len + 1, GFP_ATOMIC);
#endif


	printk(KERN_INFO "len = %#x\n", len);
	printk(KERN_INFO "source.domain = %#x\n", source->domain);
	printk(KERN_INFO "source.port = %#x\n", source->port);
	printk(KERN_INFO "message_type = %#x\n", message_type);
	printk(KERN_INFO "data = %p\n", data);
#if 0
	memcpy(p, &r->ring[0], 4096);
	for (i =0; i<4096; i++) {
	    if ((int)p[i] < 65 || p[i] > 90) {
		p[i] = 91;
	    } 
	}
	p[4096] = '\0';
	printk(KERN_INFO "%s\n", p);
#endif
}  
#endif

static V4V_INLINE uint32_t
v4v_ring_bytes_to_read (volatile struct v4v_ring *r)
{
        int32_t ret;

	dprintk_in();

        ret = r->tx_ptr - r->rx_ptr;
        dprintk("tx= %#x, rx= %#x, ret = %d \n", (unsigned long)r->tx_ptr, (unsigned long)r->rx_ptr, ret);
        if (ret < 0)
                ret += r->len;

	dprintk_out();

        return (uint32_t) ret;
}


/*
 * Copy at most t bytes of the next message in the ring, into the buffer
 * at _buf, setting from and protocol if they are not NULL, returns
 * the actual length of the message, or -1 if there is nothing to read
 */
V4V_UNUSED static V4V_INLINE ssize_t
v4v_copy_out (struct v4v_ring *r, struct v4v_addr *from, uint32_t * protocol,
              void *_buf, size_t t, int consume)
{

	
        volatile struct v4v_ring_message_header *mh;
        /* unnecessary cast from void * required by MSVC compiler */
        uint8_t *buf = (uint8_t *) _buf;
        uint32_t btr = v4v_ring_bytes_to_read (r);
        uint32_t rxp = r->rx_ptr;
        uint32_t bte;
        uint32_t len;
        ssize_t ret;


	dprintk_in();

#if 0
        //printk("enter: rx = %#x, tx = %#x t:%#lx, consume:%d, total=%#lx, btr:%#x\n", r->rx_ptr, r->tx_ptr, t, consume, r->rx_ptr + t, btr);
        if (rxp == r->len) {
		printk("rxp:%#x == r->len:%#x, tx_ptr: %#lx, t:%#lx, consume:%d, btr:%#x", rxp, r->len, r->tx_ptr, t, consume, btr);
        	//dprintk_err("rx = %#x, tx = %#x\n", r->rx_ptr, r->tx_ptr);
                rxp = 0;
		if (consume)
                    r->rx_ptr = 0;
		    btr = v4v_ring_bytes_to_read (r);
	}
#endif
        //printk("rx = %#x, tx = %#x\n", r->rx_ptr, r->tx_ptr);
	dprintk("btr = %#x, mh = %#lx, r = %p", btr, sizeof(*mh), r->ring);

        if (btr < sizeof (*mh)) {
		dprintk_err("not enough bytes to read for the header: %#x < %#x\n", btr, sizeof(*mh));
        	dprintk_err("rx = %#x, tx = %#x t:%#lx, consume:%d\n", r->rx_ptr, r->tx_ptr, t, consume);
		v4v_hexdump(&r->ring[rxp], 0x40);
                ret = -1;
                goto out;
        }

        /*
         * Becuase the message_header is 128 bits long and the ring is 128 bit
         * aligned, we're gaurunteed never to wrap
         */
        mh = (volatile struct v4v_ring_message_header *) &r->ring[r->rx_ptr];
#ifdef V4V_DEBUG
        print_msg_header(r, mh);
#endif
	

	if (!mh) {
        	dprintk_err("rx = %#x, tx = %#x t:%#lx, consume:%d\n", r->rx_ptr, r->tx_ptr, t, consume);
		dprintk_err("ring totally corrupt...: %p\n", r->ring);
		ret = -1;
		goto out;
	}
        len = mh->len;
        
        if (btr < len || !len)
        {
		//dump_ring(r);
		dprintk_err("not enough bytes to read for the message: %#x < %#x\n", btr, len);
        	dprintk_err("rx = %#x, tx = %#x t:%#lx, consume:%d\n", r->rx_ptr, r->tx_ptr, t, consume);
		v4v_hexdump(&r->ring[rxp], 0x40);
		ret = -1;
		goto out;
        }

#if defined(__GNUC__)
        if (from) 
                *from = mh->source;
#else
        /* MSVC can't do the above */
        if (from)
                memcpy((void *) from, (void *) &(mh->source), sizeof(struct v4v_addr));
#endif

        dprintk("port=%i, domain= %i\n", from->port, from->domain);
        if (protocol)
                *protocol = mh->message_type;

        rxp += sizeof (*mh);
        if (rxp == r->len) {
		//printk("rxp:%#x == r->len:%#x, t:%#lx, consume:%d", rxp, r->len, t, consume);
                rxp = 0;
	}
        len -= sizeof (*mh);
        ret = len;

        bte = r->len - rxp;
	
	dprintk("rxp = %#x, bte = %#x, btr = %#x, len = %#x, t = %#lx\n", rxp, bte, btr, len, t);

        if (bte < len)
        {
                if (t < bte)
                {
                        if (buf)
                        {
                                memcpy (buf, (void *) &r->ring[rxp], t);
				//corrupt
				//printk(KERN_INFO "%s:%d: rxp = %#x, bte = %#x, btr = %#x, len = %#x, t = %#lx\n", __func__, __LINE__, rxp, bte, btr, len, t);
				//v4v_hexdump(&r->ring[rxp], t);
				//v4v_hexdump(buf, t);
                                buf += t;
                        }

                        rxp = 0;
                        //rxp = sizeof(v4v_ring_t);
                        len -= t;
                        t = 0;
			dprintk("t<bte rxp = %#x = 0, len = %#x\n", rxp, len);
                }
                else
                {
                        if (buf)
                        {
                                memcpy (buf, (void *) &r->ring[rxp], bte);
				//corrupt
				//printk(KERN_INFO "%s:%d: rxp = %#x, bte = %#x, btr = %#x, len = %#x, t = %#lx\n", __func__, __LINE__, rxp, bte, btr, len, t);
				//v4v_hexdump(&r->ring[rxp], bte);
				//v4v_hexdump(buf, bte);
                                buf += bte;
                        }
                        //rxp = sizeof(v4v_ring_t);
                        rxp = 0;
                        len -= bte;
                        t -= bte;
			dprintk("t>bte rxp = 0, t= %#x, len = %#x\n", t, len);
                }
        }
        else
	{
		dprintk("bte > LEN KNIKAS %#x, len = %#x\n", bte, len);
	}
	//printk("rxp = %#x = 0, len = %#x, buf:%p\n", rxp, len, buf);
        dprintk("rx = %#x, tx = %#x t:%#lx, consume:%d\n", r->rx_ptr, r->tx_ptr, t, consume);

        if (buf && t)  {
                memcpy (buf, (void *) &r->ring[rxp], (t < len) ? t : len);
		//printk(KERN_INFO "%s:%d: rxp = %#x, bte = %#x, btr = %#x, len = %#x, t = %#lx\n", __func__, __LINE__, rxp, bte, btr, len, t);
		//v4v_hexdump(buf, (t < len) ? t : len);
	}
	//printk("after memcpys: rx = %#x, tx = %#x t:%#lx, consume:%d, total=%#lx\n", r->rx_ptr, r->tx_ptr, t, consume, r->rx_ptr + t);
	
	//printk("len before round up len = %li, rxp = %li, r->len = %li, round loss = %li", (unsigned long)len, (unsigned long)rxp, (unsigned long)r->len, V4V_ROUNDUP (len) - len);
        
	//rxp += V4V_ROUNDUP (len);
	/*jo magic*/
	rxp += len;
	/*jo magic end*/
        if (V4V_ROUNDUP(rxp) == r->len) {
	//	printk("%s: rxp:%#x == r->len:%#x, t:%#lx, consume:%d, btr:%#x", __LINE__, rxp, r->len, t, consume, btr);
	//	printk("rxp tinkering: rx = %#x, tx = %#x t:%#lx, consume:%d, total=%#lx\n", r->rx_ptr, r->tx_ptr, t, consume, r->rx_ptr + t);
                rxp = 0;
	}

	//printk("after round up rxp = %li, rx = %li\n", (unsigned long)rxp, (unsigned long)r->rx_ptr);
        mb ();

        if (consume){
		//printk("%s: In consume rxp = %li\n", __func__, (unsigned long)rxp); 
		/*!jo magic*/
	        //r->rx_ptr = rxp;
	//	printk("consume before roundup: rxp:%#lx, rx = %#x, tx = %#x t:%#lx, consume:%d, total=%#lx\n", rxp, r->rx_ptr, r->tx_ptr, t, consume, r->rx_ptr + t);
		r->rx_ptr = V4V_ROUNDUP(rxp);
		/*jo magic end*/
	//	printk("consume: rxp:%#lx rx = %#x, tx = %#x t:%#lx, consume:%d, total=%#lx\n", rxp, r->rx_ptr, r->tx_ptr, t, consume, r->rx_ptr + t);
		dprintk("%s: In consume rx = %li (ROUNDUP loss: %li\n", __func__, (unsigned long)r->rx_ptr, V4V_ROUNDUP(rxp) - rxp);
	}

        dprintk("buf: %p, from: %p\n", (buf ? buf : 0), (from ? from : 0));
out:
	dprintk("ret:%#x rx = %#x, tx = %#x", ret, r->rx_ptr, r->tx_ptr);
	//printk("exit: rx = %#x, tx = %#x t:%#lx, consume:%d, total=%#lx\n", r->rx_ptr, r->tx_ptr, t, consume, r->rx_ptr + t);

	dprintk_out();
	//v4v_hexdump(buf, ret);
        return ret;
}

static V4V_INLINE void
v4v_memcpy_skip (void *_dst, const void *_src, size_t len, size_t *skip)
{
        const uint8_t *src =  (const uint8_t *) _src;
        uint8_t *dst = (uint8_t *) _dst;

	dprintk_in();
        if (!*skip)
        {
                memcpy (dst, src, len);
                goto out;
        }

        if (*skip >= len)
        {
                *skip -= len;
                goto out;
        }

        src += *skip;
        dst += *skip;
        len -= *skip;
        *skip = 0;

        memcpy (dst, src, len);
out:
	dprintk_out();
}

/*
 * Copy at most t bytes of the next message in the ring, into the buffer
 * at _buf, skipping skip bytes, setting from and protocol if they are not
 * NULL, returns the actual length of the message, or -1 if there is
 * nothing to read
 */
static ssize_t
v4v_copy_out_offset(struct v4v_ring *r, struct v4v_addr *from,
                    uint32_t * protocol, void *_buf, size_t t, int consume,
                    size_t skip) V4V_UNUSED;

V4V_INLINE static ssize_t
v4v_copy_out_offset(struct v4v_ring *r, struct v4v_addr *from,
                    uint32_t * protocol, void *_buf, size_t t, int consume,
                    size_t skip)
{
        volatile struct v4v_ring_message_header *mh;
        /* unnecessary cast from void * required by MSVC compiler */
        uint8_t *buf = (uint8_t *) _buf;
        uint32_t btr = v4v_ring_bytes_to_read (r);
        uint32_t rxp = r->rx_ptr;
        uint32_t bte;
        uint32_t len;
        ssize_t ret = 0;

	dprintk_in();
        buf -= skip;

        if (btr < sizeof (*mh)) {
                ret = -1;
                goto out;
        }

        /*
         * Becuase the message_header is 128 bits long and the ring is 128 bit
         * aligned, we're gaurunteed never to wrap
         */
        mh = (volatile struct v4v_ring_message_header *)&r->ring[r->rx_ptr];

        len = mh->len;
        if (btr < len) {
		printk("ERROR in btr < len\n");
                ret = -1;
                goto out;
	}

#if defined(__GNUC__)
        if (from)
                *from = mh->source;
#else
        /* MSVC can't do the above */
        if (from)
                memcpy((void *)from, (void *)&(mh->source), sizeof(struct v4v_addr));
#endif

        if (protocol)
                *protocol = mh->message_type;

        rxp += sizeof (*mh);
        if (rxp == r->len)
                rxp = 0;
        len -= sizeof (*mh);
        ret = len;

        bte = r->len - rxp;

        if (bte < len)
        {
                if (t < bte)
                {
                        if (buf)
                        {
                                v4v_memcpy_skip (buf, (void *) &r->ring[rxp], t, &skip);
                                buf += t;
                        }

                        rxp = 0;
                        len -= bte;
                        t = 0;
                }
                else
                {
                        if (buf)
                        {
                                v4v_memcpy_skip (buf, (void *) &r->ring[rxp], bte,
                                                &skip);
                                buf += bte;
                        }
                        rxp = 0;
                        len -= bte;
                        t -= bte;
                }
        }

        if (buf && t)
                v4v_memcpy_skip (buf, (void *) &r->ring[rxp], (t < len) ? t : len,
                                &skip);


        rxp += V4V_ROUNDUP (len);
        if (rxp == r->len)
                rxp = 0;

        mb ();

        if (consume)
                r->rx_ptr = rxp;

out:
	dprintk_out();
        return ret;
}


#endif /* !__V4V_UTILS_H__ */
