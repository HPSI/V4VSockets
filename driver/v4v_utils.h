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
#else
#define dprintk(args...) 
#define dprintk_info(fmt) 
#define dprintk_in()
#define dprintk_out()
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
static V4V_INLINE uint32_t
v4v_ring_bytes_to_read (volatile struct v4v_ring *r)
{
        int32_t ret;

	dprintk_in();

        ret = r->tx_ptr - r->rx_ptr;
        dprintk("%s: tx= %li, rx= %li, ret = %d \n", __func__, (unsigned long)r->tx_ptr, (unsigned long)r->rx_ptr, ret);
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
        dprintk("%s: rx = %li, tx = %li\n", __func__, (unsigned long)r->rx_ptr, (unsigned long)r->tx_ptr);
	dprintk("%s: btr = %#lu, mh = %#lx, r = %#lx", __func__, btr, sizeof(*mh), (unsigned long)r);
        if (btr < sizeof (*mh)) {
		printk(KERN_INFO "%s: btr < sizeof(*mh): %li < %lu\n", __func__, (unsigned long)btr, sizeof(*mh));		
                ret = -1;
                goto out;
        }

        /*
         * Becuase the message_header is 128 bits long and the ring is 128 bit
         * aligned, we're gaurunteed never to wrap
         */


        mh = (volatile struct v4v_ring_message_header *) &r->ring[r->rx_ptr];
	dprintk("%s: r->rx_ptr: %#lx\n", __func__, (unsigned long)r->rx_ptr);		
	

        len = mh->len;
        
        if (btr < len)
        {
		printk(KERN_ERR "%s: btr < len: %li < %li\n", __func__, (unsigned long)btr, (unsigned long)len);		
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

        dprintk("PORT = %lu, DOMAIN = %lu\n", from->port, from->domain);
        if (protocol)
                *protocol = mh->message_type;
        dprintk_info("after protocol \n");

        rxp += sizeof (*mh);
        if (rxp == r->len)
                rxp = 0;
        len -= sizeof (*mh);
        ret = len;

        bte = r->len - rxp;
	
	dprintk_info("print INDEX\n");
	dprintk("rxp = %li, bte = %li, btr = %li, len = %li, t = %li\n", (unsigned long)rxp, (unsigned long)bte, (unsigned long)btr, (unsigned long)len, (unsigned long)t);

        if (bte < len)
        {
                if (t < bte)
                {
                        if (buf)
                        {
                                memcpy (buf, (void *) &r->ring[rxp], t);
                                buf += t;
                        }

                        rxp = 0;
                        len -= bte;
                        t = 0;
			dprintk("t<bte rxp = t = 0, len = %li\n", (unsigned long)len);
                }
                else
                {
                        if (buf)
                        {
                                memcpy (buf, (void *) &r->ring[rxp], bte);
                                buf += bte;
                        }
                        rxp = 0;
                        len -= bte;
                        t -= bte;
			dprintk("t>bte rxp = 0, t= %li, len = %li\n", (unsigned long)t, (unsigned long)len);
                }
        }

        if (buf && t) 
                memcpy (buf, (void *) &r->ring[rxp], (t < len) ? t : len);
	
	dprintk("len before round up len = %li, rxp = %li, r->len = %li, round = %li", (unsigned long)len, (unsigned long)rxp, (unsigned long)r->len, V4V_ROUNDUP (len));
        
	//rxp += V4V_ROUNDUP (len);
	/*jo magic*/
	rxp += len;
	/*jo magic end*/
        if (rxp == r->len)
                rxp = 0;

	dprintk("after round up rxp = %li, rx = %li\n", (unsigned long)rxp, (unsigned long)r->rx_ptr);
        mb ();

        if (consume){
		dprintk("%s: In consume rxp = %li\n", __func__, (unsigned long)rxp); 
		/*!jo magic*/
	        //r->rx_ptr = rxp;
		r->rx_ptr = V4V_ROUNDUP(rxp);
		/*jo magic end*/
		dprintk("%s: In consume rx = %li\n", __func__, (unsigned long)r->rx_ptr);
	}

        dprintk("buf is: %#lx\n", (unsigned long) (buf ? buf : 0));
        dprintk("from is: %#lx\n", (unsigned long) (from ? from : 0));
        //printk(KERN_INFO "%s: len= %#lx mh (@ %#llx) = %s, buf (@ %#llx) = %s\n", __func__, (unsigned long) len,(unsigned long long) mh, (char *) &r->ring[rxp], (unsigned long long) buf, (char*) buf);
out:
	dprintk("%s: ret= %d rx = %li, tx = %li",__func__, ret, (unsigned long)r->rx_ptr, (unsigned long)r->tx_ptr);

	dprintk_out();
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
