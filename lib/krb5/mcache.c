/*
 * Copyright (c) 1997-2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

typedef struct krb5_mcache {
    char *name;
    unsigned int refcnt;
    unsigned int anonymous:1;
    unsigned int dead:1;
    krb5_principal primary_principal;
    struct link {
	krb5_creds cred;
	struct link *next;
    } *creds;
    struct krb5_mcache *next;
    time_t mtime;
    krb5_deltat kdc_offset;
    HEIMDAL_MUTEX mutex;
} krb5_mcache;

static HEIMDAL_MUTEX mcc_mutex = HEIMDAL_MUTEX_INITIALIZER;
static struct krb5_mcache *mcc_head;

#define	MCACHE(X)	((krb5_mcache *)(X)->data.data)

#define MISDEAD(X)	((X)->dead)

static krb5_error_code KRB5_CALLCONV
mcc_get_name(krb5_context context,
	     krb5_ccache id,
             const char **name,
             const char **col,
             const char **sub)
{
    if (name)
        *name = MCACHE(id)->name;
    if (col)
        *col = NULL;
    if (sub)
        *sub = MCACHE(id)->name;
    return 0;
}

static void
mcc_krb5_mcache_init(krb5_context context, const char *n,
                     krb5_mcache *m, int anon)
{
    /* must be protected with lock on &mcc_mutex unless anonymous */
    /* n must be allc'd if !anon; given away to krb5_mcache */

    *(const char **)&m->name = n; /* allocated string n now owned by m->name */
    m->anonymous = anon;
    if (anon)
        m->next = NULL;
    else {
        m->next = mcc_head;
        mcc_head = m;
        HEIMDAL_MUTEX_init(&(m->mutex));
    }
    m->dead = 0;
    m->refcnt = 1;
    m->primary_principal = NULL;
    m->creds = NULL;
    m->kdc_offset = 0;
    m->mtime = time(NULL);
}

static krb5_error_code
mcc_alloc_inst_uniq(krb5_context context, krb5_mcache **out)
{
    /* must be protected with lock on &mcc_mutex */
    /* heap address from krb5_mcache allocation is used in unique name */

    char *n;
    int len;

    krb5_mcache *m;
    ALLOC(m, 1);
    if(m == NULL)
	return krb5_enomem(context);

    len = asprintf(&n, "u%p-0", m);
    if (len < 0) {
        free(m);
	return krb5_enomem(context);
    }

    do {
        krb5_mcache *m_c;
        for (m_c = mcc_head; m_c != NULL; m_c = m_c->next)
            if (strcmp(n, m_c->name) == 0)
                break;
        if (m_c == NULL) {
            *out = m;
            mcc_krb5_mcache_init(context, n, m, 0); /* not anonymous */
            return 0;
        }
    } while (++(n[len-1]) < '9');

    free(m);
    free(n);
    return EAGAIN; /* XXX */
}

static krb5_error_code
mcc_alloc_inst(krb5_context context, const char *name, krb5_mcache **out)
{
    /* must be protected with lock on &mcc_mutex */

    krb5_mcache *m, *m_c;
    char *n;

    /* check for dups first */
    for (m_c = mcc_head; m_c != NULL; m_c = m_c->next)
        if (strcmp(name, m_c->name) == 0)
            break;
    if (m_c) {
        m = m_c;
        /* We raced with another thread to create this cache */
        HEIMDAL_MUTEX_lock(&(m->mutex));
        m->refcnt++;
        HEIMDAL_MUTEX_unlock(&(m->mutex));
        *out = m;
        return 0;
    }

    n = strdup(name);
    if (n == NULL)
        return krb5_enomem(context);

    ALLOC(m, 1);
    if(m == NULL) {
        free(n);
        return krb5_enomem(context);
    }
    *out = m;
    mcc_krb5_mcache_init(context, n, m, 0); /* not anonymous */
    return 0;
}

static krb5_error_code
mcc_alloc(krb5_context context, const char *name, krb5_ccache *id)
{
    krb5_mcache *m;
    int ret = 0;

    if (name != NULL && strcmp(name, "anonymous") == 0) {
        ALLOC(m, 1);
        if(m == NULL)
            return krb5_enomem(context);
        mcc_krb5_mcache_init(context, "anonymous", m, 1); /* anonymous */
    }
    else {
        HEIMDAL_MUTEX_lock(&(mcc_mutex));
        ret = (name != NULL)
          ? mcc_alloc_inst(context, name, &m)
          : mcc_alloc_inst_uniq(context, &m);
        HEIMDAL_MUTEX_unlock(&(mcc_mutex));
    }

    if (ret != 0)
        return ret;

    (*id)->data.data = m;
    (*id)->data.length = sizeof(*m);

    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_resolve(krb5_context context,
            krb5_ccache *id,
            const char *res,
            const char *sub)
{
    return mcc_alloc(context, sub && *sub ? sub : res, id);
}


static krb5_error_code KRB5_CALLCONV
mcc_gen_new(krb5_context context, krb5_ccache *id)
{
    return mcc_alloc(context, NULL, id);
}

static void KRB5_CALLCONV
mcc_destroy_internal(krb5_context context,
		     krb5_mcache *m)
{
    struct link *l;

    if (m->primary_principal != NULL) {
	krb5_free_principal (context, m->primary_principal);
	m->primary_principal = NULL;
    }
    m->dead = 1;

    l = m->creds;
    while (l != NULL) {
	struct link *old;

	krb5_free_cred_contents (context, &l->cred);
	old = l;
	l = l->next;
	free (old);
    }

    m->creds = NULL;
    return;
}

static krb5_error_code KRB5_CALLCONV
mcc_initialize(krb5_context context,
	       krb5_ccache id,
	       krb5_principal primary_principal)
{
    krb5_mcache *m = MCACHE(id);
    krb5_error_code ret = 0;
    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));
    heim_assert(m->refcnt != 0, "resurrection released mcache");
    /*
     * It's important to destroy any existing
     * creds here, that matches the behaviour
     * of all other backends and also the
     * MEMORY: backend in MIT.
     */
    mcc_destroy_internal(context, m);
    m->dead = 0;
    m->kdc_offset = 0;
    m->mtime = time(NULL);
    ret = krb5_copy_principal (context,
			       primary_principal,
			       &m->primary_principal);
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    return ret;
}

static int
mcc_close_internal(krb5_mcache *m)
{
    int ret = 0;
    HEIMDAL_MUTEX_lock(&(m->mutex));
    heim_assert(m->refcnt != 0, "closed dead cache mcache");
    if (--m->refcnt == 0) {
        if (MISDEAD(m)) {
            free(m->name);
            m->name = NULL;
            ret = 1;
        }
    }
    HEIMDAL_MUTEX_unlock(&(m->mutex));
    return ret;
}

static krb5_error_code KRB5_CALLCONV
mcc_close(krb5_context context,
	  krb5_ccache id)
{
    krb5_mcache *m = MCACHE(id);

    if (m->anonymous) {
        /*(do not free m->name, which is shared const "anonymous" string)*/
        heim_assert(m->refcnt == 1, "closed invalid anonymous mcache");
        krb5_data_free(&id->data);
    }
    else if (mcc_close_internal(m)) {
	HEIMDAL_MUTEX_destroy(&(m->mutex));
	krb5_data_free(&id->data);
    }
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_destroy(krb5_context context,
	    krb5_ccache id)
{
    krb5_mcache **n, *m = MCACHE(id);

    /* XXX: order of lock acquisition must be consistent with that of other
     * routines in order to avoid possibility of deadlock due to lock order */

    if (!m->anonymous) HEIMDAL_MUTEX_lock(&mcc_mutex);
    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));
    if (m->refcnt == 0)
    {
        if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
        if (!m->anonymous) HEIMDAL_MUTEX_unlock(&mcc_mutex);
    	krb5_abortx(context, "mcc_destroy: refcnt already 0");
    }

    if (!MISDEAD(m)) {
	/* if this is an active mcache, remove it from the linked
           list, and free all data */
        if (!m->anonymous) {
            /* XXX: scope needed for mcc_mutex lock could be further limited to
             * here rather than top and bottom of this routine if modification
             * to &m->mutex (incr, decr) and get (read) were made atomic */
            /*HEIMDAL_MUTEX_lock(&mcc_mutex);*/
            for(n = &mcc_head; n && *n; n = &(*n)->next) {
                if(m == *n) {
                    *n = m->next;
                    m->next = NULL;
                    break;
                }
            }
            /*HEIMDAL_MUTEX_unlock(&mcc_mutex);*/
	}
	mcc_destroy_internal(context, m);
    }
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&mcc_mutex);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_store_cred(krb5_context context,
	       krb5_ccache id,
	       krb5_creds *creds)
{
    krb5_mcache *m = MCACHE(id);
    krb5_error_code ret;
    struct link *l;

    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));
    do {
        if (MISDEAD(m)) {
            ret = ENOENT;
            break;
        }

        l = malloc(sizeof(*l));
        if (l == NULL) {
            ret = krb5_enomem(context);
            break;
        }

        memset (&l->cred, 0, sizeof(l->cred));
        ret = krb5_copy_creds_contents (context, creds, &l->cred);
        if (ret == 0) {
            l->next = m->creds;
            m->creds = l;
            m->mtime = time(NULL);
        }
        else {
            free(l);
        }
    } while (0);
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    return ret;
}

static krb5_error_code KRB5_CALLCONV
mcc_get_principal(krb5_context context,
		  krb5_ccache id,
		  krb5_principal *principal)
{
    krb5_mcache *m = MCACHE(id);
    krb5_error_code ret;

    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));
    ret = (!MISDEAD(m) && m->primary_principal != NULL)
      ? krb5_copy_principal (context,
			     m->primary_principal,
			     principal)
      : ENOENT;
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    return ret;
}

static krb5_error_code KRB5_CALLCONV
mcc_get_first (krb5_context context,
		krb5_ccache id,
		krb5_cc_cursor *cursor)
{
    krb5_mcache *m = MCACHE(id);
    krb5_error_code ret = 0;

    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));
    if (!MISDEAD(m))
        *cursor = m->creds;
    else
        ret = ENOENT;
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    return ret;
}

static krb5_error_code KRB5_CALLCONV
mcc_get_next (krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    krb5_mcache *m = MCACHE(id);
    struct link *l;
    krb5_error_code ret;

    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));
    if (MISDEAD(m)) {
	if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
	return ENOENT;
    }

    l = *cursor;
    if (l != NULL) {
	*cursor = l->next;
	ret = krb5_copy_creds_contents (context,
					&l->cred,
					creds);
    } else
	ret = KRB5_CC_END;

    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    return ret;
}

static krb5_error_code KRB5_CALLCONV
mcc_end_get (krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor)
{
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_remove_cred(krb5_context context,
		 krb5_ccache id,
		 krb5_flags which,
		 krb5_creds *mcreds)
{
    krb5_mcache *m = MCACHE(id);
    struct link **q, *p;

    if (!m->anonymous) HEIMDAL_MUTEX_lock(&(m->mutex));

    for(q = &m->creds, p = *q; p; p = *q) {
	if(krb5_compare_creds(context, which, mcreds, &p->cred)) {
	    *q = p->next;
	    krb5_free_cred_contents(context, &p->cred);
	    free(p);
	    m->mtime = time(NULL);
	} else
	    q = &p->next;
    }
    if (!m->anonymous) HEIMDAL_MUTEX_unlock(&(m->mutex));
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_set_flags(krb5_context context,
	      krb5_ccache id,
	      krb5_flags flags)
{
    return 0; /* XXX */
}

struct mcache_iter {
    krb5_mcache *cache;
};

static krb5_error_code KRB5_CALLCONV
mcc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct mcache_iter *iter;

    iter = calloc(1, sizeof(*iter));
    if (iter == NULL)
	return krb5_enomem(context);

    HEIMDAL_MUTEX_lock(&mcc_mutex);
    iter->cache = mcc_head;
    if (iter->cache) {
	HEIMDAL_MUTEX_lock(&(iter->cache->mutex));
	iter->cache->refcnt++;
	HEIMDAL_MUTEX_unlock(&(iter->cache->mutex));
    }
    HEIMDAL_MUTEX_unlock(&mcc_mutex);

    *cursor = iter;
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_get_cache_next(krb5_context context, krb5_cc_cursor cursor, krb5_ccache *id)
{
    struct mcache_iter *iter = cursor;
    krb5_error_code ret;
    krb5_mcache *m;

    if (iter->cache == NULL)
	return KRB5_CC_END;

    ret = _krb5_cc_allocate(context, &krb5_mcc_ops, id);
    if (ret)
	return ret;

    HEIMDAL_MUTEX_lock(&mcc_mutex);
    m = iter->cache;
    if (m->next)
    {
    	HEIMDAL_MUTEX_lock(&(m->next->mutex));
    	m->next->refcnt++;
    	HEIMDAL_MUTEX_unlock(&(m->next->mutex));
    }

    iter->cache = m->next;
    HEIMDAL_MUTEX_unlock(&mcc_mutex);

    (*id)->data.data = m;
    (*id)->data.length = sizeof(*m);

    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct mcache_iter *iter = cursor;

    if (iter->cache) {
        if (mcc_close_internal(iter->cache)) {
            HEIMDAL_MUTEX_destroy(&(iter->cache->mutex));
            free(iter->cache);
        }
    }
    free(iter);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_mcache *mfrom = MCACHE(from), *mto = MCACHE(to);
    struct link *creds;
    krb5_principal principal;

    if (!mfrom->anonymous) {
        /* drop the from cache from the linked list to avoid lookups */
        krb5_mcache **n;
        HEIMDAL_MUTEX_lock(&mcc_mutex);
        for(n = &mcc_head; n && *n; n = &(*n)->next) {
            if(mfrom == *n) {
                *n = mfrom->next;
                mfrom->next = NULL;
                break;
            }
        }
        HEIMDAL_MUTEX_unlock(&mcc_mutex);

        HEIMDAL_MUTEX_lock(&(mfrom->mutex));
    }

    if (!mto->anonymous)   HEIMDAL_MUTEX_lock(&(mto->mutex));
    /* swap creds */
    creds = mto->creds;
    mto->creds = mfrom->creds;
    mfrom->creds = creds;
    /* swap principal */
    principal = mto->primary_principal;
    mto->primary_principal = mfrom->primary_principal;
    mfrom->primary_principal = principal;

    mto->mtime = mfrom->mtime = time(NULL);

    if (!mfrom->anonymous) HEIMDAL_MUTEX_unlock(&(mfrom->mutex));
    if (!mto->anonymous)   HEIMDAL_MUTEX_unlock(&(mto->mutex));

    krb5_cc_destroy(context, from);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_default_name(krb5_context context, char **str)
{
    *str = strdup("MEMORY:");
    if (*str == NULL)
	return krb5_enomem(context);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_lastchange(krb5_context context, krb5_ccache id, krb5_timestamp *mtime)
{
    krb5_mcache *m = MCACHE(id);
    HEIMDAL_MUTEX_lock(&(m->mutex));
    *mtime = m->mtime;
    HEIMDAL_MUTEX_unlock(&(m->mutex));
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_set_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat kdc_offset)
{
    krb5_mcache *m = MCACHE(id);
    HEIMDAL_MUTEX_lock(&(m->mutex));
    m->kdc_offset = kdc_offset;
    HEIMDAL_MUTEX_unlock(&(m->mutex));
    return 0;
}

static krb5_error_code KRB5_CALLCONV
mcc_get_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat *kdc_offset)
{
    krb5_mcache *m = MCACHE(id);
    HEIMDAL_MUTEX_lock(&(m->mutex));
    *kdc_offset = m->kdc_offset;
    HEIMDAL_MUTEX_unlock(&(m->mutex));
    return 0;
}


/**
 * Variable containing the MEMORY based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_VARIABLE const krb5_cc_ops krb5_mcc_ops = {
    KRB5_CC_OPS_VERSION,
    "MEMORY",
    mcc_get_name,
    mcc_resolve,
    mcc_gen_new,
    mcc_initialize,
    mcc_destroy,
    mcc_close,
    mcc_store_cred,
    NULL, /* mcc_retrieve */
    mcc_get_principal,
    mcc_get_first,
    mcc_get_next,
    mcc_end_get,
    mcc_remove_cred,
    mcc_set_flags,
    NULL,
    mcc_get_cache_first,
    mcc_get_cache_next,
    mcc_end_cache_get,
    mcc_move,
    mcc_default_name,
    NULL,
    mcc_lastchange,
    mcc_set_kdc_offset,
    mcc_get_kdc_offset
};
