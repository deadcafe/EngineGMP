/*
 *	Copyright (C) 2010, deadcafe.beef@gmail.com
 *	All rights reserved.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/bn.h>

#define E_DEADCAFE_LIB_NAME "deadcafe engine"
#include "deadcafe_err.c"

static int deadcafe_destroy(ENGINE *e);
static int deadcafe_init(ENGINE *e);
static int deadcafe_finish(ENGINE *e);
static int deadcafe_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));

static inline int
bn2gmp(const BIGNUM *bn,
       mpz_t g)
{
	int ret = 0;

	bn_check_top(bn);
	if (((sizeof(bn->d[0]) * 8) == GMP_NUMB_BITS) &&
	    (BN_BITS2 == GMP_NUMB_BITS)) {
		if (_mpz_realloc(g, bn->top)) {
			memcpy(&g->_mp_d[0], &bn->d[0],
			       bn->top * sizeof(bn->d[0]));
			g->_mp_size = bn->top;
			if (bn->neg)
				g->_mp_size = -g->_mp_size;
			ret = 1;
		}
	} else {
		char *tmp = BN_bn2hex(bn);

		if (tmp) {
			ret = (mpz_set_str(g, tmp, 16) == 0 ? 1 : 0);
			OPENSSL_free(tmp);
		}
	}
	return ret;
}

static inline int
gmp2bn(const mpz_t g,
       BIGNUM *bn)
{
	int ret = 0;

	if (((sizeof(bn->d[0]) * 8) == GMP_NUMB_BITS) &&
	    (BN_BITS2 == GMP_NUMB_BITS)) {
		int s;

		if (g->_mp_size >= 0)
			s = g->_mp_size;
		else
			s = -(g->_mp_size);

		BN_zero(bn);
		if (bn_expand2(bn, s)) {
			bn->top = s;
			memcpy(&bn->d[0], &g->_mp_d[0], s * sizeof(bn->d[0]));
			bn_correct_top(bn);
			if (g->_mp_size >= 0)
				bn->neg = 0;
			else
				bn->neg = 1;
			ret = 1;
		}
	} else {
		char *tmp = OPENSSL_malloc(mpz_sizeinbase(g, 16) + 10);

		if (tmp) {
			mpz_get_str(tmp, 16, g);
			ret = BN_hex2bn(&bn, tmp);
			OPENSSL_free(tmp);
		}
	}
	return ret;
}

static int
deadcafe_bn_mod_exp(BIGNUM *r,
		    const BIGNUM *a,
		    const BIGNUM *p,
		    const BIGNUM *m)
{
	mpz_t rop;
	mpz_t base;
	mpz_t exp;
	mpz_t mod;
	int ret = 0;

	mpz_init(rop);
	mpz_init(base);
	mpz_init(exp);
	mpz_init(mod);

	if (!bn2gmp(a, base))
		goto end;
	if (!bn2gmp(p, exp))
		goto end;
	if (!bn2gmp(m, mod))
		goto end;

	mpz_powm(rop, base, exp, mod);
	if (gmp2bn(rop, r))
		ret = 1;
end:
	mpz_clear(rop);
	mpz_clear(base);
	mpz_clear(exp);
	mpz_clear(mod);
	return ret;
}

/*****************************************************************************
 *	RSA stuff
 *****************************************************************************/
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>

#define	BIND_RSA(e_)	bind_rsa((e_))
#define	INIT_RSA()	init_rsa()

static int
deadcafe_rsa_bn_mod_exp(BIGNUM *r,
		     const BIGNUM *a,
		     const BIGNUM *p,
		     const BIGNUM *m,
		     BN_CTX *ctx __attribute__((unused)),
		     BN_MONT_CTX *m_ctx __attribute__((unused)))
{
	return deadcafe_bn_mod_exp(r, a, p, m);
}

static RSA_METHOD deadcafe_rsa;

static inline int
bind_rsa(ENGINE *e)
{
	memcpy(&deadcafe_rsa, RSA_PKCS1_SSLeay(), sizeof(deadcafe_rsa));
	deadcafe_rsa.name = "DC DEADCAFE RSA method";
	deadcafe_rsa.bn_mod_exp = deadcafe_rsa_bn_mod_exp;

	return ENGINE_set_RSA(e, &deadcafe_rsa);
}

static int hndidx_rsa = -1;

static inline int
init_rsa(void)
{
	if (hndidx_rsa == -1)
		hndidx_rsa = RSA_get_ex_new_index(0,
						  "DC GMP-based RSA key handle",
						  NULL, NULL, NULL);
	if (hndidx_rsa == -1)
		return 0;
	return 1;
}
#else	/* !OPENSSL_NO_RSA */
#define	BIND_RSA(e_)	true
#define	INIT_RSA()	true
#endif	/* OPENSSL_NO_RSA */

/*****************************************************************************
 *	DSA stuff
 *****************************************************************************/
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>

#define	BIND_DSA(e_)	bind_dsa((e_))
#define	INIT_DSA(e_)	init_dsa()

static int
deadcafe_dsa_bn_mod_exp(DSA *dsa __attribute__((unused)),
		     BIGNUM *r,
		     BIGNUM *a,
		     const BIGNUM *p,
		     const BIGNUM *m,
		     BN_CTX *ctx __attribute__((unused)),
		     BN_MONT_CTX *m_ctx __attribute__((unused)))
{
	return deadcafe_bn_mod_exp(r, a, p, m);
}

static DSA_METHOD deadcafe_dsa;

static inline int
bind_dsa(ENGINE *e)
{
	memcpy(&deadcafe_dsa, DSA_OpenSSL(), sizeof(deadcafe_dsa));
	deadcafe_dsa.name = "DC DEADCAFE DSA method";
	deadcafe_dsa.bn_mod_exp = deadcafe_dsa_bn_mod_exp;

	return ENGINE_set_DSA(e, &deadcafe_dsa);
}

static int hndidx_dsa = -1;

static inline int
init_dsa(void)
{
	if (hndidx_dsa == -1)
		hndidx_dsa = DSA_get_ex_new_index(0,
						  "DC GMP-based DSA key handle",
						  NULL, NULL, NULL);
	if (hndidx_dsa == -1)
		return 0;
	return 1;
}
#else	/* !OPENSSL_NO_DSA */
#define	BIND_DSA(e_)	true
#define	INIT_DSA(e_)	true
#endif	/* OPENSSL_NO_DSA */

/*****************************************************************************
 *	DH stuff
 *****************************************************************************/
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>

#define	BIND_DH(e_)	bind_dh((e_))
#define	INIT_DH()	init_dh()

static int
deadcafe_dh_bn_mod_exp(const DH *dh __attribute__((unused)),
		    BIGNUM *r,
		    const BIGNUM *a,
		    const BIGNUM *p,
		    const BIGNUM *m,
		    BN_CTX *ctx __attribute__((unused)),
		    BN_MONT_CTX *m_ctx __attribute__((unused)))
{
	return deadcafe_bn_mod_exp(r, a, p, m);
}

static DH_METHOD deadcafe_dh;

static inline int
bind_dh(ENGINE *e)
{
	memcpy(&deadcafe_dh, DH_OpenSSL(), sizeof(deadcafe_dh));
	deadcafe_dh.name = "DC DEADCAFE DH method";
	deadcafe_dh.bn_mod_exp = deadcafe_dh_bn_mod_exp;

	return ENGINE_set_DH(e, &deadcafe_dh);
}

static int hndidx_dh = -1;

static inline int
init_dh(void)
{
	if (hndidx_dh == -1)
		hndidx_dh = DH_get_ex_new_index(0,
						"DC GMP-based DH key handle",
						NULL, NULL, NULL);
	if (hndidx_dh == -1)
		return 0;
	return 1;
}
#else	/* !OPENSSL_NO_DH */
#define	BIND_DH(e_)	true
#define	INIT_DH()	true
#endif	/* OPENSSL_NO_DH */

/*****************************************************************************
 *	DEADCAFE framwork
 *****************************************************************************/
static const ENGINE_CMD_DEFN deadcafe_cmd_defns[] = {
	{
		0,
		NULL,
		NULL,
		0
	}
};

static const char *engine_deadcafe_id = "deadcafe";
static const char *engine_deadcafe_name = "DC-GMP engine support";

static int
bind_helper(ENGINE *e)
{
	if (!ENGINE_set_id(e, engine_deadcafe_id) ||
	    !ENGINE_set_name(e, engine_deadcafe_name) ||
	    !ENGINE_set_destroy_function(e, deadcafe_destroy) ||
	    !ENGINE_set_init_function(e, deadcafe_init) ||
	    !ENGINE_set_finish_function(e, deadcafe_finish) ||
	    !ENGINE_set_ctrl_function(e, deadcafe_ctrl) ||
	    !ENGINE_set_cmd_defns(e, deadcafe_cmd_defns))
		return 0;

	if (!BIND_RSA(e) || !BIND_DSA(e) || !BIND_DH(e))
		return 0;

	ERR_load_DEADCAFE_strings();
	return 1;
}

static inline ENGINE *
engine_deadcafe(void)
{
	ENGINE *ret = ENGINE_new();

	if (ret) {
		if (!bind_helper(ret)) {
			ENGINE_free(ret);
			ret = NULL;
		}
	}
	return ret;
}

#ifdef ENGINE_DYNAMIC_SUPPORT
static inline
#endif
void
ENGINE_load_deadcafe(void)
{
	ENGINE *e = engine_deadcafe();

	if (e) {
		ENGINE_add(e);
		ENGINE_free(e);
		ERR_clear_error();
	}
}

static int
deadcafe_destroy(ENGINE *e __attribute__((unused)))
{
	ERR_unload_DEADCAFE_strings();
	return 1;
}

static int
deadcafe_init(ENGINE *e __attribute__((unused)))
{
	if (!INIT_RSA() || !INIT_DSA() || !INIT_DH())
		return 0;
	return 1;
}

static int
deadcafe_finish(ENGINE *e __attribute__((unused)))
{
	return 1;
}

static int
deadcafe_ctrl(ENGINE *e __attribute__((unused)),
	      int cmd,
	      long i __attribute__((unused)),
	      void *p __attribute__((unused)),
	      void (*f)(void) __attribute__((unused)))
{
	int ret = 1;

	switch (cmd) {
	default:
		DEADCAFEerr(DEADCAFE_F_E_DEADCAFE_CTRL,
			    DEADCAFE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
		ret = 0;
		break;
	}
	return ret;
}

#ifdef ENGINE_DYNAMIC_SUPPORT
static int
bind_fn(ENGINE *e,
	const char *id)
{
	if (id && (strcmp(id, engine_deadcafe_id) != 0))
		return 0;
	if (!bind_helper(e))
		return 0;
	return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif	/* ENGINE_DYNAMIC_SUPPORT */
