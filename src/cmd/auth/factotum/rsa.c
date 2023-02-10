#include "std.h"
#include "dat.h"

/*
 * RSA authentication.
 *
 * Encrypt/Decrypt:
 *	start n=xxx ek=xxx
 *	write msg
 *	read encrypt/decrypt(msg)
 *
 * Sign (PKCS #1 using hash=sha1, sha2x or hash=md5)
 *	start n=xxx ek=xxx
 *	write hash(msg)
 *	read signature(hash(msg))
 *
 * Verify:
 *	start n=xxx ek=xxx
 *	write hash(msg)
 *	write signature(hash(msg))
 *	read ok or fail
 *
 * all numbers are hexadecimal biginits parsable with strtomp.
 * must be lower case for attribute matching in start.
 */

static int
xrsadecrypt(Conv *c)
{
	char *txt, buf[16384], *role;
	int n, ret;
	mpint *m, *mm;
	Key *k;
	RSApriv *key;

	ret = -1;
	txt = nil;
	m = nil;
	mm = nil;

	/* fetch key */
	c->state = "keylookup";
	k = keylookup("%A", c->attr);
	if(k == nil)
		goto out;
	key = k->priv;

	/* make sure have private half if needed */
	role = strfindattr(c->attr, "role");
	if(strcmp(role, "decrypt") == 0 && !key->c2){
		werrstr("missing private half of key -- cannot decrypt");
		goto out;
	}

	/* read text */
	c->state = "read";
	if((n=convreadm(c, &txt)) < 0)
		goto out;
	if(n < 32){
		convprint(c, "data too short");
		goto out;
	}

	/* encrypt/decrypt */
	m = betomp((uchar*)txt, n, nil);
	if(m == nil)
		goto out;
	if(strcmp(role, "decrypt") == 0)
		mm = rsadecrypt(key, m, nil);
	else
		mm = rsaencrypt(&key->pub, m, nil);
	if(mm == nil)
		goto out;
	n = mptobe(mm, (uchar*)buf, sizeof buf, nil);

	/* send response */
	c->state = "write";
	convwrite(c, buf, n);
	ret = 0;

out:
	mpfree(m);
	mpfree(mm);
	keyclose(k);
	free(txt);
	return ret;
}

static int
xrsasign(Conv *c)
{
	char *hash, *role;
	int dlen, n, ret;
	DigestAlg *hashfn;
	Key *k;
	RSApriv *key;
	uchar sig[16384], digest[256];
	char *sig2;

	ret = -1;

	/* fetch key */
	c->state = "keylookup";
	k = keylookup("%A", c->attr);
	if(k == nil)
		return ret;

	/* make sure have private half if needed */
	key = k->priv;
	role = strfindattr(c->attr, "role");
	if(strcmp(role, "sign") == 0 && !key->c2){
		keyclose(k);
		werrstr("missing private half of key -- cannot sign");
		return ret;
	}

	/* get hash type from key */
	// Awkward...
	// sha1 - obsolete
	// sha2_256
	// sha2_512
	// md5 and md2 (deprecated?)
	hash = strfindattr(k->attr, "hash");
fprint(2, "hash: %s\n", hash ? hash : "nil");
	if(hash == nil)
		hash = "sha1";
	if(strcmp(hash, "sha1") == 0){
		hashfn = sha1;
		dlen = SHA1dlen;
	}else if(strncmp(hash, "rsa-sha2-", 8) == 0){
		char *hlen = strdup(hash + 8);

		if (*hlen == '\0')
			hlen = "512";
		switch(atoi(hlen)){
		default:
			werrstr("unknown SHA2 hash length %s", hlen);
			goto out;
		case 224:
			dlen = SHA2_224dlen;
			hashfn = sha2_224;
			break;
		case 256:
			dlen = SHA2_256dlen;
			hashfn = sha2_256;
			break;
		case 384:
			dlen = SHA2_384dlen;
			hashfn = sha2_384;
			break;
		case 512:
			dlen = SHA2_512dlen;
			hashfn = sha2_512;
			break;
		}
	}else if(strcmp(hash, "md5") == 0){
		hashfn = md5;
		dlen = MD5dlen;
	}else{
		werrstr("unknown hash function %s", hash);
		goto out;
	}

	/* read hash */
	c->state = "read hash";
fprint(2, "readconv(%s - %d\n", c->state, dlen);
	if((n=convread(c, digest, dlen)) < 0)
		goto out;

	if(strcmp(role, "sign") == 0){
		/* sign */
		if((n=rsasign(key, hashfn, digest, dlen, sig, sizeof sig)) < 0)
			goto out;

		/* write */
		convwrite(c, sig, n);
	}else{
		/* read signature */
		if((n = convreadm(c, &sig2)) < 0)
			goto out;

		/* verify */
		if(rsaverify(&key->pub, hashfn, digest, dlen, (uchar*)sig2, n) == 0)
			convprint(c, "ok");
		else
			convprint(c, "signature does not verify");
		free(sig2);
	}
	ret = 0;

out:
	keyclose(k);
	return ret;
}

/*
 * convert to canonical form (lower case)
 * for use in attribute matches.
 */
static void
strlwr(char *a)
{
	for(; *a; a++){
		if('A' <= *a && *a <= 'Z')
			*a += 'a' - 'A';
	}
}

static RSApriv*
readrsapriv(Key *k)
{
	char *a;
	RSApriv *priv;

	priv = rsaprivalloc();

	if((a=strfindattr(k->attr, "ek"))==nil
	|| (priv->pub.ek=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if((a=strfindattr(k->attr, "n"))==nil
	|| (priv->pub.n=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if(k->privattr == nil)	/* only public half */
		return priv;

	if((a=strfindattr(k->privattr, "!p"))==nil
	|| (priv->p=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if((a=strfindattr(k->privattr, "!q"))==nil
	|| (priv->q=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if(!probably_prime(priv->p, 20) || !probably_prime(priv->q, 20)) {
		werrstr("rsa: p or q not prime");
		goto Error;
	}
	if((a=strfindattr(k->privattr, "!kp"))==nil
	|| (priv->kp=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if((a=strfindattr(k->privattr, "!kq"))==nil
	|| (priv->kq=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if((a=strfindattr(k->privattr, "!c2"))==nil
	|| (priv->c2=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	if((a=strfindattr(k->privattr, "!dk"))==nil
	|| (priv->dk=strtomp(a, nil, 16, nil))==nil)
		goto Error;
	strlwr(a);
	return priv;

Error:
	rsaprivfree(priv);
	return nil;
}

static int
rsacheck(Key *k)
{
	static int first = 1;

	if(first){
		fmtinstall('B', mpfmt);
		first = 0;
	}

	if((k->priv = readrsapriv(k)) == nil){
		werrstr("malformed key data");
		return -1;
	}
	return 0;
}

static void
rsaclose(Key *k)
{
	rsaprivfree(k->priv);
	k->priv = nil;
}

static Role
rsaroles[] =
{
	"sign", xrsasign,
	"verify",	xrsasign,	/* public operation */
	"decrypt",	xrsadecrypt,
	"encrypt",	xrsadecrypt,	/* public operation */
	0
};

Proto rsa = {
	"rsa",
	rsaroles,
	nil,
	rsacheck,
	rsaclose
};
