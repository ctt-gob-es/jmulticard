package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;

public abstract class BaseAgreementSpi
    extends KeyAgreementSpi
{
    private static final Map<String, ASN1ObjectIdentifier> defaultOids = new HashMap<>();
    private static final Map<String, Integer> keySizes = new HashMap<>();
    private static final Map<String, String> nameTable = new HashMap<>();

    private static final Hashtable oids = new Hashtable();
    private static final Hashtable des = new Hashtable();

    static
    {
        final Integer i64 = Integers.valueOf(64);
        final Integer i128 = Integers.valueOf(128);
        final Integer i192 = Integers.valueOf(192);
        final Integer i256 = Integers.valueOf(256);

        keySizes.put("DES", i64); //$NON-NLS-1$
        keySizes.put("DESEDE", i192); //$NON-NLS-1$
        keySizes.put("BLOWFISH", i128); //$NON-NLS-1$
        keySizes.put("AES", i256); //$NON-NLS-1$

        keySizes.put(NISTObjectIdentifiers.id_aes128_ECB.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_ECB.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_ECB.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_CFB.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CFB.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CFB.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_OFB.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_OFB.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_OFB.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_wrap.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_wrap.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_CCM.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_CCM.getId(), i256);
        keySizes.put(NISTObjectIdentifiers.id_aes128_GCM.getId(), i128);
        keySizes.put(NISTObjectIdentifiers.id_aes192_GCM.getId(), i192);
        keySizes.put(NISTObjectIdentifiers.id_aes256_GCM.getId(), i256);
        keySizes.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), i128);
        keySizes.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), i192);
        keySizes.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), i256);
        keySizes.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId(), i128);

        keySizes.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), i192);
        keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), i192);
        keySizes.put(OIWObjectIdentifiers.desCBC.getId(), i64);

        keySizes.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), i256);
        keySizes.put(CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.getId(), i256);
        keySizes.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.getId(), i256);

        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), Integers.valueOf(160));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), i256);
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), Integers.valueOf(384));
        keySizes.put(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), Integers.valueOf(512));

        defaultOids.put("DESEDE", PKCSObjectIdentifiers.des_EDE3_CBC); //$NON-NLS-1$
        defaultOids.put("AES", NISTObjectIdentifiers.id_aes256_CBC); //$NON-NLS-1$
        defaultOids.put("CAMELLIA", NTTObjectIdentifiers.id_camellia256_cbc); //$NON-NLS-1$
        defaultOids.put("SEED", KISAObjectIdentifiers.id_seedCBC); //$NON-NLS-1$
        defaultOids.put("DES", OIWObjectIdentifiers.desCBC); //$NON-NLS-1$

        nameTable.put(MiscObjectIdentifiers.cast5CBC.getId(), "CAST5"); //$NON-NLS-1$
        nameTable.put(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.getId(), "IDEA"); //$NON-NLS-1$
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB.getId(), "Blowfish"); //$NON-NLS-1$
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC.getId(), "Blowfish"); //$NON-NLS-1$
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CFB.getId(), "Blowfish"); //$NON-NLS-1$
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_OFB.getId(), "Blowfish"); //$NON-NLS-1$
        nameTable.put(OIWObjectIdentifiers.desECB.getId(), "DES"); //$NON-NLS-1$
        nameTable.put(OIWObjectIdentifiers.desCBC.getId(), "DES"); //$NON-NLS-1$
        nameTable.put(OIWObjectIdentifiers.desCFB.getId(), "DES"); //$NON-NLS-1$
        nameTable.put(OIWObjectIdentifiers.desOFB.getId(), "DES"); //$NON-NLS-1$
        nameTable.put(OIWObjectIdentifiers.desEDE.getId(), "DESede"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), "DESede"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), "DESede"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_alg_CMSRC2wrap.getId(), "RC2"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), "HmacSHA1"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA224.getId(), "HmacSHA224"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), "HmacSHA256"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), "HmacSHA384"); //$NON-NLS-1$
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), "HmacSHA512"); //$NON-NLS-1$
        nameTable.put(NTTObjectIdentifiers.id_camellia128_cbc.getId(), "Camellia"); //$NON-NLS-1$
        nameTable.put(NTTObjectIdentifiers.id_camellia192_cbc.getId(), "Camellia"); //$NON-NLS-1$
        nameTable.put(NTTObjectIdentifiers.id_camellia256_cbc.getId(), "Camellia"); //$NON-NLS-1$
        nameTable.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), "Camellia"); //$NON-NLS-1$
        nameTable.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), "Camellia"); //$NON-NLS-1$
        nameTable.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), "Camellia"); //$NON-NLS-1$
        nameTable.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId(), "SEED"); //$NON-NLS-1$
        nameTable.put(KISAObjectIdentifiers.id_seedCBC.getId(), "SEED"); //$NON-NLS-1$
        nameTable.put(KISAObjectIdentifiers.id_seedMAC.getId(), "SEED"); //$NON-NLS-1$
        nameTable.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), "GOST28147"); //$NON-NLS-1$

        nameTable.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), "AES"); //$NON-NLS-1$
        nameTable.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), "AES"); //$NON-NLS-1$
        nameTable.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), "AES"); //$NON-NLS-1$

        oids.put("DESEDE", PKCSObjectIdentifiers.des_EDE3_CBC); //$NON-NLS-1$
        oids.put("AES", NISTObjectIdentifiers.id_aes256_CBC); //$NON-NLS-1$
        oids.put("DES", OIWObjectIdentifiers.desCBC); //$NON-NLS-1$

        des.put("DES", "DES"); //$NON-NLS-1$ //$NON-NLS-2$
        des.put("DESEDE", "DES"); //$NON-NLS-1$ //$NON-NLS-2$
        des.put(OIWObjectIdentifiers.desCBC.getId(), "DES"); //$NON-NLS-1$
        des.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), "DES"); //$NON-NLS-1$
        des.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), "DES"); //$NON-NLS-1$
    }

    protected final String kaAlgorithm;
    protected final DerivationFunction kdf;

    protected byte[]     ukmParameters;
    private HybridValueParameterSpec hybridSpec;

    public BaseAgreementSpi(final String kaAlgorithm, final DerivationFunction kdf)
    {
        this.kaAlgorithm = kaAlgorithm;
        this.kdf = kdf;
    }

    protected static String getAlgorithm(final String algDetails)
    {
        if (algDetails.indexOf('[') > 0)
        {
            return algDetails.substring(0, algDetails.indexOf('['));
        }

        if (algDetails.startsWith(NISTObjectIdentifiers.aes.getId()))
        {
            return "AES"; //$NON-NLS-1$
        }
        if (algDetails.startsWith(GNUObjectIdentifiers.Serpent.getId()))
        {
            return "Serpent"; //$NON-NLS-1$
        }

        final String name = nameTable.get(Strings.toUpperCase(algDetails));

        if (name != null)
        {
            return name;
        }

        return algDetails;
    }

    protected static int getKeySize(final String algDetails)
    {
        if (algDetails.indexOf('[') > 0)
        {
            return Integer.parseInt(algDetails.substring(algDetails.indexOf('[') + 1, algDetails.indexOf(']')));
        }

        final String algKey = Strings.toUpperCase(algDetails);
        if (!keySizes.containsKey(algKey))
        {
            return -1;
        }

        return keySizes.get(algKey).intValue();
    }

    protected static byte[] trimZeroes(final byte[] secret)
    {
        if (secret[0] != 0)
        {
            return secret;
        }
        else
        {
            int ind = 0;
            while (ind < secret.length && secret[ind] == 0)
            {
                ind++;
            }

            final byte[] rv = new byte[secret.length - ind];

            System.arraycopy(secret, ind, rv, 0, rv.length);

            return rv;
        }
    }

    @Override
	protected void engineInit(
        final Key             key,
        final SecureRandom    random)
        throws InvalidKeyException
    {
        try
        {
            doInitFromKey(key, null, random);
        }
        catch (final InvalidAlgorithmParameterException e)
        {
            // this should never occur.
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
	protected void engineInit(
        final Key key,
        final AlgorithmParameterSpec params,
        final SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params instanceof HybridValueParameterSpec)
        {
            hybridSpec = (HybridValueParameterSpec)params;
            doInitFromKey(key, hybridSpec.getBaseParameterSpec(), random);
        }
        else
        {
            hybridSpec = null;
            doInitFromKey(key, params, random);
        }
    }

    @Override
	protected byte[] engineGenerateSecret()
        throws IllegalStateException
    {
        if (kdf != null)
        {
            final byte[] secret = calcSecret();
            try
            {
                return getSharedSecretBytes(secret, null, secret.length * 8);
            }
            catch (final NoSuchAlgorithmException e)
            {
                throw new IllegalStateException(e.getMessage());
            }
        }

        return calcSecret();
    }

    @Override
	protected int engineGenerateSecret(
        final byte[]  sharedSecret,
        final int     offset)
        throws IllegalStateException, ShortBufferException
    {
        final byte[] secret = engineGenerateSecret();

        if (sharedSecret.length - offset < secret.length)
        {
            throw new ShortBufferException(kaAlgorithm + " key agreement: need " + secret.length + " bytes"); //$NON-NLS-1$ //$NON-NLS-2$
        }

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;
    }

    @Override
	protected SecretKey engineGenerateSecret(
        final String algorithm)
        throws NoSuchAlgorithmException
    {
        final String algKey = Strings.toUpperCase(algorithm);
        String oidAlgorithm = algorithm;

        if (oids.containsKey(algKey))
        {
            oidAlgorithm = ((ASN1ObjectIdentifier)oids.get(algKey)).getId();
        }

        final int    keySize = getKeySize(oidAlgorithm);

        final byte[] secret = getSharedSecretBytes(calcSecret(), oidAlgorithm, keySize);

        final String algName = getAlgorithm(algorithm);

        if (des.containsKey(algName))
        {
            DESParameters.setOddParity(secret);
        }

        return new SecretKeySpec(secret, algName);
    }

    private byte[] getSharedSecretBytes(final byte[] secret, final String oidAlgorithm, final int keySize)
        throws NoSuchAlgorithmException
    {
        if (kdf != null)
        {
            if (keySize < 0)
            {
                throw new NoSuchAlgorithmException("unknown algorithm encountered: " + oidAlgorithm); //$NON-NLS-1$
            }
            final byte[] keyBytes = new byte[keySize / 8];

            if (kdf instanceof DHKEKGenerator)
            {
                if (oidAlgorithm == null)
                {
                    throw new NoSuchAlgorithmException("algorithm OID is null"); //$NON-NLS-1$
                }
                ASN1ObjectIdentifier oid;
                try
                {
                    oid = new ASN1ObjectIdentifier(oidAlgorithm);
                }
                catch (final IllegalArgumentException e)
                {
                    throw new NoSuchAlgorithmException("no OID for algorithm: " + oidAlgorithm); //$NON-NLS-1$
                }
                final DHKDFParameters params = new DHKDFParameters(oid, keySize, secret, ukmParameters);

                kdf.init(params);
            }
            else
            {
                final KDFParameters params = new KDFParameters(secret, ukmParameters);

                kdf.init(params);
            }

            kdf.generateBytes(keyBytes, 0, keyBytes.length);

            Arrays.clear(secret);

            return keyBytes;
        }
        else
        {
            if (keySize > 0)
            {
                final byte[] keyBytes = new byte[keySize / 8];

                System.arraycopy(secret, 0, keyBytes, 0, keyBytes.length);

                Arrays.clear(secret);

                return keyBytes;
            }

            return secret;
        }
    }

    private byte[] calcSecret()
    {
        if (hybridSpec != null)
        {
            // Set Z' to Z || T
            final byte[] s = doCalcSecret();
            final byte[] sec = Arrays.concatenate(s, hybridSpec.getT());

            Arrays.clear(s);

            return sec;
        }
        else
        {
            return doCalcSecret();
        }
    }

    protected abstract byte[] doCalcSecret();

    protected abstract void doInitFromKey(Key key, AlgorithmParameterSpec parameterSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException;
}
