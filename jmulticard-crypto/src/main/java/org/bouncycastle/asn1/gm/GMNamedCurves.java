package org.bouncycastle.asn1.gm;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Chinese standard GM named curves.
 */
public class GMNamedCurves
{
    static X9ECPoint configureBasepoint(final ECCurve curve, final String encoding)
    {
        final X9ECPoint G = new X9ECPoint(curve, Hex.decodeStrict(encoding));
        WNafUtil.configureBasepoint(G.getPoint());
        return G;
    }

    static ECCurve configureCurve(final ECCurve curve)
    {
        return curve;
    }

    static BigInteger fromHex(final String hex)
    {
        return new BigInteger(1, Hex.decodeStrict(hex));
    }

    /*
     * SM2SysParams
     */
    static X9ECParametersHolder sm2p256v1 = new X9ECParametersHolder()
    {
        @Override
		protected ECCurve createCurve()
        {
            final BigInteger p = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"); //$NON-NLS-1$
            final BigInteger a = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"); //$NON-NLS-1$
            final BigInteger b = fromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"); //$NON-NLS-1$
            final BigInteger n = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"); //$NON-NLS-1$
            final BigInteger h = BigInteger.valueOf(1);

            return configureCurve(new ECCurve.Fp(p, a, b, n, h, true));
        }

        @Override
		protected X9ECParameters createParameters()
        {
            final byte[] S = null;
            final ECCurve curve = getCurve();

            final X9ECPoint G = configureBasepoint(curve,
                "0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"); //$NON-NLS-1$

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    static X9ECParametersHolder wapip192v1 = new X9ECParametersHolder()
    {
        @Override
		protected ECCurve createCurve()
        {
            final BigInteger p = fromHex("BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F"); //$NON-NLS-1$
            final BigInteger a = fromHex("BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985"); //$NON-NLS-1$
            final BigInteger b = fromHex("1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1"); //$NON-NLS-1$
            final BigInteger n = fromHex("BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677"); //$NON-NLS-1$
            final BigInteger h = BigInteger.valueOf(1);

            return configureCurve(new ECCurve.Fp(p, a, b, n, h, true));
        }

        @Override
		protected X9ECParameters createParameters()
        {
            final byte[] S = null;
            final ECCurve curve = getCurve();

            final X9ECPoint G = configureBasepoint(curve,
                "044AD5F7048DE709AD51236DE65E4D4B482C836DC6E410664002BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2"); //$NON-NLS-1$

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };


    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static void defineCurve(final String name, final ASN1ObjectIdentifier oid, final X9ECParametersHolder holder)
    {
        objIds.put(Strings.toLowerCase(name), oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    static
    {
        defineCurve("wapip192v1", GMObjectIdentifiers.wapip192v1, wapip192v1); //$NON-NLS-1$
        defineCurve("sm2p256v1", GMObjectIdentifiers.sm2p256v1, sm2p256v1); //$NON-NLS-1$
    }

    public static X9ECParameters getByName(final String name)
    {
        final ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOID(oid);
    }

    public static X9ECParametersHolder getByNameLazy(final String name)
    {
        final ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOIDLazy(oid);
    }

    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     * @return EC parameters.
     */
    public static X9ECParameters getByOID(final ASN1ObjectIdentifier oid)
    {
        final X9ECParametersHolder holder = getByOIDLazy(oid);
        return holder == null ? null : holder.getParameters();
    }

    public static X9ECParametersHolder getByOIDLazy(final ASN1ObjectIdentifier oid)
    {
        return (X9ECParametersHolder)curves.get(oid);
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     * @param name Object identifier anme.
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(
        final String name)
    {
        return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(name));
    }

    /**
     * @param oid Object identifier.
     * @return the named curve name represented by the given object identifier.
     */
    public static String getName(
        final ASN1ObjectIdentifier oid)
    {
        return (String)names.get(oid);
    }

    /**
     * @return an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static Enumeration getNames()
    {
        return names.elements();
    }
}

