package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * XMSSOid class.
 */
public final class DefaultXMSSOid
    implements XMSSOid
{

    /**
     * XMSS OID lookup table.
     */
    private static final Map<String, DefaultXMSSOid> oidLookupTable;

    static
    {
        final Map<String, DefaultXMSSOid> map = new HashMap<>();
        map.put(createKey("SHA-256", 32, 16, 67, 10), new DefaultXMSSOid(0x00000001, "XMSS_SHA2_10_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 16), new DefaultXMSSOid(0x00000002, "XMSS_SHA2_16_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 20), new DefaultXMSSOid(0x00000003, "XMSS_SHA2_20_256"));
        map.put(createKey("SHA-512", 64, 16, 131, 10), new DefaultXMSSOid(0x00000004, "XMSS_SHA2_10_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 16), new DefaultXMSSOid(0x00000005, "XMSS_SHA2_16_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 20), new DefaultXMSSOid(0x00000006, "XMSS_SHA2_20_512"));
        map.put(createKey("SHAKE128", 32, 16, 67, 10), new DefaultXMSSOid(0x00000007, "XMSS_SHAKE_10_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 16), new DefaultXMSSOid(0x00000008, "XMSS_SHAKE_16_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 20), new DefaultXMSSOid(0x00000009, "XMSS_SHAKE_20_256"));
        map.put(createKey("SHAKE256", 64, 16, 131, 10), new DefaultXMSSOid(0x0000000a, "XMSS_SHAKE_10_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 16), new DefaultXMSSOid(0x0000000b, "XMSS_SHAKE_16_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 20), new DefaultXMSSOid(0x0000000c, "XMSS_SHAKE_20_512"));
        oidLookupTable = Collections.unmodifiableMap(map);
    }

    /**
     * OID.
     */
    private final int oid;
    /**
     * String representation of OID.
     */
    private final String stringRepresentation;

    /**
     * Constructor...
     *
     * @param oid                  OID.
     * @param stringRepresentation String representation of OID.
     */
    private DefaultXMSSOid(final int oid, final String stringRepresentation)
    {
        super();
        this.oid = oid;
        this.stringRepresentation = stringRepresentation;
    }

    /**
     * Lookup OID.
     *
     * @param algorithmName       Algorithm name.
     * @param digestSize	Digest size.
     * @param winternitzParameter Winternitz parameter.
     * @param len Length.
     * @param height              Binary tree height.
     * @return XMSS OID if parameters were found, null else.
     */
    public static DefaultXMSSOid lookup(final String algorithmName, final int digestSize, final int winternitzParameter, final int len,
                                        final int height)
    {
        if (algorithmName == null)
        {
            throw new NullPointerException("algorithmName == null");
        }
        return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height));
    }

    /**
     * Create a key based on parameters.
     *
     * @param algorithmName       Algorithm name.
     * @param digestSize	Digest size.
     * @param winternitzParameter Winternitz Parameter.
     * @param len Length.
     * @param height              Binary tree height.
     * @return String representation of parameters for lookup table.
     */
    private static String createKey(final String algorithmName, final int digestSize, final int winternitzParameter, final int len,
                                    final int height)
    {
        if (algorithmName == null)
        {
            throw new NullPointerException("algorithmName == null");
        }
        return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height;
    }

    /**
     * Getter OID.
     *
     * @return OID.
     */
    @Override
	public int getOid()
    {
        return this.oid;
    }

    @Override
    public String toString()
    {
        return this.stringRepresentation;
    }
}
