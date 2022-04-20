package test.es.gob.jmulticard.asn1.der;


import org.junit.Assert;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.DerBoolean;
import junit.framework.TestCase;

/** @author Alberto Mart&iacute;nez */
public class TestDerBoolean extends TestCase {

    /** Test method for {@link es.gob.jmulticard.asn1.DecoderObject#setDerValue(byte[])}. */
    public final static void testSetDerValueWithNullArgumentMustGenerateIllegalArgumentException() {
        final DerBoolean db = new DerBoolean();
        try {
            db.setDerValue(null);
        }
        catch (final Exception e) {
            if (!(e instanceof IllegalArgumentException)) {
                Assert.fail("Se esperaba " + IllegalArgumentException.class.getName() + " pero se obtuvo " + e.getClass().getName()); //$NON-NLS-1$ //$NON-NLS-2$
            }
        }
    }

    /** Test method for {@link es.gob.jmulticard.asn1.DecoderObject#getBytes()}.
     * @throws TlvException Si no se puede crear el TLV.
     * @throws Asn1Exception Si falla la creaci&oacute;n del tipo ASN1. */
    public final static void testGetBytes() throws Asn1Exception, TlvException {
        final DerBoolean db = new DerBoolean();
        db.setDerValue(new byte[] {
                (byte) 0x01, (byte) 0x01, (byte) 0x00
        });
        Assert.assertEquals(
    		"010100", //$NON-NLS-1$
    		HexUtils.hexify(db.getBytes(), false),
    		"Se esperaba '010100' y se ha obtenido '" + HexUtils.hexify(db.getBytes(), false) + "'" //$NON-NLS-1$ //$NON-NLS-2$
		);
    }

    /** Test method for {@link es.gob.jmulticard.asn1.DecoderObject#checkTag(byte)}. */
    public final static void testCheckTagWithWrongTagMustThrowException() {
        try {
            final DerBoolean db = new DerBoolean();
            db.checkTag((byte) 0x02);
        }
        catch(final Asn1Exception e) {
        	System.out.println("Todo normal, ha saltado " + e); //$NON-NLS-1$
        }
        catch(final Exception e) {
            Assert.fail("Se esperaba " + Asn1Exception.class.getName() + " pero se obtuvo " + e.getClass().getName()); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }
}