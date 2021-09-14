package test.es.gob.jmulticard.asn1;

import org.junit.Assert;
import org.junit.Test;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.BitString;
import es.gob.jmulticard.asn1.der.Utf8String;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.AccessFlags;

/** Prueba del tipos simples ASN&#46;1. */
public final class TestAsn1SimpleTypes {

	private static final byte[] SAMPLE_DIGEST_INFO = {
		(byte)0x30, (byte)0x21, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x05, (byte)0x2B, (byte)0x0E,
		(byte)0x03, (byte)0x02, (byte)0x1A, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x14, (byte)0x90,
		(byte)0xA8, (byte)0x3D, (byte)0x18, (byte)0xEB, (byte)0xD9, (byte)0xCD, (byte)0x0B, (byte)0xF2,
		(byte)0x56, (byte)0x1C, (byte)0x31, (byte)0x5C, (byte)0x34, (byte)0x79, (byte)0xE0, (byte)0xE7,
		(byte)0xAC, (byte)0xD4, (byte)0x4D, (byte)0x00
	};

	/** Prueba de creaci&oacute;n de <code>DigestInfo</code> de PKCS#1.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testDigestInfoCreation() throws Exception {
		final DigestInfo di = new DigestInfo();
		di.setDerValue(SAMPLE_DIGEST_INFO);
		System.out.println(di);
	}

	/** Prueba la creaci&oacute; de un tipo <code>UTF8String</code> con datos incorrectos.
	 * @throws TlvException Si no se puede crear el TLV. */
	@Test
	@SuppressWarnings("static-method")
    public void testUtf8StringCreationWithBadData() throws TlvException {
		final Utf8String u = new Utf8String();
		try {
			u.setDerValue(new byte[] { (byte)0x00, (byte) 0x01, (byte) 0xff});
		}
		catch(final Asn1Exception e) {
			System.out.println("Fallo esperado: " + e); //$NON-NLS-1$
			return;
		}
		Assert.fail("Tendria que haber saltado un Asn1Exception"); //$NON-NLS-1$
	}

	/** Prueba la creaci&oacute; de un tipo <code>BitString</code> con datos incorrectos.
	 * @throws TlvException Si no se puede crear el TLV. */
	@Test
	@SuppressWarnings("static-method")
    public void testBitStringCreationWithBadData() throws TlvException {
		final BitString u = new AccessFlags();
		try {
			u.setDerValue(new byte[] { (byte)0x00, (byte) 0x01, (byte) 0xff});
		}
		catch(final Asn1Exception e) {
			System.out.println("Fallo esperado: " + e); //$NON-NLS-1$
			return;
		}
		Assert.fail("Tendria que haber saltado un Asn1Exception"); //$NON-NLS-1$
	}

}
