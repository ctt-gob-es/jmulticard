package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;

/** Tipo nulo.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Null extends DecoderObject {

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		// Vacio
	}

	@Override
	protected byte getDefaultTag() {
		return 0;
	}

    @Override
	public void setDerValue(final byte[] value) throws Asn1Exception, TlvException {
    	// Vacio
    }

    @Override
	protected byte[] getRawDerValue() {
        return new byte[0];
    }

    @Override
	public byte[] getBytes() {
        return new byte[0];
    }

    @Override
	public void checkTag(final byte tag) throws Asn1Exception {
    	// No hacemos nada
    }


}
