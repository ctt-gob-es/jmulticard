package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.asn1.DecoderObject;

/** Tipo nulo.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Null extends DecoderObject {

	@Override
	protected void decodeValue() {
		// Vacio
	}

	@Override
	protected byte getDefaultTag() {
		return 0;
	}

    @Override
	public void setDerValue(final byte[] value) {
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
	public void checkTag(final byte tag) {
    	// No hacemos nada
    }


}
