package es.gob.jmulticard.asn1.der;

import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;

/** Tipo nulo.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
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
	public void setDerValue(final byte[] value) throws Asn1Exception,
	                                                   TlvException {
    	if (value == null || value.length == 0) {
    		super.setDerValue(new byte[0]);
    	}
    	else {
    		JmcLogger.warning("Se ha proporcionado datos a un tipo nulo, estos se ignoraran"); //$NON-NLS-1$
    	}
    }

    @Override
	public void checkTag(final byte tag) {
    	// No hacemos nada
    }
}
