package es.gob.jmulticard.card.icao;

import javax.security.auth.callback.CallbackHandler;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.DnieNFC;
import es.gob.jmulticard.card.pace.PaceException;

/** Pasaporte accedido de forma inal&aacute;mbrica mediante PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class IcaoMrtdWithPace extends DnieNFC {

	/** Construye una clase que representa un MRTD accedido de forma
	 * inal&aacute;mbrica mediante PACE.
	 * @param conn Conexi&oacute;n con el lector NFC.
	 * @param cryptoHelper Clase de utilidad de funciones criptogr&aacute;ficas.
	 * @param ch <code>CallbackHandler</code> que debe proporcionar, mediante un
	 *           <code>es.gob.jmulticard.callback.CustomTextInputCallback</code> o
	 *           un <code>javax.security.auth.callback.TextInputCallback</code> el
	 *           CAN o la MRZ del pasaporte.
	 * @throws PaceException Si no se puede establecer el canal PACE.
	 * @throws ApduConnectionException Si no se puede establecer la conexi&oacute;n NFC. */
	public IcaoMrtdWithPace(final ApduConnection conn,
			                       final CryptoHelper cryptoHelper,
			                       final CallbackHandler ch) throws PaceException,
	                                                                ApduConnectionException {
		super(
			conn,
			null,          // No hay PIN
			cryptoHelper,
			ch,            // CallbackHandler, debe proporcionar la MRZ o el CAN
			false          // No se cargan claves y certificados
		);
	}

    /** {@inheritDoc} */
	@Override
    public String getCardName() {
        return "MRTD accedido de forma inalambrica mediante PACE"; //$NON-NLS-1$
    }

	/** {@inheritDoc} */
	@Override
	public void openSecureChannelIfNotAlreadyOpened() {
		throw new UnsupportedOperationException(
			"No se permite apertura de canal CWA-14890" //$NON-NLS-1$
		);
	}

    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) {
    	throw new UnsupportedOperationException(
			"No se permite firmar con MRTD" //$NON-NLS-1$
		);
    }

	@Override
	public String toString() {
		return getCardName();
	}

}
