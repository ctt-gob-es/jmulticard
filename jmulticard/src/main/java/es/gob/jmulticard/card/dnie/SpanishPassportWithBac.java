package es.gob.jmulticard.card.dnie;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.card.PrivateKeyReference;

/** Pasaporte espa&ntilde;ol (con soporte de criptograf&iacute;a de curva el&iacute;ptica)
 * accedido de forma inal&aacute;mbrica.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SpanishPassportWithBac extends Dnie3 {

	/** Construye una clase que representa un pasaporte espa&ntilde;ol (con soporte de criptograf&iacute;a de curva
	 * el&iacute;ptica) accedido de forma inal&aacute;mbrica.
	 * @param conn Conexi&oacute;n con el lector NFC.
	 * @param cryptoHelper Clase de utilidad de funciones criptogr&aacute;ficas.
	 * @throws ApduConnectionException Si no se puede establecer la conexi&oacute;n NFC. */
	public SpanishPassportWithBac(final ApduConnection conn,
			               final CryptoHelper cryptoHelper) throws ApduConnectionException {
		super(
			conn,
			null,          // No hay PIN
			cryptoHelper,
			null,          // No hace falta CAN ni MRZ
			false          // No se cargan claves y certificados
		);
	}

    /** {@inheritDoc} */
	@Override
    public String getCardName() {
        return "Pasaporte espanol (con soporte de criptografia curva eliptica) accedido de forma inalambrica"; //$NON-NLS-1$
    }

	/** {@inheritDoc} */
	@Override
	public void openSecureChannelIfNotAlreadyOpened() {
		throw new UnsupportedOperationException(
			"No se permite apertura de canal CWA-14890" //$NON-NLS-1$
		);
	}

	@Override
	public String toString() {
		return getCardName();
	}

    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) {
    	throw new UnsupportedOperationException(
			"No se permite firmar con pasaporte" //$NON-NLS-1$
		);
    }

}
