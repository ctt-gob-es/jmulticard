package es.gob.jmulticard.card.icao.bac;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;

/** Pasaporte accedido de forma inal&aacute;mbrica mediante BAC.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class IcaoMrtdWithBac extends Dnie3 {

	/** Construye una clase que representa un MRTD accedido de forma
	 * inal&aacute;mbrica mediante BAC..
	 * @param conn Conexi&oacute;n con el lector NFC.
	 * @param cryptoHlpr Clase de utilidad de funciones criptogr&aacute;ficas.
	 * @throws ApduConnectionException Si no se puede establecer la conexi&oacute;n NFC. */
	public IcaoMrtdWithBac(final ApduConnection conn,
			               final CryptoHelper cryptoHlpr) throws ApduConnectionException {
		super(
			conn,
			null,          // No hay PIN
			cryptoHlpr,
			null,          // No hace falta CAN ni MRZ
			false          // No se cargan claves y certificados
		);
	}

	@Override
    public String getCardName() {
        return "MRTD accedido de forma inalambrica mediante BAC"; //$NON-NLS-1$
    }

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
			"No se permite firmar con un MRTD" //$NON-NLS-1$
		);
    }

}
