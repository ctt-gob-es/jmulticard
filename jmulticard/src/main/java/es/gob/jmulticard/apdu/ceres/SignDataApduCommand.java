package es.gob.jmulticard.apdu.ceres;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU de firma de datos.
 * Los datos a firmar deben cargarse previamente con una APDU <code>LoadData</code>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class SignDataApduCommand extends CommandApdu {

	private static final byte CLA = (byte) 0x90;
	private static final byte INS_SIGN_DATA = (byte) 0x5A;
	private static final byte RSA_SIGN = (byte) 0x80;

	/** Construye una APDU de firma de datos.
	 * @param reference Referencia de la clave de firma.
	 * @param keySize Tama&ntilde;o en bits de la clave de firma (1024 o 2048). */
	public SignDataApduCommand(final byte reference, final int keySize) {
		super(
			CLA,
			INS_SIGN_DATA,
			RSA_SIGN,
			reference,
			null,
			Integer.valueOf(keySize / 8)
		);
	}

}
