package es.gob.jmulticard.apdu.ceres;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU de firma de datos.
 * Los datos a firmar deben cargarse previamente con una APDU <code>LoadData</code>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class SignDataApduCommand extends CommandApdu {

	private static final byte CLA = (byte) 0x90;
	private static final byte INS_SIGN_DATA = (byte) 0x5A;

	/** Construye una APDU de firma de datos.
	 * @param path Ruta hacia la clave de firma. */
	public SignDataApduCommand(final String path) {
		super(
			CLA,
			INS_SIGN_DATA,
			(byte)0x80,
			(byte)0x00,
			null,
			Integer.valueOf(128)
		);
	}

}