package es.gob.jmulticard.apdu.ceres;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU de carga de datos.
 * La tarjeta realiza de forma autom&aacute;tica el relleno PKCS#1.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class LoadDataApduCommand extends CommandApdu {

	private static final byte CLA = (byte) 0x90;
	private static final byte INS_LOAD_DATA = (byte) 0x58;

	/** Construye una APDU de carga de datos.
	 * @param data Datos a cargar */
	public LoadDataApduCommand(final byte[] data) {
		super(
			CLA,
			INS_LOAD_DATA,
			(byte)0x00,
			(byte)0x00,
			data,
			null
		);
	}

}
