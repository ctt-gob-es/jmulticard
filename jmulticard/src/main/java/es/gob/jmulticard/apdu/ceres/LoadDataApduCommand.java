package es.gob.jmulticard.apdu.ceres;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU de carga de datos.
 * Estos deben proporcionarse como <i>DigestInfo</i> con relleno PKCS#1.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class LoadDataApduCommand extends CommandApdu {

	private static final byte CLA = (byte) 0x90;
	private static final byte INS_LOAD_DATA = (byte) 0x58;

	/** Construye una APDU de carga de datos.
	 * @param digestInfo <i>DigestInfo</i> de los datos a cargar */
	public LoadDataApduCommand(final byte[] digestInfo) {
		super(
			CLA,
			INS_LOAD_DATA,
			(byte)0x00,
			(byte)0x00,
			digestInfo,
			null
		);
	}

}
