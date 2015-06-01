package es.gob.jmulticard.apdu.iso7816eight;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU de envoltura de datos (o de otra APDU).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class EnvelopeDataApduCommand extends CommandApdu {

	private static final byte CLA = (byte) 0x90;
	private static final byte INS_SIGN_DATA = (byte) 0xC2;

	/** Construye una APDU de envoltura de datos.
	 * @param data Datos a envolver. */
	public EnvelopeDataApduCommand(final byte[] data) {
		super(
			CLA,
			INS_SIGN_DATA,
			(byte) 0x00,
			(byte) 0x00,
			data,
			null
		);
	}

}
