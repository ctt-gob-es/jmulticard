package es.gob.jmulticard.apdu.dnie;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU para el cambio de PIN.
 * @author Sergio Mart&iacute;nez Rico
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s Capote. */
public final class ChangePinApduCommand extends CommandApdu {

	private static final byte CLA = (byte) 0x90;

	/** C&oacute;digo de instrucci&oacute;n de la APDU. */
	private static final byte INS_CHANGE_PIN = (byte) 0x24;

	private static final byte INSTRUCTION_PARAMETER_P1 = 0x00;
	private static final byte INSTRUCTION_PARAMETER_P2 = 0x00;

	private static final byte CHV_CODE = 0x01;

	/** Construye una APDU ISO 7816-4 de cambio de PIN.
	 * @param oldPIN Pin actual de la tarjeta inteligente.
	 * @param newPIN Pin nuevo de la tarjeta inteligente. */
	public ChangePinApduCommand(final byte[] oldPIN, final byte[] newPIN) {
		super(
			CLA,					  // CLA
			INS_CHANGE_PIN, 		  // INS
			INSTRUCTION_PARAMETER_P1, // P1
			INSTRUCTION_PARAMETER_P2, // P2
			buidData(oldPIN, newPIN), // Data
			null					  // Le
		);
	}

	private static byte[] buidData(final byte[] oldPin, final byte[] newPin) {
		final byte[] data = new byte[1 + 1 + oldPin.length + 1 + newPin.length];
		data[0] = CHV_CODE;
		data[1] = (byte) oldPin.length;
		System.arraycopy(oldPin, 0, data, 2, oldPin.length);
		data[2+oldPin.length] = (byte) newPin.length;
		System.arraycopy(newPin, 0, data, 3+oldPin.length, newPin.length);
		return data;
	}
}
