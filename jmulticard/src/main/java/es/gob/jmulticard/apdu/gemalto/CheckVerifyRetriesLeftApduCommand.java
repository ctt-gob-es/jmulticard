package es.gob.jmulticard.apdu.gemalto;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU ISO 7816-4 para la obtenci&oacute;n del n&uacute;mero de intentos restantes de
 * verificaci&oacute;n de PIN (CHV, <i>Card Holder Verification</i>).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CheckVerifyRetriesLeftApduCommand extends CommandApdu {

	private static final byte INS_VERIFY = (byte) 0x20;

	/** Construye una APDU ISO 7816-4 para la obtenci&oacute;n del n&uacute;mero de intentos restantes de
	 * verificaci&oacute;n de PIN (CHV, <i>Card Holder Verification</i>).
	 * @param cla Clase (CLA) de la APDU */
	public CheckVerifyRetriesLeftApduCommand(final byte cla) {
		super(cla, INS_VERIFY, (byte)0x00, (byte)0x81, null, null);
	}

}
