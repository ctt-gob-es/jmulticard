package es.gob.jmulticard.apdu.bit4id.stcm;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;

/** APDU ISO 7816-4 de verificaci&oacute;n de PIN (CHV, <i>Card Holder Verification</i>).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class VerifyApduCommand extends CommandApdu {

	/** C&oacute;digo de instrucci&oacute;n de la APDU. */
	private static final byte INS_VERIFY = (byte) 0x20;

    /** Construye una APDU ISO 7816-4 de verificaci&oacute;n de PIN
     * (CHV, <i>Card Holder Verification</i>).
     * @param cla Clase (CLA) de la APDU.
     * @param pinPc PIN de la tarjeta inteligente. */
    public VerifyApduCommand(final byte cla, final PasswordCallback pinPc) {
        super(
    		cla,		   // CLA
    		INS_VERIFY,    // INS
    		(byte)0x00,    // P1
    		(byte)0x10,	   // P2
    		getPin(pinPc), // Data
    		null		   // Le
		);
    }

    private static byte[] getPin(final PasswordCallback pinPc) {
    	if (pinPc == null) {
    		throw new IllegalArgumentException(
				"El PasswordCallback del PIN no puede ser nulo" //$NON-NLS-1$
			);
    	}
    	final char[] in = pinPc.getPassword();
    	return HexUtils.charArrayToByteArray(in);
    }
}
