package es.gob.jmulticard.apdu.bit4id.stcm;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU ISO 7816-4 de verificaci&oacute;n de PIN (CHV, <i>Card Holder Verification</i>).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class VerifyApduCommand extends CommandApdu {

	private static final byte INS_VERIFY = (byte) 0x20;

    /** Construye una APDU ISO 7816-4 de verificaci&oacute;n de PIN (CHV, <i>Card Holder Verification</i>).
     * @param cla Clase (CLA) de la APDU
     * @param pinPc Pin de la tarjeta inteligente */
    public VerifyApduCommand(final byte cla, final PasswordCallback pinPc) {
        super(
    		cla,							// CLA
    		INS_VERIFY, 					// INS
    		(byte)0x00, 					// P1
    		(byte)0x10,						// P2
    		charArrayToByteArray(pinPc),	// Data
    		null							// Le
		);
    }

    private static byte[] charArrayToByteArray(final PasswordCallback pinPc) {
    	if (pinPc == null) {
    		throw new IllegalArgumentException(
				"El PasswordCallback del PIN no puede ser nulo" //$NON-NLS-1$
			);
    	}
    	final char[] in = pinPc.getPassword();
    	if (in == null) {
    		return new byte[0];
    	}
    	final byte[] ret = new byte[in.length];
    	for (int i=0; i<in.length; i++) {
    		ret[i] = (byte) in[i];
    	}
    	return ret;
    }

}
