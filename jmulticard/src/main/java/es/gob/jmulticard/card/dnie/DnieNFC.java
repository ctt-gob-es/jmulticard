package es.gob.jmulticard.card.dnie;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.pace.PaceChannelHelper;
import es.gob.jmulticard.card.pace.PaceConnection;
import es.gob.jmulticard.card.pace.PaceException;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;

/**
 * Lectura de Dnie3 a partir de un dispositivo con NFC.
 *
 * @author Sergio Mart&iacute;nez Rico
 *
 */
public final class DnieNFC extends Dnie3 {

	DnieNFC(ApduConnection conn, PasswordCallback pwc, CryptoHelper cryptoHelper, String can)
			throws ApduConnectionException, InvalidCardException, BurnedDnieCardException, PaceException {
		super(paceConnection(can, conn), pwc, cryptoHelper);
	}

	private static ApduConnection paceConnection(String can, ApduConnection con) throws ApduConnectionException, PaceException {

		SecureMessaging sm = null;
		sm = PaceChannelHelper.openPaceChannel(
				(byte)0x00,//(byte)0x10,
				can, // CAN
				con,
				new JseCryptoHelper()
			);

        // Establecemos el canal PACE
    	final PaceConnection paceSecureConnection = new PaceConnection(
    		con,
    		new JseCryptoHelper(),
    		sm
		);
        return paceSecureConnection;
	}
}
