package es.gob.jmulticard.card.dnie;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
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

	// Se guarda el codigo CAN para establecer un canal PACE cada vez que se quiere 
	// realizar una operacion de firma
	private String can;
	
	DnieNFC(ApduConnection conn, PasswordCallback pwc, CryptoHelper cryptoHelper, String can)
			throws ApduConnectionException, InvalidCardException, BurnedDnieCardException, PaceException {
		super(paceConnection(conn, can), pwc, cryptoHelper);
		this.can = can;
	}

	private static ApduConnection paceConnection(ApduConnection con, String can) throws ApduConnectionException, PaceException {

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
	
	/** {@inheritDoc} */
	@Override
	protected void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, BadPinException {	
			if(!(getConnection() instanceof Cwa14890Connection)) {
				try {
					this.rawConnection = paceConnection(getConnection(), this.can);
				} catch (ApduConnectionException e) {
					new CryptoCardException("Error en la transmision de la APDU: " + e);
				} catch (PaceException e) {
					new CryptoCardException("Error en el establecimiento del canal PACE: " + e);
				}
			}
	
		super.openSecureChannelIfNotAlreadyOpened();
	}
    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                 BadPinException {
    	final byte[] ret = signInternal(data, signAlgorithm, privateKeyReference);

    	//XXX Provoca un error en la tarjeta que la resetea para establecer un canal en claro
    	resetNFCCard();
    	return ret;
    }

    //Resetea la tarjeta enviando una APDU sin cifrar para provocar un error en la tarjeta
	private void resetNFCCard() {
		try {
			setConnection(((Cwa14890Connection)getConnection()).getSubConnection());
			selectMasterFile();
		} 
		catch (ApduConnectionException e1) {} 
		catch (Iso7816FourCardException e1) {} 
	}
}
