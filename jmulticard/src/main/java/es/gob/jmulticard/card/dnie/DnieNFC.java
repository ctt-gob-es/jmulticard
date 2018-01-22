package es.gob.jmulticard.card.dnie;

import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import java.lang.Character;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.pace.InvalidCanException;
import es.gob.jmulticard.card.pace.PaceChannelHelper;
import es.gob.jmulticard.card.pace.PaceConnection;
import es.gob.jmulticard.card.pace.PaceException;
import es.gob.jmulticard.card.pace.PaceInitializer;
import es.gob.jmulticard.card.pace.PaceInitializerCan;
import es.gob.jmulticard.card.pace.PaceInitializerMrz;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;

/** Lectura de DNIe 3 a partir de un dispositivo con NFC.
 * @author Sergio Mart&iacute;nez Rico.
 * @author Ignacio Mar&iacute;n 
*/
public final class DnieNFC extends Dnie3 {

	// Se guarda el codigo CAN para establecer un canal PACE cada vez que se quiere
	// realizar una operacion de firma
	private static PacePasswordType paceInitType;
	private static String paceInitValue;

	DnieNFC(final ApduConnection conn,
			final PasswordCallback pwc,
			final CryptoHelper cryptoHelper,
			final CallbackHandler ch) throws PaceException, ApduConnectionException {
		super(paceConnection(conn, ch), pwc, cryptoHelper, ch,false);
	}

	private static ApduConnection paceConnection(final ApduConnection con,
			                                     final CallbackHandler ch) throws ApduConnectionException, PaceException{
		// Primero obtenemos el CAN/MRZ
		Callback tic = new CustomTextInputCallback();

		SecureMessaging sm = null;
		boolean wrongInit = true;
		int counter = 0;
		paceInitValue = null;
		paceInitType = null;
		while(wrongInit) {
			//Pide el codigo can en caso de que no haya sido introducido con anterioridad
			//El contador permite hacer dos verificaciones del can por si en la primera no se hubiera reseteado la tarjeta
			if(paceInitValue == null || paceInitType == null|| counter > 0) {
				try {
					ch.handle(
						new Callback[] {
							tic
						}
					);
				}
				catch (final Exception e) {
					throw new PaceException("Error obteniendo el CAN: " + e, e); //$NON-NLS-1$
				}
				paceInitValue = ((CustomTextInputCallback)tic).getText();
				//Se obtiene el tipo de inicializador analizando el valor introducido. 
				paceInitType = getPasswordType(paceInitValue);
				
				//Se decide el tipo de contraseña

				if ((paceInitValue == null || paceInitValue.isEmpty()) || (paceInitType == null))  {
					throw new InvalidCanException("El CAN/MRZ no puede ser nulo ni vacio"); //$NON-NLS-1$
				}
			}
			try {
				PaceInitializer paceInitializer;
				switch (paceInitType) {
					case MRZ:
						paceInitializer = PaceInitializerMrz.deriveMrz(paceInitValue);
						break;
					case CAN:
					default:
						paceInitializer = new PaceInitializerCan(paceInitValue);
				}
				sm = PaceChannelHelper.openPaceChannel(
					(byte)0x00,
					paceInitializer,
					con,
					new JseCryptoHelper()
				);
				// En caso de establecer correctamente el canal inicializamos el contador para que
				// siempre obtenga el can mediante el callback
				counter = 0;
				wrongInit = false;
			}
			catch(final PaceException e) {
				Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
					"Error estableciendo canal PACE (probablemente por CAN/MRZ invalido): " + e //$NON-NLS-1$
				);
				//Si el CAN/MRZ es incorrecto modificamos el mensaje del dialogo y volvemos a pedirlo
				wrongInit = true;
				tic = new CustomTextInputCallback();
				counter++;
			}
		}

        // Establecemos el canal PACE
		return new PaceConnection(
    		con,
    		new JseCryptoHelper(),
    		sm
		);

	}

	private static ApduConnection paceConnection(final ApduConnection con) throws ApduConnectionException,
	                                                                       PaceException {
		PaceInitializer paceInitializer;
		switch (paceInitType) {
			case MRZ:
				paceInitializer = PaceInitializerMrz.deriveMrz(paceInitValue);
				break;
			case CAN:
			default:
				paceInitializer = new PaceInitializerCan(paceInitValue);
		}

		final SecureMessaging sm = PaceChannelHelper.openPaceChannel(
			(byte) 0x00,
			paceInitializer, // CAN/MRZ
			con,
			new JseCryptoHelper()
		);

        // Establecemos el canal PACE
    	return new PaceConnection(
    		con,
    		new JseCryptoHelper(),
    		sm
		);

	}

	/** {@inheritDoc} */
	@Override
	protected void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException,
																PinException {
		if(!(getConnection() instanceof Cwa14890Connection)) {
			try {
				this.rawConnection = paceConnection(getConnection());
			}
			catch (final ApduConnectionException e) {
				throw new CryptoCardException(
					"Error en la transmision de la APDU: " + e //$NON-NLS-1$
				);
			}
			catch (final PaceException e) {
				throw new CryptoCardException(
					"Error en el establecimiento del canal PACE: " + e //$NON-NLS-1$
				);
			}
		}

		super.openSecureChannelIfNotAlreadyOpened();
	}


    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                 PinException {
    	final byte[] ret = signInternal(data, signAlgorithm, privateKeyReference);

    	try {
    		//Define el canal sin cifrar para resetearlo tras cada firma
    		setConnection(((Cwa14890Connection)getConnection()).getSubConnection());
    		//Resetea la tarjeta intentando leer un fichero sin cifrar el canal (se obtiene error 69 87)
    		resetCard();
		}
    	catch (final ApduConnectionException e) {
			LOGGER.warning(
				"Fallo en el reinicio del canal seguro: " + e //$NON-NLS-1$
			);
		}

    	return ret;
    }

	private void resetCard() {
		try {
			selectMasterFile();
		}
		catch (final Exception e1) {
			// Error al pasar de un canal cifrado a uno no cifrado. Se usa para reiniciar la tarjeta inteligente por NFC
		}
	}
	
	private static PacePasswordType getPasswordType(String paceInitValue){
		PacePasswordType type = null;
		if(isNumeric(paceInitValue) && paceInitValue.length() <= 6){
			type = PacePasswordType.CAN;
		}else{
			type = PacePasswordType.MRZ;
		}
		return type;
	}
	
	/**
	 * Analiza el valor introducido y devuelve true si es un valor num&eacute;rico.
	 *
	 * @param cs
	 * @return If cs is numeric or not.
	 */
	 private static  boolean isNumeric(final CharSequence cs) {
	        if (cs == null || cs.length() == 0) {
	            return false;
	        }
	        final int sz = cs.length();
	        for (int i = 0; i < sz; i++) {
	            if (!Character.isDigit(cs.charAt(i))) {
	                return false;
	            }
	        }
	        return true;
	    }
}
