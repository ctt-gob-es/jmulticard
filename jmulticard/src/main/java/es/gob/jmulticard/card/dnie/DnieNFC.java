package es.gob.jmulticard.card.dnie;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.pace.InvalidCanException;
import es.gob.jmulticard.card.pace.PaceChannelHelper;
import es.gob.jmulticard.card.pace.PaceConnection;
import es.gob.jmulticard.card.pace.PaceException;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;

/** Lectura de DNIe 3 a partir de un dispositivo con NFC.
 * @author Sergio Mart&iacute;nez Rico. */
public final class DnieNFC extends Dnie3 {

	// Se guarda el codigo CAN para establecer un canal PACE cada vez que se quiere
	// realizar una operacion de firma
	private static String can;
	private static String ANDROID_OS_NAME = "Dalvik"; //$NON-NLS-1$
	private static String OS_NAME_PROPERTY = "java.vm.name"; //$NON-NLS-1$

	DnieNFC(final ApduConnection conn,
			final PasswordCallback pwc,
			final CryptoHelper cryptoHelper,
			final CallbackHandler ch) throws ApduConnectionException,
	                                    PaceException {
		super(paceConnection(conn, ch), pwc, cryptoHelper, ch);
	}

	private static ApduConnection paceConnection(final ApduConnection con, final CallbackHandler ch) throws ApduConnectionException, PaceException {

		Callback tic;
		// Primero obtenemos el CAN
		// Filtramos si la ejecucion es en Android
		if(ANDROID_OS_NAME.equalsIgnoreCase(System.getProperty(OS_NAME_PROPERTY))) {
			tic = new TextInputCallback();
		}
		else {
			tic = new javax.security.auth.callback.TextInputCallback("dummy"); //$NON-NLS-1$
		}
		SecureMessaging sm = null;
		boolean wrongCan = true;
		int counter = 0;
		can = null;
		while(wrongCan) {
			//Pide el codigo can en caso de que no haya sido introducido con anterioridad
			//El contador permite hacer dos verificaciones del can por si en la primera no se hubiera reseteado la tarjeta
			if(can == null || counter > 0) {
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
				if(ANDROID_OS_NAME.equalsIgnoreCase(System.getProperty(OS_NAME_PROPERTY))) {
					can = ((TextInputCallback)tic).getText();
				}
				else {
					can = ((javax.security.auth.callback.TextInputCallback)tic).getText();
				}

				if (can == null || can.isEmpty()) {
					throw new InvalidCanException("El CAN no puede ser nulo ni vacio"); //$NON-NLS-1$
				}
			}
			try {
				sm = PaceChannelHelper.openPaceChannel(
					(byte)0x00,//(byte)0x10,
					can, // CAN
					con,
					new JseCryptoHelper()
				);
				// En caso de establecer correctamente el canal inicializamos el contador para que
				// siempre obtenga el can mediante el callback
				counter = 0;
				wrongCan = false;
			}
			catch(final PaceException e) {
				//Si el CAN es incorrecto modificamos el mensaje del dialogo y volvemos a pedirlo
				wrongCan = true;
				if(ANDROID_OS_NAME.equalsIgnoreCase(System.getProperty(OS_NAME_PROPERTY))) {
					tic = new TextInputCallback();
				}
				else {
					tic = new javax.security.auth.callback.TextInputCallback("dummy"); //$NON-NLS-1$
				}
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

	private static ApduConnection paceConnection(final ApduConnection con, final String can1) throws ApduConnectionException, PaceException {

		final SecureMessaging sm = PaceChannelHelper.openPaceChannel(
			(byte)0x00,//(byte)0x10,
			can1, // CAN
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
				this.rawConnection = paceConnection(getConnection(), can);
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
}
