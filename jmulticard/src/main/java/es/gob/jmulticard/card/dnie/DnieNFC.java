package es.gob.jmulticard.card.dnie;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.pace.InvalidCanOrMrzException;
import es.gob.jmulticard.card.pace.PaceChannelHelper;
import es.gob.jmulticard.card.pace.PaceConnection;
import es.gob.jmulticard.card.pace.PaceException;
import es.gob.jmulticard.card.pace.PaceInitializer;
import es.gob.jmulticard.card.pace.PaceInitializerCan;
import es.gob.jmulticard.card.pace.PaceInitializerMrz;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;

/** DNIe 3 accedido mediante PACE por NFC.
 * @author Sergio Mart&iacute;nez Rico
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public class DnieNFC extends Dnie3 {

	private static final int MAX_PACE_RETRIES = 2;

	// Se guarda el codigo CAN o MRZ para establecer un canal PACE cada vez que se quiere
	// realizar una operacion de firma
	private static PacePasswordType paceInitType;
	private static String paceInitValue;

	DnieNFC(final ApduConnection conn,
			final PasswordCallback pwc,
			final CryptoHelper cryptoHelper,
			final CallbackHandler ch) throws PaceException,
	                                         ApduConnectionException {
		this(
			getPaceConnection(conn, ch),
			pwc,
			cryptoHelper,
			ch,
			true
		);
	}

	/** Construte un DNIe 3 accedido mediante PACE por NFC.
	 * @param conn Conexi&oacute;n NFC.
	 * @param pwc <code>PasswordCallback</code> para obtener el PIN.
	 * @param cryptoHelper Clase de utiildades criptogr&aacute;ficas.
	 * @param ch <code>CallbackHandler</code> para obtener el PIN y el CAN o la MRZ.
	 * @param loadCertsAndKeys <code>true</code> si se ha de hacer una carga de claves
	 *                         y certificados en el momento de la construcci&oacute;n.
	 * @throws PaceException Si no se puede establecer en canal PACE.
	 * @throws ApduConnectionException Si hay problemas en el env&iacute;o de las APDU. */
	protected DnieNFC(final ApduConnection conn,
			final PasswordCallback pwc,
			final CryptoHelper cryptoHelper,
			final CallbackHandler ch,
			final boolean loadCertsAndKeys) throws PaceException,
	                                               ApduConnectionException {
		super(
			getPaceConnection(conn, ch),
			pwc,
			cryptoHelper,
			ch,
			loadCertsAndKeys
		);
	}

    /** {@inheritDoc} */
	@Override
    public String getCardName() {
        return "DNIe 3.0 accedido de forma inalambrica"; //$NON-NLS-1$
    }

	private static ApduConnection getPaceConnection(final ApduConnection con,
			                                        final CallbackHandler ch) throws ApduConnectionException,
	                                                                                 PaceException {
		// Primero obtenemos el CAN/MRZ
		final String prompt = CardMessages.getString("DnieNFC.0"); //$NON-NLS-1$
		Callback tic;
		try {
			tic = (Callback) Class.forName("javax.security.auth.callback.TextInputCallback").getConstructor(String.class).newInstance(prompt); //$NON-NLS-1$
		}
		catch(final ClassNotFoundException    |
				    InstantiationException    |
				    IllegalAccessException    |
				    IllegalArgumentException  |
				    InvocationTargetException |
				    NoSuchMethodException     |
				    SecurityException e) {
			LOGGER.info(
				"No se ha encontrado la clase 'javax.security.auth.callback.TextInputCallback', se usara 'test.es.gob.jmulticard.callback.CustomTextInputCallback': " + e //$NON-NLS-1$
			);
			try {
				tic = (Callback) Class.forName("es.gob.jmulticard.callback.CustomTextInputCallback").getConstructor(String.class).newInstance(prompt); //$NON-NLS-1$
			}
			catch (InstantiationException |
				   IllegalAccessException |
				   IllegalArgumentException |
				   InvocationTargetException |
				   NoSuchMethodException |
				   SecurityException |
				   ClassNotFoundException e1) {
				throw new IllegalStateException(
					"No se ha encontrado ni la clase 'javax.security.auth.callback.TextInputCallback' ni 'test.es.gob.jmulticard.callback.CustomTextInputCallback': " + e1, e1 //$NON-NLS-1$
				);
			}
		}

		int counter = 0;
		paceInitValue = null;
		paceInitType = null;

		while(true) {
			// Pide el codigo CAN o MRZ en caso de que no haya sido introducido con anterioridad
			// El contador permite hacer varias verificaciones del CAN/MRZ por si en la primera no se hubiera reseteado la tarjeta
			if (paceInitValue == null || paceInitType == null) {
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

				try {
					final Method m = tic.getClass().getMethod("getText"); //$NON-NLS-1$
					final Object o = m.invoke(tic);
					if (!(o instanceof String)) {
						throw new IllegalStateException(
							"El TextInputCallback ha devuelto un dato de tipo " + (o == null ? "null" : o.getClass().getName()) //$NON-NLS-1$ //$NON-NLS-2$
						);
					}
					paceInitValue = (String)o;
				}
				catch (final NoSuchMethodException    |
					         SecurityException        |
					         IllegalAccessException   |
					         IllegalArgumentException |
					         InvocationTargetException e) {
					throw new IllegalStateException(
						"El TextInputCallback no tiene un metodo 'getText': " + e, e //$NON-NLS-1$
					);
				}

				//Se obtiene el tipo de inicializador analizando el valor introducido.
				paceInitType = getPasswordType(paceInitValue);

				if (paceInitValue == null || paceInitValue.isEmpty() || paceInitType == null)  {
					throw new InvalidCanOrMrzException("El CAN/MRZ no puede ser nulo ni vacio"); //$NON-NLS-1$
				}
			}
			try {
				final PaceInitializer paceInitializer;
				switch (paceInitType) {
					case MRZ:
						paceInitializer = PaceInitializerMrz.deriveMrz(paceInitValue);
						break;
					case CAN:
						paceInitializer = new PaceInitializerCan(paceInitValue);
						break;
					default:
						throw new UnsupportedOperationException(
							"Tipo de inicializador PACE no soportado: " + paceInitType //$NON-NLS-1$
						);
				}

				final SecureMessaging sm = PaceChannelHelper.openPaceChannel(
					(byte)0x00,
					paceInitializer,
					con,
					new JseCryptoHelper()
				);

				return new PaceConnection(
		    		con,
		    		new JseCryptoHelper(),
		    		sm
				);

			}
			catch(final InvalidCanOrMrzException e) {

				// En cualquier caso, si da esta excepcion, no guardamos el CAN/MRZ
				paceInitValue = null;
				paceInitType = null;

				if (counter >= MAX_PACE_RETRIES) {
					throw e;
				}
				Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
					"Error en el intento " + Integer.toString(counter + 1) + " de establecimiento de canal PACE (probablemente por CAN/MRZ invalido): " + e //$NON-NLS-1$ //$NON-NLS-2$
				);
				//Si el CAN/MRZ es incorrecto volvemos a pedirlo
				counter++;
			}

		}

	}

	private static ApduConnection getPaceConnection(final ApduConnection con) throws ApduConnectionException,
	                                                                                 PaceException {
		final PaceInitializer paceInitializer;
		switch (paceInitType) {
			case MRZ:
				paceInitializer = PaceInitializerMrz.deriveMrz(paceInitValue);
				break;
			case CAN:
				paceInitializer = new PaceInitializerCan(paceInitValue);
				break;
			default:
				throw new UnsupportedOperationException(
					"No se soporta el codigo de inicializacion de PACE: " + paceInitType //$NON-NLS-1$
				);
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
	public void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException,
															 PinException {
		if(!(getConnection() instanceof Cwa14890Connection)) {
			try {
				this.rawConnection = getPaceConnection(getConnection());
			}
			catch (final ApduConnectionException e) {
				throw new CryptoCardException(
					"Error en la transmision de la APDU: " + e, e //$NON-NLS-1$
				);
			}
			catch (final PaceException e) {
				throw new CryptoCardException(
					"Error en el establecimiento del canal PACE: " + e, e //$NON-NLS-1$
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
			// Error al pasar de un canal cifrado a uno no cifrado.
			// Se usa para reiniciar la tarjeta inteligente por NFC
		}
	}

	private static PacePasswordType getPasswordType(final String paceInitializationValue) {
		if(isNumeric(paceInitializationValue) && paceInitializationValue.length() <= 6) {
			return PacePasswordType.CAN;
		}
		return PacePasswordType.MRZ;
	}

	/** Indica si un texto es num&eacute;rico.
	 * @param cs Texto a analizar.
	 * @return <code>true</code> si el texto es num&eacute;rico,
	 *         <code>false</code> en caso contrario. */
	 private static boolean isNumeric(final CharSequence cs) {
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
