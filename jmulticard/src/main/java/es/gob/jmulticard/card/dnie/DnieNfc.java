package es.gob.jmulticard.card.dnie;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.PaceChannelHelper;
import es.gob.jmulticard.DigestAlgorithm;
import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.apdu.iso7816four.pace.MseSetPaceAlgorithmApduCommand.PacePasswordType;
import es.gob.jmulticard.asn1.icao.CardAccess;
import es.gob.jmulticard.callback.CustomTextInputCallback;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.card.icao.InvalidCanOrMrzException;
import es.gob.jmulticard.card.icao.WirelessInitializer;
import es.gob.jmulticard.card.icao.WirelessInitializerCan;
import es.gob.jmulticard.card.icao.WirelessInitializerMrz;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.connection.pace.PaceConnection;
import es.gob.jmulticard.connection.pace.PaceException;
import es.gob.jmulticard.connection.pace.SecureMessaging;

/** DNIe 3 accedido mediante PACE por NFC.
 * @author Sergio Mart&iacute;nez Rico
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Ignacio Mar&iacute;n. */
public class DnieNfc extends Dnie3 {

	// Se guarda el codigo CAN o MRZ para establecer un canal PACE
	// cada vez que se quiere realizar una operacion de firma
	private static PacePasswordType paceInitType;
	private static String paceInitValue;

	/** Construte un DNIe 3 accedido mediante PACE por NFC.
	 * @param conn Conexi&oacute;n NFC.
	 * @param pwc <code>PasswordCallback</code> para obtener el PIN.
	 * @param cryptoHlpr Clase de utiildades criptogr&aacute;ficas.
	 * @param ch <code>CallbackHandler</code> para obtener el PIN y el CAN o la MRZ.
	 * @throws IcaoException Si no se puede establecer en canal PACE.
	 * @throws ApduConnectionException Si hay problemas en el env&iacute;o de las APDU. */
	public DnieNfc(final ApduConnection conn,
			       final PasswordCallback pwc,
			       final CryptoHelper cryptoHlpr,
			       final CallbackHandler ch) throws IcaoException,
	                                                ApduConnectionException {
		super(getPaceConnection(conn, ch, cryptoHlpr), pwc, cryptoHlpr, ch);
	}

	@Override
    public String getCardName() {
        return "DNIe 3.0/4.0 accedido de forma inalambrica"; //$NON-NLS-1$
    }

	private static ApduConnection getPaceConnection(final ApduConnection con,
			                                        final CallbackHandler ch,
			                                        final CryptoHelper cryptoHelper) throws ApduConnectionException,
	                                                                                        IcaoException {
		// Primero obtenemos el CAN/MRZ
		final String prompt = CardMessages.getString("DnieNFC.0"); //$NON-NLS-1$

		// Al usar el minimizado y la ofuscacion de Android se puede dar el caso de que la reflexion falle
		// incluso en CustomInputCallback, por lo que se establece siempre una via sin reflexion.
		Callback textInputCallback;
		Method m;
		try {
			textInputCallback = (Callback) Class.forName("javax.security.auth.callback.TextInputCallback").getConstructor(String.class).newInstance(prompt); //$NON-NLS-1$
			m = textInputCallback.getClass().getMethod("getText"); //$NON-NLS-1$
		}
		catch(final ClassNotFoundException    |
				    InstantiationException    |
				    IllegalAccessException    |
				    IllegalArgumentException  |
				    InvocationTargetException |
				    NoSuchMethodException     |
				    SecurityException e) {
			JmcLogger.info(
				DnieNfc.class.getName(),
				"getPaceConnection", //$NON-NLS-1$
				"No se ha encontrado la clase 'javax.security.auth.callback.TextInputCallback', se usara 'es.gob.jmulticard.callback.CustomTextInputCallback': " + e //$NON-NLS-1$
			);
			textInputCallback = new CustomTextInputCallback(prompt);
			m = null;
		}

		// Reiniciamos valor del CAN/MRZ
		paceInitValue = null;
		paceInitType = null;

		// Pide el codigo CAN/MRZ
		try {
			ch.handle(new Callback[] { textInputCallback });
		}
		catch (final Exception e) {
			throw new PaceException("Error obteniendo el CAN", e); //$NON-NLS-1$
		}

		if (textInputCallback instanceof CustomTextInputCallback) {
			paceInitValue = ((CustomTextInputCallback)textInputCallback).getText();
		}
		else if (m != null) {
			try {
				final Object o = m.invoke(textInputCallback);
				if (!(o instanceof String)) {
					throw new IllegalStateException(
						"El TextInputCallback ha devuelto un dato de tipo " + (o == null ? "null" : o.getClass().getName()) //$NON-NLS-1$ //$NON-NLS-2$
					);
				}
				paceInitValue = (String)o;
			}
			catch (final SecurityException        |
				         IllegalAccessException   |
				         IllegalArgumentException |
				         InvocationTargetException e) {
				throw new IllegalStateException("El TextInputCallback no tiene un metodo 'getText'", e); //$NON-NLS-1$
			}
		}
		else {
			// No deberia saltar nunca (m no puede ser null en ese punto)
			throw new IllegalStateException("El TextInputCallback no tiene un metodo 'getText'"); //$NON-NLS-1$
		}

		//Se obtiene el tipo de inicializador analizando el valor introducido.
		paceInitType = getPasswordType(paceInitValue);

		if (paceInitValue == null || paceInitValue.isEmpty())  {
			throw new InvalidCanOrMrzException("El CAN/MRZ no puede ser nulo ni vacio"); //$NON-NLS-1$
		}

		try {
			final WirelessInitializer paceInitializer;
			switch (paceInitType) {
				case MRZ:
					paceInitializer = WirelessInitializerMrz.deriveMrz(paceInitValue, cryptoHelper);
					break;
				case CAN:
					paceInitializer = new WirelessInitializerCan(paceInitValue);
					break;
				default:
					throw new UnsupportedOperationException("Tipo de inicializador PACE no soportado: " + paceInitType); //$NON-NLS-1$
			}

			final SecureMessaging sm = cryptoHelper.getPaceChannelHelper(
				new CardAccess(
					CardAccess.PaceAlgorithm.PACE_ECDH_GM_AES_CBC_CMAC_128,
					CardAccess.PaceAlgorithmParam.BRAINPOOL_256_R1,
					DigestAlgorithm.SHA1
				),
				null // No hay PACE CHAT
			).openPaceChannel((byte)0x00, paceInitializer, con);

			return new PaceConnection(con, cryptoHelper, sm);
		}
		catch(final InvalidCanOrMrzException e) {

			// En cualquier caso, si da esta excepcion, no guardamos el CAN/MRZ
			paceInitValue = null;
			paceInitType = null;

			// Relanzamos la excepcion
			throw e;
		}
	}

	private ApduConnection getPaceConnection(final ApduConnection con,
                                             final PaceChannelHelper pch) throws ApduConnectionException,
	                                                                             IcaoException {
		final WirelessInitializer paceInitializer;
		switch (paceInitType) {
			case MRZ:
				paceInitializer = WirelessInitializerMrz.deriveMrz(paceInitValue, getCryptoHelper());
				break;
			case CAN:
				paceInitializer = new WirelessInitializerCan(paceInitValue);
				break;
			default:
				throw new UnsupportedOperationException(
					"No se soporta el codigo de inicializacion de PACE: " + paceInitType //$NON-NLS-1$
				);
		}

		final SecureMessaging sm = pch.openPaceChannel((byte) 0x00, paceInitializer, con);

        // Establecemos el canal PACE
    	return new PaceConnection(con, getCryptoHelper(), sm);
	}

	@Override
	public void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException,
															 PinException {
		openSecureChannelIfNotAlreadyOpened(true);
	}

	@Override
	public void openSecureChannelIfNotAlreadyOpened(final boolean doChv) throws CryptoCardException,
															                    PinException {
		if(!(getConnection() instanceof Cwa14890Connection)) {
			try {
				rawConnection = getPaceConnection(
					getConnection(),
					getCryptoHelper().getPaceChannelHelper(
						new CardAccess(
							CardAccess.PaceAlgorithm.PACE_ECDH_GM_AES_CBC_CMAC_128,
							CardAccess.PaceAlgorithmParam.BRAINPOOL_256_R1,
							DigestAlgorithm.SHA1
						),
						null // No hay PACE CHAT
					)
				);
			}
			catch (final ApduConnectionException e) {
				throw new CryptoCardException("Error en la transmision de la APDU", e); //$NON-NLS-1$
			}
			catch (final IcaoException e) {
				throw new CryptoCardException("Error en el establecimiento del canal PACE", e); //$NON-NLS-1$
			}

			try {
				setConnection(rawConnection);
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException("Error al abrir el canal PACE", e); //$NON-NLS-1$
			}
		}

		super.openSecureChannelIfNotAlreadyOpened(doChv);
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
    		JmcLogger.warning("Fallo en el reinicio del canal seguro: " + e); //$NON-NLS-1$
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
			JmcLogger.info(
				DnieNfc.class.getName(),
				"resetCard", //$NON-NLS-1$
				"Paso de canal seguro a no seguro al reiniciar: " + e1 //$NON-NLS-1$
			);
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
