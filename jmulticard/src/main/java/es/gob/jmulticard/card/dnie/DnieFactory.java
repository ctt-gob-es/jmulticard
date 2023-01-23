package es.gob.jmulticard.card.dnie;

import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.dnie.ceressc.CeresSc;
import es.gob.jmulticard.card.dnie.tif.Tif;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.CardNotPresentException;
import es.gob.jmulticard.connection.NoReadersFoundException;

/** Factor&iacute;a para la obtenci&oacute;n de DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class DnieFactory {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	private static final byte[] ATR_MASK = {
		(byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF
	};

	private static final byte[] ATR_NFC_MASK = {
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0x00, (byte) 0xFF, (byte) 0x00
	};

	private static final byte[] ATR_NFC2_MASK = {
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00
	};

	private static final Atr ATR_NFC = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x88, (byte) 0x80, (byte) 0x01, (byte) 0xE1, (byte) 0xF3, (byte) 0x5E, (byte) 0x11, (byte) 0x77, (byte) 0x81,
		(byte) 0xA1, (byte) 0x00, (byte) 0x03
	}, ATR_NFC_MASK);

	private static final Atr ATR_NFC2 = new Atr(new byte[] {
	    (byte) 0x3B, (byte) 0x8C, (byte) 0x80, (byte) 0x01, (byte) 0x50, (byte) 0x42, (byte) 0x8E, (byte) 0x93, (byte) 0x2A, (byte) 0xE1,
	    (byte) 0xF3, (byte) 0x5E, (byte) 0x11, (byte) 0x77, (byte) 0x81, (byte) 0x81, (byte) 0x02
	}, ATR_NFC2_MASK);

	private static final Atr ATR = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44, (byte) 0x4E, (byte) 0x49,
		(byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
	}, ATR_MASK);

	private static final Atr ATR_TIF = new Atr(new byte[] {
		(byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x54, (byte) 0x49, (byte) 0x46,
		(byte) 0x31, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
	}, ATR_MASK);

	private static final String DNIE3_R2_IDESP = "BMP100001"; //$NON-NLS-1$

	private DnieFactory() {
		// No instanciable
	}

	/** Obtiene la clase de DNIe apropiada (seg&uacute;n su ATR).
	 * @param conn Conexi&oacute;n con el lector de tarjetas.
	 * @param pwc <i>PasswordCallback</i> para la obtenci&oacute;n del PIN.
	 * @param cryptoHelper Clase de apoyo para operaciones criptogr&aacute;ficas.
	 * @param ch Gestor de <i>callbacks</i> para la obtenci&oacute;n de datos adicionales por parte
	 *           del titular del DNIe.
	 * @return Clase de DNIe apropiada (seg&uacute;n su ATR).
	 * @throws InvalidCardException Si se ha detectado al menos una tarjeta, pero no es un DNIe.
	 * @throws BurnedDnieCardException Si se ha detectado un DNIe con su memoria vol&aacute;til borrada.
	 * @throws ApduConnectionException Si no se puede conectar con el lector de tarjetas. */
	public static Dnie getDnie(final ApduConnection conn,
			                   final PasswordCallback pwc,
			                   final CryptoHelper cryptoHelper,
			                   final CallbackHandler ch) throws InvalidCardException,
											                    BurnedDnieCardException,
											                    ApduConnectionException {
		return getDnie(conn, pwc, cryptoHelper, ch, true);
	}

	/** Obtiene la clase de DNIe apropiada (seg&uacute;n su ATR).
	 * @param conn Conexi&oacute;n con el lector de tarjetas.
	 * @param pwc <i>PasswordCallback</i> para la obtenci&oacute;n del PIN.
	 * @param cryptoHelper Clase de apoyo para operaciones criptogr&aacute;ficas.
	 * @param ch Gestor de <i>callbacks</i> para la obtenci&oacute;n de datos adicionales por parte
	 *           del titular del DNIe (como el PIN y el CAN).
	 * @param loadCertsAndKeys Si se indica <code>true</code>, se cargan las referencias a
     *                         las claves privadas y a los certificados, mientras que si se
     *                         indica <code>false</code>, no se cargan, permitiendo la
     *                         instanciaci&oacute;n de un DNIe sin capacidades de firma o
     *                         autenticaci&oacute;n con certificados.
	 * @return Clase de DNIe apropiada (seg&uacute;n su ATR).
	 * @throws InvalidCardException Si se ha detectado al menos una tarjeta, pero no es un DNIe.
	 * @throws BurnedDnieCardException Si se ha detectado un DNIe con su memoria vol&aacute;til borrada.
	 * @throws ApduConnectionException Si no se puede conectar con el lector de tarjetas. */
	public static Dnie getDnie(final ApduConnection conn,
			                   final PasswordCallback pwc,
			                   final CryptoHelper cryptoHelper,
			                   final CallbackHandler ch,
			              	   final boolean loadCertsAndKeys) throws InvalidCardException,
											                          BurnedDnieCardException,
											                          ApduConnectionException {
		if (conn == null) {
			throw new IllegalArgumentException(
				"La conexion no puede ser nula" //$NON-NLS-1$
			);
		}

		byte[] responseAtr;
		Atr actualAtr;
		InvalidCardException invalidCardException = null;
		CardNotPresentException cardNotPresentException = null;
		final long[] terminals = conn.getTerminals(false);
		if (terminals.length < 1) {
			throw new NoReadersFoundException();
		}
		for (final long terminal : terminals) {
			conn.setTerminal((int) terminal);
			try {
				responseAtr = conn.reset();
			}
			catch(final CardNotPresentException e) {
				cardNotPresentException = e;
				continue;
			}
			actualAtr = new Atr(responseAtr, ATR_MASK);
			final byte[] actualAtrBytes = actualAtr.getBytes();
			if(ATR_NFC.equals(actualAtr) || ATR_NFC2.equals(actualAtr)) {
				try {
					LOGGER.info("Detectado DNIe 3.0 o 4.0 por NFC"); //$NON-NLS-1$
					LOGGER.info(new DnieAtr(actualAtr).toString());
					return new DnieNfc(conn, pwc, cryptoHelper, ch, loadCertsAndKeys);
				}
				catch (final IcaoException e) {
					throw new ApduConnectionException(
						"No se ha podido abrir el canal PACE", e //$NON-NLS-1$
					);
				}
			}
			if (ATR.equals(actualAtr)) {
				if (actualAtrBytes[15] == 0x04) {
					LOGGER.info("Detectado DNIe 3.0 o 4.0"); //$NON-NLS-1$
					LOGGER.info(new DnieAtr(actualAtr).toString());
					return new Dnie3(conn, pwc, cryptoHelper, ch, loadCertsAndKeys);
				}
				LOGGER.info("Detectado DNIe 2.0"); //$NON-NLS-1$
				LOGGER.info(new DnieAtr(actualAtr).toString());
				return new Dnie(conn, pwc, cryptoHelper, ch, loadCertsAndKeys);
			}
			if (ATR_TIF.equals(actualAtr)) {
				LOGGER.info("Detectada tarjeta TIF"); //$NON-NLS-1$
				// Las tarjetas TIF siempre se instancian con precarga de claves y certificados
				// (no se aplica el parametro 'loadCertsAndKeys')
				return new Tif(conn, pwc, cryptoHelper, ch);
			}

			// La factoria tambien soporta las tarjetas FNMT CERES 4.30 y superior
			if (CeresSc.ATR_TC.equals(actualAtr)) {
				LOGGER.info("Detectada tarjeta FNMT CERES 4.30 o superior"); //$NON-NLS-1$
				return new CeresSc(conn, pwc, cryptoHelper, ch, loadCertsAndKeys);
			}

			// La tarjeta encontrada no es un DNIe
			// Vemos si es un DNIe quemado, en el que el ATR termina en 65-81 en vez de
			// en 90-00
			if (
				actualAtrBytes[actualAtrBytes.length -1] == (byte) 0x81 &&
				actualAtrBytes[actualAtrBytes.length -2] == (byte) 0x65
			) {
				throw new BurnedDnieCardException(actualAtr);
			}

			invalidCardException = new InvalidCardException("DNIe", ATR, responseAtr); //$NON-NLS-1$
			continue;
		}
		if (invalidCardException != null) {
			throw invalidCardException;
		}
		if (cardNotPresentException != null) {
			throw cardNotPresentException;
		}
		throw new ApduConnectionException("No se ha podido conectar con ningun lector de tarjetas"); //$NON-NLS-1$
	}

	/** Obtiene las constantes de canal de usuario CWA-14890 de un DNIe 3.0.
	 * @param idesp IDESP del DNIe para el cual se desea obtener las constantes de canal.
	 * @return Constantes de canal de usuario CWA-14890 de un DNIe 3.0. */
	public static Dnie3Cwa14890Constants getDnie3UsrCwa14890Constants(final String idesp) {
		if (idesp == null || idesp.isEmpty()) {
			LOGGER.warning(
				"El IDESP proporcionado era nulo o vacio, se usaran las constantes CWA14890 de usuario para los DNIe 3 modernos" //$NON-NLS-1$
			);
			return new Dnie3r2UsrCwa14890Constants();
		}
		if (DNIE3_R2_IDESP.compareTo(idesp) > 0) {
			return new Dnie3UsrCwa14890Constants();
		}
		return new Dnie3r2UsrCwa14890Constants();
	}

	static Dnie3Cwa14890Constants getDnie3PinCwa14890Constants(final String idesp) {
		if (idesp == null || idesp.isEmpty()) {
			LOGGER.warning(
				"El IDESP proporcionado era nulo o vacio, se usaran las constantes CWA14890 de PIN para los DNIe 3 modernos" //$NON-NLS-1$
			);
			return new Dnie3r2PinCwa14890Constants();
		}
		if (DNIE3_R2_IDESP.compareTo(idesp) > 0) {
			return new Dnie3PinCwa14890Constants();
		}
		return new Dnie3r2PinCwa14890Constants();
	}

}
