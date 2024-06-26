
package es.gob.jmulticard.card.dnie.ceressc;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.DigestAlgorithm;
import es.gob.jmulticard.apdu.iso7816four.pace.PaceChat;
import es.gob.jmulticard.asn1.icao.CardAccess;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.card.icao.WirelessInitializer;
import es.gob.jmulticard.card.icao.WirelessInitializerPin;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.pace.PaceConnection;
import es.gob.jmulticard.connection.pace.PaceException;
import es.gob.jmulticard.connection.pace.SecureMessaging;

/** Tarjetas CERES v5.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CeresSc5 extends Dnie {

	/** Construye una clase que representa una tarjeta FNMT CERES v5.x con canal EAC 2.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad que
     *                   pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.
	 * @throws IcaoException Si se producen errores abriendo el canal PACE. */
	public CeresSc5(final ApduConnection conn,
			        final PasswordCallback pwc,
			        final CryptoHelper cryptoHlpr,
			        final CallbackHandler ch) throws ApduConnectionException, IcaoException {
		super(getPaceConnection(conn, ch, cryptoHlpr), pwc, cryptoHlpr, ch);
	}

	private static ApduConnection getPaceConnection(final ApduConnection con,
                                                    final CallbackHandler ch,
                                                    final CryptoHelper cryptoHelper) throws ApduConnectionException,
	                                                                                        IcaoException {
		// Primero obtenemos el PIN para abrir canal PACE
		final String prompt = CardMessages.getString("DnieNFC.0"); //$NON-NLS-1$
		final PasswordCallback pinCallback = new PasswordCallback(prompt, false);

		try {
			ch.handle(new Callback[] { pinCallback });
		}
		catch (final Exception e) {
			throw new PaceException("Error obteniendo el PIN", e); //$NON-NLS-1$
		}

		final WirelessInitializer paceInitializer = new WirelessInitializerPin(pinCallback.getPassword());

		final SecureMessaging sm = cryptoHelper.getPaceChannelHelper(
			new CardAccess(
				CardAccess.PaceAlgorithm.PACE_ECDH_GM_AES_CBC_CMAC_192,
				CardAccess.PaceAlgorithmParam.BRAINPOOL_256_R1,
				DigestAlgorithm.SHA256
			),
			new PaceChat(PaceChat.TerminalType.ST)
		).openPaceChannel((byte) 0x00, paceInitializer, con);
		return new PaceConnection(con, cryptoHelper, sm);
	}

	@Override
    public String getCardName() {
        return "FNMT TC CERES v5.x"; //$NON-NLS-1$
    }

	@Override
	protected Cwa14890PublicConstants getCwa14890PublicConstants() {
		throw new UnsupportedOperationException("Esta tarjeta no soporta CWA-14890"); //$NON-NLS-1$
	}

	@Override
	protected Cwa14890PrivateConstants getCwa14890PrivateConstants() {
		throw new UnsupportedOperationException("Esta tarjeta no soporta CWA-14890"); //$NON-NLS-1$
	}

}
