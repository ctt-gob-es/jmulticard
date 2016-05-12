package es.gob.jmulticard.card.dnie;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;

/** Tarjeta FNMT TIF (variante del DNIe).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Tif extends Dnie {

	/** Construye una tarjeta FNMT TIF (variante del DNIe).
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TIF.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.
     * @throws es.gob.jmulticard.card.InvalidCardException Si la tarjeta conectada no es un DNIe.
     * @throws BurnedDnieCardException Si la tarjeta conectada es una TIF con la memoria vol&aacute;til borrada. */
	public Tif(final ApduConnection conn,
			   final PasswordCallback pwc,
			   final CryptoHelper cryptoHelper,
			   final CallbackHandler ch) throws ApduConnectionException,
			                                    InvalidCardException,
			                                    BurnedDnieCardException {
		super(conn, pwc, cryptoHelper, ch);
	}
	
	/** {@inheritDoc}
	 */
	@Override
	public byte[] changePIN(final String oldPin, final String newPin) throws CryptoCardException, BadPinException, AuthenticationModeLockedException {
		throw new UnsupportedOperationException("El cambio de PIN no esta permitido para la tarjeta insertada."); //$NON-NLS-1$
	}

}
