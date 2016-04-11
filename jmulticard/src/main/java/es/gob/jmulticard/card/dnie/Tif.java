package es.gob.jmulticard.card.dnie;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.cwa14890.Cwa14890Constants;

/** Tarjeta FNMT TIF (variante del DNIe).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Tif extends Dnie {

	/** Construye una tarjeta FNMT TIF (variante del DNIe).
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TIF.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.
     * @throws es.gob.jmulticard.card.InvalidCardException Si la tarjeta conectada no es un DNIe.
     * @throws BurnedDnieCardException Si la tarjeta conectada es una TIF con la memoria vol&aacute;til borrada. */
	public Tif(final ApduConnection conn,
			   final PasswordCallback pwc,
			   final CryptoHelper cryptoHelper) throws ApduConnectionException,
			                                           InvalidCardException,
			                                           BurnedDnieCardException {
		super(conn, pwc, cryptoHelper);
	}

	@Override
	protected Cwa14890Constants getCwa14890Constants() {
		return new TifCwa14890Constants();
	}

}
