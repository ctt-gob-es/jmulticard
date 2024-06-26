package es.gob.jmulticard.card.dnie.tif;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;

/** Tarjeta FNMT TIF (variante del DNIe).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Tif extends Dnie {

	/** Construye una tarjeta FNMT TIF (variante del DNIe).
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TIF.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se
     *                                 proporciona cerrada y no es posible abrirla. */
	public Tif(final ApduConnection conn,
			   final PasswordCallback pwc,
			   final CryptoHelper cryptoHlpr,
			   final CallbackHandler ch) throws ApduConnectionException {
		super(conn, pwc, cryptoHlpr, ch);
	}

	@Override
	protected Cwa14890PublicConstants getCwa14890PublicConstants() {
		return new TifCwa14890Constants();
	}

	@Override
	protected Cwa14890PrivateConstants getCwa14890PrivateConstants() {
		return new TifCwa14890Constants();
	}

	@Override
    public String getCardName() {
        return "TIF (Tarjeta de Identificacion del Funcionario de la DGP)"; //$NON-NLS-1$
    }
}
