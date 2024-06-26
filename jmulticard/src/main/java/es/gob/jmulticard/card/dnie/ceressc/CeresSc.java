package es.gob.jmulticard.card.dnie.ceressc;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.PasswordCallbackNotFoundException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.cwa14890.ChannelType;
import es.gob.jmulticard.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection;

/** Tarjeta FNMT CERES con canal seguro.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CeresSc extends Dnie {

	private static final byte[] ATR_MASK_TC = {
		(byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};

	/** ATR de las tarjetas FNMT CERES 4.30 y superior. */
	public static final Atr ATR_TC = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x46, (byte) 0x4E, (byte) 0x4d,
        (byte) 0x54, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, ATR_MASK_TC);

	private static String cardVersion = null;

	/** Construye una tarjeta FNMT CERES con canal seguro.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN de la tarjeta.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.
	 * @throws InvalidCardException Si la tarjeta no es una CERES 4.30 o superior. */
	public CeresSc(final ApduConnection conn,
			       final PasswordCallback pwc,
			       final CryptoHelper cryptoHlpr,
			       final CallbackHandler ch) throws ApduConnectionException,
	                                                InvalidCardException {
		super(conn, pwc, cryptoHlpr, ch);
		checkAtr(conn.reset());
	}

	@Override
	protected Cwa14890PublicConstants getCwa14890PublicConstants() {
		return new CeresScCwa14890Constants();
	}

	@Override
	protected boolean needsPinForLoadingCerts() {
		return false;
	}

	@Override
	protected Cwa14890PrivateConstants getCwa14890PrivateConstants() {
		return new CeresScCwa14890Constants();
	}

    @Override
    public void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException,
                                                             PinException,
                                                             PasswordCallbackNotFoundException {
    	if (isSecurityChannelOpen()) {
    		return;
    	}

    	JmcLogger.info(CeresSc.class.getName(), "openSecureChannelIfNotAlreadyOpened", "Conexion actual: " + getConnection()); //$NON-NLS-1$ //$NON-NLS-2$
    	JmcLogger.info(CeresSc.class.getName(), "openSecureChannelIfNotAlreadyOpened", "Conexion subyacente: " + rawConnection); //$NON-NLS-1$ //$NON-NLS-2$

        // Si la conexion esta cerrada, la reestablecemos
        if (!getConnection().isOpen()) {
	        try {
				setConnection(rawConnection);
			}
	        catch (final ApduConnectionException e) {
	        	throw new CryptoCardException("Error en el establecimiento del canal inicial", e); //$NON-NLS-1$
			}
        }

    	// Aunque el canal seguro estuviese cerrado, podria si estar enganchado
    	if (!(getConnection() instanceof Cwa14890Connection)) {
    		final ApduConnection secureConnection = new Cwa14890OneV2Connection(
				this,
				getConnection(),
				getCryptoHelper(),
				getCwa14890PublicConstants(),
				getCwa14890PrivateConstants(),
				ChannelType.CWA_USER // En estas tarjetas no hay canal de PIN
			);

	        try {
	        	selectMasterFile();
	        }
	        catch (final Exception e) {
	        	JmcLogger.warning("Error seleccionando el MF tras el establecimiento del canal seguro de PIN: " + e); //$NON-NLS-1$
	        }

        	try {
        		setConnection(secureConnection);
        	}
        	catch (final ApduConnectionException e) {
        		throw new CryptoCardException("Error en el establecimiento del canal seguro", e); //$NON-NLS-1$
        	}
    	}

    	try {
    		verifyPin(getInternalPasswordCallback());
    	}
    	catch (final ApduConnectionException e) {
    		throw new CryptoCardException("Error en la apertura del canal seguro", e); //$NON-NLS-1$
    	}
    }

    @Override
    protected String getPinMessage(final int retriesLeft) {
    	return CardMessages.getString("Gen.0", Integer.toString(retriesLeft)); //$NON-NLS-1$
    }

    private static void checkAtr(final byte[] atrBytes) throws InvalidCardException {
    	final Atr tmpAtr = new Atr(atrBytes, ATR_MASK_TC);
    	if (ATR_TC.equals(tmpAtr) && atrBytes[15] >= (byte) 0x04 && atrBytes[16] >= (byte) 0x30) {
    		cardVersion = HexUtils.hexify(new byte[] { atrBytes[15] }, false) + "." + HexUtils.hexify(new byte[] { atrBytes[16] }, false); //$NON-NLS-1$
    		JmcLogger.info(
				CeresSc.class.getName(),
				"checkAtr", //$NON-NLS-1$
				"Encontrada TC CERES en version " + cardVersion //$NON-NLS-1$
			);
			return;
		}
    	throw new InvalidCardException("CERES", ATR_TC, atrBytes); //$NON-NLS-1$
    }

    @Override
	public String toString() {
    	return "Tarjeta FNMT CERES" + (cardVersion != null ? " version " + cardVersion : ""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }
}
