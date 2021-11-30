package es.gob.jmulticard.card.bit4id.stcm;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.bit4id.stcm.VerifyApduCommand;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tajeta de <a href="http://www.bit4id.com/">Bit4Id</a> con chip <a href="http://www.st.com/">ST</a>
 *  distribuida por <a href="http://www.camerfirma.com/">CamerFirma</a>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class StCard extends Iso7816FourCard implements CryptoCard {

	private static byte CLA = (byte) 0x00;

    /** Octeto que identifica una verificaci&oacute;n fallida del PIN */
    private final static byte ERROR_PIN_SW1 = (byte) 0x63;

	/** Construye una tajeta de <a href="http://www.bit4id.com/">Bit4Id</a> con chip <a href="http://www.st.com/">ST</a>
     *  distribuida por <a href="http://www.camerfirma.com/">CamerFirma</a>.
	 * @param conn Conexi&oacute;n hacia la tarjeta.
	 * @throws IOException Si hay errores en el di&aacute;logo ISO 7816-4.
	 * @throws Iso7816FourCardException Cuando hay errores de entrada / salida. */
	public StCard(final ApduConnection conn) throws Iso7816FourCardException, IOException {
		super(CLA, conn);
		connect(conn);
		final byte[] b1 = selectFileByLocationAndRead(new Location("2FFF0000")); //$NON-NLS-1$
		try (
			final FileOutputStream fos = new FileOutputStream(java.io.File.createTempFile("0000_", ".DER")) //$NON-NLS-1$ //$NON-NLS-2$
		) {
			fos.write(b1);
			fos.flush();
		}
		System.out.println(HexUtils.hexify(b1, true));
		System.out.println("LEN: " + b1.length); //$NON-NLS-1$
	}

    /** Conecta con el lector del sistema que tenga una CardOS insertada.
     * @param conn Conexi&oacute;n hacia la tarjeta.
     * @throws IOException Cuando hay errores de entrada / salida. */
    private static void connect(final ApduConnection conn) throws IOException {
    	if (conn == null) {
    		throw new IllegalArgumentException("La conexion no puede ser nula"); //$NON-NLS-1$
    	}
    	conn.open();
    }

	@Override
	public String[] getAliases() {
		throw new UnsupportedOperationException();
	}

	@Override
	public X509Certificate getCertificate(final String alias) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] sign(final byte[] data, final String algorithm,
			           final PrivateKeyReference keyRef) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void selectMasterFile() {
		//throw new UnsupportedOperationException();
	}

	@Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException,
	                                                           PinException {
		if (pinPc == null) {
			throw new BadPinException("No se ha establecido un PasswordCallback"); //$NON-NLS-1$
		}
		final CommandApdu chv = new VerifyApduCommand(CLA, pinPc);
		final ResponseApdu verifyResponse = sendArbitraryApdu(chv);
        if (!verifyResponse.isOk()) {
            if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
            	throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
            }
            throw new ApduConnectionException(
        		"Error en el envio de la verificacion de PIN con respuesta: " + //$NON-NLS-1$
    				verifyResponse.getStatusWord()
    		);
        }
	}

	@Override
	public String getCardName() {
		return "Bit4ID con chip ST para CamerFirma"; //$NON-NLS-1$
	}

}
