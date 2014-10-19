package es.gob.jmulticard.card.cardos;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionProtocol;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs15.Odf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta Atos / Siemens CardOS.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CardOS extends Iso7816FourCard implements CryptoCard {

    private static final byte[] ATR_MASK = new byte[] {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private static final Atr ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0xD2, (byte) 0x18, (byte) 0x00, (byte) 0x81, (byte) 0x31,
        (byte) 0xFE, (byte) 0x58, (byte) 0xC9, (byte) 0x01, (byte) 0x14
    }, ATR_MASK);

    private static final byte[] PKCS15_NAME = new byte[] {
		(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x63, (byte) 0x50,
		(byte) 0x4B, (byte) 0x43, (byte) 0x53, (byte) 0x2D, (byte) 0x31, (byte) 0x35
	};

    private static byte CLA = (byte) 0x00;

    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private final PasswordCallback passwordCallback;

    private static final Map<String, X509Certificate> certificatesByAlias = new LinkedHashMap<String, X509Certificate>();

	/** Construye un objeto que representa una tarjeta Atos / Siemens CardOS.
     * @param conn Conexi&oacute;n con la tarjeta.
	 * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TUI.
	 * @throws Iso7816FourCardException Cuando hay errores relativos a la ISO-7816-4.
	 * @throws IOException Si hay errores de entrada / salida. */
	public CardOS(final ApduConnection conn, final PasswordCallback pwc) throws Iso7816FourCardException, IOException {
		super(CLA, conn);
		if (pwc == null) {
			throw new IllegalArgumentException("El PasswordCallback no puede ser nulo"); //$NON-NLS-1$
		}
		this.passwordCallback = pwc;

		// Conectamos
		connect(conn);

		// Precargamos los certificados
		try {
			preloadCertificates();
		}
		catch (final Asn1Exception e) {
			throw new IOException("Error creando las estructuras ASN.1: " + e, e); //$NON-NLS-1$
		}
		catch (final TlvException e) {
			throw new IOException("Error tratando los TLV internos de las estructuras ASN.1: " + e, e); //$NON-NLS-1$
		}

	}

    /** Conecta con el lector del sistema que tenga una CardOS insertada.
     * @param conn Conexi&oacute;n hacia la tarjeta.
     * @throws Iso7816FourCardException Si hay errores en el di&aacute;logo ISO 7816-4.
     * @throws IOException Cuando hay errores de entrada / salida. */
    private void connect(final ApduConnection conn) throws Iso7816FourCardException, IOException {
    	if (conn == null) {
    		throw new IllegalArgumentException("La conexion no puede ser nula"); //$NON-NLS-1$
    	}

    	// Siemens CardOS son T=1
    	conn.setProtocol(ApduConnectionProtocol.T1);

    	final long[] terminals = conn.getTerminals(false);
    	if (terminals.length < 1) {
    	    throw new NoReadersFoundException();
    	}

    	byte[] responseAtr;
    	Atr actualAtr;
    	InvalidCardException invalidCardException = null;
    	CardNotPresentException cardNotPresentException = null;
    	ApduConnectionException apduConnectionException = null;
    	for (final long terminal : terminals) {
    		conn.setTerminal((int) terminal);
    		try {
    			responseAtr = conn.reset();
    		}
    		catch(final CardNotPresentException e) {
    			cardNotPresentException = e;
    			continue;
    		}
    		catch(final ApduConnectionException e) {
    			apduConnectionException = e;
    			continue;
    		}
    		actualAtr = new Atr(responseAtr, ATR_MASK);
    		if (!ATR.equals(actualAtr)) { // La tarjeta encontrada no es una CardOS
    			invalidCardException = new InvalidCardException(getCardName(), ATR, responseAtr);
    			continue;
    		}
    		return;
    	}
    	if (invalidCardException != null) {
    		throw invalidCardException;
    	}
    	if (cardNotPresentException != null) {
    		throw cardNotPresentException;
    	}
    	if (apduConnectionException != null) {
    		throw apduConnectionException;
    	}
    	throw new ApduConnectionException("No se ha podido conectar con ningun lector de tarjetas"); //$NON-NLS-1$
    }

    private void preloadCertificates() throws FileNotFoundException, Iso7816FourCardException, IOException, Asn1Exception, TlvException {
    		// Entramos en el directorio PKCS#15
			selectFileByName(PKCS15_NAME);

			// Seleccionamos el ODF, no nos devuelve FCI ni nada
			selectFileById(new byte[] { (byte) 0x50, (byte) 0x31 });

			// Leemos el ODF, que tiene esta estructura en cada uno de sus registros:
    		// PKCS15Objects ::= CHOICE {
    		//		privateKeys         [0] PrivateKeys,
    		//		publicKeys          [1] PublicKeys,
    		//		trustedPublicKeys   [2] PublicKeys,
    		//		secretKeys          [3] SecretKeys,
    		//		certificates        [4] Certificates,
    		//		trustedCertificates [5] Certificates,
    		//		usefulCertificates  [6] Certificates,
    		//		dataObjects         [7] DataObjects,
    		//		authObjects         [8] AuthObjects,
    		//		... -- For future extensions
    		// }
			final byte[] odfBytes = readBinaryComplete(162); // A2

//			System.out.println(HexUtils.hexify(c, true));
//			final java.io.OutputStream fos = new FileOutputStream(File.createTempFile("ODF_", ".asn1"));  //$NON-NLS-1$//$NON-NLS-2$
//			fos.write(c);
//			fos.flush();
//			fos.close();

			final Odf odf = new Odf();
			odf.setDerValue(odfBytes);

    }

	@Override
	public String getCardName() {
		return "Atos / Siemens CardOS"; //$NON-NLS-1$
	}

	@Override
	public String[] getAliases() throws CryptoCardException {
		throw new UnsupportedOperationException();
	}

	@Override
	public X509Certificate getCertificate(final String alias) throws CryptoCardException, BadPinException {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias) throws CryptoCardException {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] sign(final byte[] data, final String algorithm, final PrivateKeyReference keyRef) throws CryptoCardException, BadPinException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void selectMasterFile() throws ApduConnectionException, FileNotFoundException, Iso7816FourCardException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException, BadPinException {
		throw new UnsupportedOperationException();
	}

}
