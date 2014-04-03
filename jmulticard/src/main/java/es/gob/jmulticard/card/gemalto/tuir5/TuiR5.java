package es.gob.jmulticard.card.gemalto.tuir5;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.apdu.gemalto.CheckVerifyRetriesLeftApduCommand;
import es.gob.jmulticard.apdu.gemalto.VerifyApduCommand;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.card.iso7816four.RequiredSecurityStateNotSatisfiedException;

/** Tarjeta Gemalto TUI R5 MPCOS.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TuiR5 extends Iso7816FourCard implements CryptoCard {

    private static final byte[] ATR_MASK = new byte[] {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private static final Atr ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x6F, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x66, (byte) 0xB0, (byte) 0x07, (byte) 0x01, (byte) 0x01,
        (byte) 0x77, (byte) 0x07, (byte) 0x53, (byte) 0x02, (byte) 0x31, (byte) 0x10, (byte) 0x82, (byte) 0x90, (byte) 0x00
    }, ATR_MASK);

    private static final byte[][] APPLETS_AIDS = new byte[][] {
    	{ (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x0E, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x63, (byte) 0x42, (byte) 0x00 },
    	{ (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x0F, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x63, (byte) 0x42, (byte) 0x00 },
    	{ (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x0C, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x63, (byte) 0x42, (byte) 0x00 }
	};

    private static final Location   CDF_LOCATION = new Location("50005003"); //$NON-NLS-1$
    private static final Location PRKDF_LOCATION = new Location("50005001"); //$NON-NLS-1$

    private static byte CLA = (byte) 0x00;

    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private final PasswordCallback passwordCallback;

    private static final Map<String, X509Certificate> certificatesByAlias = new LinkedHashMap<String, X509Certificate>();

	/** Construye una clase que representa una tarjeta Gemalto TUI R5 MPCOS.
     * @param conn Conexi&oacute;n con la tarjeta
	 * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TUI
	 * @throws Iso7816FourCardException Cuando hay errores relativos a la ISO-7816-4
	 * @throws IOException Si hay errores de entrada / salida */
	public TuiR5(final ApduConnection conn, final PasswordCallback pwc) throws Iso7816FourCardException, IOException {
		super((byte) 0x00, conn);

		if (pwc == null) {
			throw new IllegalArgumentException("El PasswordCallback no puede ser nulo"); //$NON-NLS-1$
		}
		this.passwordCallback = pwc;

		// Conectamos
		connect(conn);

		// Seleccionamos el Applet GemXpresso
		selectPkcs15Applet();

		// Precargamos los certificados
		preloadCertificates();

		LOGGER.info("Intentos de PIN restantes: " + getRemainingPinRetries()); //$NON-NLS-1$

    	verifyPin(this.passwordCallback);

    	// Precargamos las referencias a las claves privadas
    	loadKeyReferences();

	}

    /** Conecta con el lector del sistema que tenga una TUI insertada.
     * @throws Iso7816FourCardException
     * @throws IOException Cuando hay errores de entrada / salida */
    private void connect(final ApduConnection conn) throws Iso7816FourCardException, IOException {
    	if (conn == null) {
    		throw new IllegalArgumentException("La conexion no puede ser nula"); //$NON-NLS-1$
    	}

    	final long[] terminals = conn.getTerminals(false);
    	if (terminals.length < 1) {
    	    throw new NoReadersFoundException();
    	}

    	byte[] responseAtr;
    	Atr actualAtr;
    	InvalidCardException invalidCardException = null;
    	CardNotPresentException cardNotPresentException = null;
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
    		if (!ATR.equals(actualAtr)) { // La tarjeta encontrada no es una TUI
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
    	throw new ApduConnectionException("No se ha podido conectar con ningun lector de tarjetas"); //$NON-NLS-1$

    }

    private void preloadCertificates() throws IOException, Iso7816FourCardException {
    	selectMasterFile();
        final Cdf cdf = new Cdf();
        try {
			cdf.setDerValue(selectFileByLocationAndRead(CDF_LOCATION));
		}
        catch (final Exception e) {
        	throw new IOException("Error en la lectura del CDF: " + e, e); //$NON-NLS-1$
		}

        final CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		}
		catch (final CertificateException e) {
			throw new IOException("Error obteniendo la factoria de certificados X.509: " + e, e); //$NON-NLS-1$
		}
        for (int i=0; i<cdf.getCertificateCount(); i++) {
        	try {
				certificatesByAlias.put(
					cdf.getCertificateAlias(i),
					(X509Certificate) cf.generateCertificate(
						new ByteArrayInputStream(
							selectFileByLocationAndRead(new Location(cdf.getCertificatePath(i)))
						)
					)
				);
			}
        	catch (final CertificateException e) {
				throw new IOException("Error en la lectura del certificado " + i + " del dispositivo: " + e, e); //$NON-NLS-1$ //$NON-NLS-2$
			}
        }
    }

    private void selectPkcs15Applet() throws ApduConnectionException, InvalidCardException {
    	// Seleccionamos el Applet TUI, probando los identificadores conocidos
    	for (final byte[] aid : APPLETS_AIDS) {
    		try {
				selectFileByName(aid);
				return;
			}
    		catch (final FileNotFoundException e) {
				continue;
			}
    	}
    	throw new InvalidCardException("La tarjeta no contiene ningun Applet PKCS#15 de identificador conocido"); //$NON-NLS-1$
    }

    /** Carga la informaci&oacute;n p&uacute;blica con la referencia a las claves de firma. */
    private void loadKeyReferences() {
        final PrKdf prKdf = new PrKdf();
        try {
            prKdf.setDerValue(selectFileByLocationAndRead(PRKDF_LOCATION));
        }
        catch(final RequiredSecurityStateNotSatisfiedException e) {
        	throw new SecurityException("Se necesita PIN"); //$NON-NLS-1$
        }
        catch (final Exception e) {
            throw new IllegalStateException("No se ha podido cargar el PrKDF de la tarjeta: " + e.toString()); //$NON-NLS-1$
        }
    }

	@Override
	public String[] getAliases() throws CryptoCardException {
		return certificatesByAlias.keySet().toArray(new String[0]);
	}

	@Override
	public X509Certificate getCertificate(final String alias) throws CryptoCardException, BadPinException {
		return certificatesByAlias.get(alias);
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias) throws CryptoCardException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] sign(final byte[] data, final String algorithm, final PrivateKeyReference keyRef)
			throws CryptoCardException, BadPinException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void selectMasterFile() throws ApduConnectionException, FileNotFoundException {
		final CommandApdu selectMf = new CommandApdu(
			CLA,
			(byte) 0xA4,
			(byte) 0x08,
			(byte) 0x0C,
			new byte[] { (byte) 0x50, (byte) 0x00, (byte) 0x50, (byte) 0x01},
			null
		);
		sendArbitraryApdu(selectMf);
	}

	@Override
	public String getCardName() {
		return "Gemalto TUI R5 (MPCOS)"; //$NON-NLS-1$
	}

    /** Obtiene el n&uacute;mero de intentos restantes para introducci&oacute;n del PIN.
     * @return N&uacute;mero de intentos restantes para introducci&oacute;n del PIN
     * @throws ApduConnectionException Si se recibe una respuesta inesperada o hay errores de comunicaci&oacute; con la tarjeta */
    private int getRemainingPinRetries() throws ApduConnectionException {
    	final CheckVerifyRetriesLeftApduCommand retriesLeftCommandApdu = new CheckVerifyRetriesLeftApduCommand((byte) 0x00);
    	System.out.println(HexUtils.hexify(retriesLeftCommandApdu.getBytes(), true));
    	final ResponseApdu verifyResponse = this.getConnection().transmit(
			retriesLeftCommandApdu
    	);
    	if (verifyResponse.getStatusWord().getMsb() == (byte) 0x63) {
    		return verifyResponse.getStatusWord().getLsb() - (byte) 0xC0;
    	}
    	throw new ApduConnectionException("Respuesta desconocida: " + HexUtils.hexify(verifyResponse.getBytes(), true)); //$NON-NLS-1$
    }

	@Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException, BadPinException {
		final VerifyApduCommand verifyPinApduCommand = new VerifyApduCommand(
			CLA,
			this.passwordCallback
		);
		final ResponseApdu verifyResponse = this.getConnection().transmit(
			verifyPinApduCommand
		);
		if (!verifyResponse.isOk()) {
			throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
		}
	}

}
