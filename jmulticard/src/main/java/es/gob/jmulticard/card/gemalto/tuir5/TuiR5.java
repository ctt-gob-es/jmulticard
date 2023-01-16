package es.gob.jmulticard.card.gemalto.tuir5;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.gemalto.GemaltoVerifyApduCommand;
import es.gob.jmulticard.apdu.gemalto.MseSetSignatureKeyApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.AbstractIso7816FourCard;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.CardNotPresentException;
import es.gob.jmulticard.connection.NoReadersFoundException;

/** Tarjeta Gemalto TUI R5 MPCOS.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TuiR5 extends AbstractIso7816FourCard implements CryptoCard {

    private static final byte[] ATR_MASK = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private static final Atr ATR = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x6F, (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0x66, (byte) 0xB0, (byte) 0x07, (byte) 0x01, (byte) 0x01,
        (byte) 0x77, (byte) 0x07, (byte) 0x53, (byte) 0x02, (byte) 0x31, (byte) 0x10, (byte) 0x82, (byte) 0x90, (byte) 0x00
    }, ATR_MASK);

    private static final byte[][] APPLETS_AIDS = {
    	{ (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x0E, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x63, (byte) 0x42, (byte) 0x00 },
    	{ (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x0F, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x63, (byte) 0x42, (byte) 0x00 },
    	{ (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x0C, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x63, (byte) 0x42, (byte) 0x00 }
	};

    private static final Location CDF_LOCATION = new Location("50005003"); //$NON-NLS-1$

    private static final byte CLA = (byte) 0x00;

    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private transient final PasswordCallback passwordCallback;

    private static final Map<String, X509Certificate> CERTIFICATES_BY_ALIAS = new ConcurrentHashMap<>();

    /** Manejador de funciones criptogr&aacute;ficas. */
    private final CryptoHelper cryptoHelper;

	/** Construye un objeto que representa una tarjeta Gemalto TUI R5 MPCOS.
     * @param conn Conexi&oacute;n con la tarjeta.
	 * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TUI.
	 * @param cryptoHlpr Manejador de funciones criptogr&aacute;ficas.
	 * @throws Iso7816FourCardException Cuando hay errores relativos a la ISO-7816-4.
	 * @throws IOException Si hay errores de entrada / salida. */
	public TuiR5(final ApduConnection conn,
			     final PasswordCallback pwc,
			     final CryptoHelper cryptoHlpr) throws Iso7816FourCardException, IOException {
		super(CLA, conn);

		cryptoHelper = cryptoHlpr;

		if (pwc == null) {
			throw new IllegalArgumentException("El PasswordCallback no puede ser nulo"); //$NON-NLS-1$
		}
		passwordCallback = pwc;

		// Conectamos
		connect(conn);

		// Seleccionamos el Applet GemXpresso
		selectPkcs15Applet();

		// Precargamos los certificados
		preloadCertificates();

//		LOGGER.info("Intentos de PIN restantes: " + getRemainingPinRetries()); //$NON-NLS-1$
//
//    	verifyPin(this.passwordCallback);
//
//    	// Precargamos las referencias a las claves privadas
//    	loadKeyReferences();

	}

    /** Conecta con el lector del sistema que tenga una TUI insertada.
     * @param conn Conexi&oacute;n hacia la TUI
     * @throws IOException Cuando hay errores de entrada / salida. */
    private void connect(final ApduConnection conn) throws IOException {
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
        catch (final Asn1Exception | TlvException e) {
        	throw new IOException("Error en la lectura del CDF", e); //$NON-NLS-1$
		}

        for (int i=0; i<cdf.getCertificateCount(); i++) {
        	try {
				CERTIFICATES_BY_ALIAS.put(
					cdf.getCertificateAlias(i),
					cryptoHelper.generateCertificate(
						selectFileByLocationAndRead(new Location(cdf.getCertificatePath(i)))
					)
				);
			}
        	catch (final CertificateException e) {
				throw new IOException("Error en la lectura del certificado " + i + " del dispositivo", e); //$NON-NLS-1$ //$NON-NLS-2$
			}
        }
    }

    private void selectPkcs15Applet() throws ApduConnectionException, InvalidCardException, Iso7816FourCardException {
    	// Seleccionamos el Applet TUI, probando los identificadores conocidos
    	for (final byte[] aid : APPLETS_AIDS) {
    		try {
				selectFileByName(aid);
				return;
			}
    		catch (final FileNotFoundException e) {
    			LOGGER.info(
					"Aplicacion no encontrada con AID '" + HexUtils.hexify(aid, false) + "': " + e //$NON-NLS-1$ //$NON-NLS-2$
				);
				continue;
			}
    	}
    	throw new InvalidCardException("La tarjeta no contiene ningun Applet PKCS#15 de identificador conocido"); //$NON-NLS-1$
    }

    @Override
	public String[] getAliases() {
		return CERTIFICATES_BY_ALIAS.keySet().toArray(new String[0]);
	}

	@Override
	public X509Certificate getCertificate(final String alias) {
		return CERTIFICATES_BY_ALIAS.get(alias);
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias) throws CryptoCardException {
		if (alias == null) {
			throw new IllegalArgumentException("El alias no puede ser nulo"); //$NON-NLS-1$
		}
		if (!CERTIFICATES_BY_ALIAS.containsKey(alias)) {
			LOGGER.warning("La tarjeta no contiene el alias '" + alias + "', se devolvera null"); //$NON-NLS-1$ //$NON-NLS-2$
			return null;
		}
		final String aliases[] = getAliases();
		byte index = (byte) 0xff;
		for (int i=0;i<aliases.length;i++) {
			if (alias.equals(aliases[i])) {
				index = (byte) i;
				break;
			}
		}
		if (index == (byte) 0xff) {
			throw new IllegalStateException("La tarjeta no contiene el alias: " + alias); //$NON-NLS-1$
		}
		final MseSetSignatureKeyApduCommand mseSet = new MseSetSignatureKeyApduCommand(
			CLA,
			MseSetSignatureKeyApduCommand.CryptographicMechanism.RSASSA_PKCS1V1_5_SHA1,
			index
		);
		final ResponseApdu res;
		try {
			res = sendArbitraryApdu(mseSet);
		}
		catch (final ApduConnectionException e) {
			throw new CryptoCardException("Error enviando la APDU de establecimiento de clave privada para firma", e); //$NON-NLS-1$
		}
		if (res.isOk()) {
			return new TuiPrivateKeyReference(index);
		}
		throw new CryptoCardException(
			"No se ha podido recuperar la referencia a la clave privada: " + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
		);
	}

	@Override
	public byte[] sign(final byte[] data,
			           final String algorithm,
			           final PrivateKeyReference keyRef) throws CryptoCardException {
		if (keyRef == null) {
			throw new IllegalArgumentException("La referencia a la clave privada no puede ser nula"); //$NON-NLS-1$
		}
		if (!(keyRef instanceof TuiPrivateKeyReference)) {
			throw new CryptoCardException(
				"Solo se admiten claves privadas de tipo TuiPrivateKeyReference, pero se encontro: " + keyRef.getClass().getName() //$NON-NLS-1$
			);
		}
		// TODO: Implementar
		return null;
	}

	@Override
	protected void selectMasterFile() throws ApduConnectionException {
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

    @Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException, BadPinException {
		final GemaltoVerifyApduCommand verifyPinApduCommand = new GemaltoVerifyApduCommand(
			CLA,
			passwordCallback
		);
		final ResponseApdu verifyResponse = getConnection().transmit(
			verifyPinApduCommand
		);
		if (!verifyResponse.isOk()) {
			throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
		}
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder(getCardName())
		 .append("\n Tarjeta con ").append(CERTIFICATES_BY_ALIAS.size()).append(" certificado(s):\n"); //$NON-NLS-1$ //$NON-NLS-2$
		final String[] aliases = getAliases();
		for (int i=0;i<aliases.length;i++) {
			sb.append("  "); //$NON-NLS-1$
			sb.append(i+1);
			sb.append(" - "); //$NON-NLS-1$
			sb.append(aliases[i]);
		}
		return sb.toString();
	}

}
