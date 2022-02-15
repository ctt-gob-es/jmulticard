package es.gob.jmulticard.card.gide.smartcafe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.CertificateUtils;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.gide.RetriesLeftApduCommand;
import es.gob.jmulticard.apdu.gide.VerifyApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetComputationApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse;
import es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Odf;
import es.gob.jmulticard.asn1.der.pkcs15.Path;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta G&amp;D SmartCafe con Applet PKCS#15.
 * @author Vicente Ortiz
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SmartCafePkcs15Applet extends Iso7816FourCard implements CryptoCard {

	private static final byte[] ATR_MASK = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xf
	};

	/** ATR de tarjeta G&amp;D SmartCafe 3&#46;2. */
	private static final Atr ATR = new Atr(new byte[] {
		(byte) 0x3b, (byte) 0xf7, (byte) 0x18, (byte) 0x00, (byte) 0x00, (byte) 0x80,
		(byte) 0x31, (byte) 0xfe, (byte) 0x45, (byte) 0x73, (byte) 0x66, (byte) 0x74,
		(byte) 0x65, (byte) 0x2d, (byte) 0x6e, (byte) 0x66, (byte) 0xc4
	}, ATR_MASK);

	private static final byte[] ATR_MASK_MSC = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};

	/** ATR de tarjeta MicroSD G&amp;D Mobile Security Card. */
	private static final Atr ATR_MSC = new Atr(new byte[] {
		(byte) 0x3b, (byte) 0x80, (byte) 0x80, (byte) 0x01, (byte) 0x01
	}, ATR_MASK_MSC);

	/** ATR de tarjeta G&amp;D SmartCafe 3&#46;2 con T=CL (v&iacute;a inal&aacute;mbrica). */
	private static final byte[] ATR_MASK_TCL = {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xf
	};

	private static final Atr ATR_TCL = new Atr(new byte[] {
		(byte) 0x3b, (byte) 0xf7, (byte) 0x18, (byte) 0x00, (byte) 0x00, (byte) 0x80,
		(byte) 0x31, (byte) 0xfe, (byte) 0x45, (byte) 0x73, (byte) 0x66, (byte) 0x74,
		(byte) 0x65, (byte) 0x2d, (byte) 0x6e, (byte) 0x66, (byte) 0xc4
	}, ATR_MASK_TCL);

    private static final byte[] PKCS15_NAME = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x63, (byte) 0x50,
        (byte) 0x4B, (byte) 0x43, (byte) 0x53, (byte) 0x2D, (byte) 0x31, (byte) 0x35
    };

    private static final byte[] ODF_PATH = { (byte) 0x50, (byte) 0x31 };
    private static final byte[] MF_PATH  = { (byte) 0x3F, (byte) 0x00 };

    private static byte CLA = (byte) 0x00;

    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private static final Map<String, X509Certificate> CERTS_BY_ALIAS = new LinkedHashMap<>();
    private static final Map<String, Integer> KEYNO_BY_ALIAS = new LinkedHashMap<>();

    /** Octeto que identifica una verificaci&oacute;n fallida del PIN. */
    private final static byte ERROR_PIN_SW1 = (byte) 0x63;

    private PasswordCallback passwordCallback = null;
    private CallbackHandler callbackHandler = null;

    private boolean authenticated = false;

    /** Manejador de funciones criptogr&aacute;ficas. */
    protected final CryptoHelper cryptoHelper;

    /** Construye un objeto que representa una tarjeta G&amp;D SmartCafe con el
     * Applet PKCS#15 de AET.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que
     *                     pueden variar entre m&aacute;quinas virtuales.
     * @throws IOException Si hay errores de entrada / salida. */
    public SmartCafePkcs15Applet(final ApduConnection conn,
    		                     final CryptoHelper cryptoHelper) throws IOException {
    	this(conn, cryptoHelper, true);
    }

    /** Construye un objeto que representa una tarjeta G&amp;D SmartCafe con el
     * Applet PKCS#15 de AET.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que
     *                     pueden variar entre m&aacute;quinas virtuales.
     * @param failIfNoCerts Si se establece a <code>true</code> y la tarjeta no
     *                      contiene ningun par certificado + clave privada la
     *                      inicializaci&oacute;n falla con un <code>IOException</code>,
     *                      si se establece a <code>false</code>, la inicializaci&oacute;n
     *                      se completa haya o no haya claves y certificados.
     * @throws IOException Si hay errores de entrada / salida. */
    public SmartCafePkcs15Applet(final ApduConnection conn,
    		                     final CryptoHelper cryptoHelper,
    		                     final boolean failIfNoCerts) throws IOException {
        super(CLA, conn);

        if (cryptoHelper == null) {
            throw new IllegalArgumentException("El CryptoHelper no puede ser nulo"); //$NON-NLS-1$
        }
        this.cryptoHelper = cryptoHelper;

        // Conectamos
        conn.reset();
        connect(conn);

        try {
            selectFileByName(PKCS15_NAME);
        }
        catch (final Iso7816FourCardException e) {
        	 throw new IOException(
                "No se ha podido seleccionar el Applet AET PKCS#15: " + e, e //$NON-NLS-1$
            );
        }

        // Cargamos los certificados
        try {
			preloadCertificates();
		}
        catch (final Iso7816FourCardException | Asn1Exception | TlvException e) {
            throw new IOException(
        		"No se han podido leer los certificados: " + e, e //$NON-NLS-1$
    		);
        }

        // Miramos cuantas claves hay en la tarjeta
        final int keyCount = getKeyCount(
    		sendArbitraryApdu(
	    		new CommandApdu(
					new byte[] {
						(byte) 0x00, (byte)0xCA, (byte)0x01, (byte)0x02, (byte)0x06
					}
				)
    		)
		);

        LOGGER.info(
    		"Se ha" + (keyCount > 1 ? "n" : "") + " encontrado " + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
				keyCount + " clave" + (keyCount > 1 ? "s" : "") + " y " + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
    				CERTS_BY_ALIAS.size() + " certificado" + (CERTS_BY_ALIAS.size() > 1 ? "s" : "") + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    					" en la tarjeta"); //$NON-NLS-1$

        // Buscamos las claves publicas de las claves y guardamos su ordinal comparado
        // con el alias del certificado que tenga la misma clave publica
        for (int i=0;i<keyCount;i++) {
        	final ResponseApdu res = sendArbitraryApdu(
    			new CommandApdu(
					new byte[] {
						(byte) 0x80,
						(byte) 0x3A,
						(byte) i,    // Ordinal de la clave
						(byte) 0x01, // 02=Exponente, 01=Modulo
						(byte) 0x00
					}
				)
			);
        	if (!res.isOk()) {
        		LOGGER.severe(
    				"Error obteniendo el modulo de la clave " + i + ": " + res //$NON-NLS-1$ //$NON-NLS-2$
				);
        		continue;
        	}

        	// En Java los BigInteger tienen signo, metemos un 0x00 antes para indicar
        	// que es positivo
        	final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        	baos.write((byte)0x00);
        	baos.write(res.getData());
        	final BigInteger modulus = new BigInteger(baos.toByteArray());

        	// Almacenamos el numero de clave asociado con el alias del certificado
        	// correspondiente
        	storeKeyOrdinal(i, modulus);
        }

    	// Limpiamos los certificados sin claves
        final Set<String> aliases = CERTS_BY_ALIAS.keySet();
        for (final String alias : aliases) {
        	if (!KEYNO_BY_ALIAS.containsKey(alias)) {
        		LOGGER.info(
    				"El certificado '" + alias + "' se descarta por carecer de clave privada" //$NON-NLS-1$ //$NON-NLS-2$
				);
        		CERTS_BY_ALIAS.remove(alias);
        	}
        }

        if (aliases.isEmpty()) {
        	throw new IOException(
    			"La tarjeta no contiene claves" //$NON-NLS-1$
			);
        }
    }

    private static void storeKeyOrdinal(final int ordinal, final BigInteger publicKeyModulus) {
    	final Set<String> aliases = CERTS_BY_ALIAS.keySet();
    	for (final String alias : aliases) {
    		final PublicKey publicKey = CERTS_BY_ALIAS.get(alias).getPublicKey();
    		if (publicKey instanceof RSAPublicKey) {
    			final BigInteger certPublicKeyModulus = ((RSAPublicKey)publicKey).getModulus();
    			if (certPublicKeyModulus.equals(publicKeyModulus)) {
    				KEYNO_BY_ALIAS.put(alias, Integer.valueOf(ordinal));
    			}
    		}
    	}
    }

    private static int getKeyCount(final ResponseApdu ra) throws IOException {
    	if (!ra.isOk()) {
    		throw new IOException(
				"No se ha podido determinar el numero de claves en tarjeta: " + HexUtils.hexify(ra.getBytes(), true) //$NON-NLS-1$
			);
    	}
    	final byte[] res = ra.getData();
    	if (
			res.length == 6 &&
			res[0] == (byte)0x7F &&
			res[1] == (byte)0xFF &&
			res[2] == (byte)0x20 &&
			res[4] == (byte)0x0C &&
			res[5] == (byte)0x0B
		) {
    		return 0x20 - res[3];
    	}
    	throw new IOException(
			"No se ha podido determinar el numero de claves en tarjeta: " + HexUtils.hexify(ra.getBytes(), true) //$NON-NLS-1$
		);
    }

	/** Establece el <code>PasswordCallback</code> para el PIN de la tarjeta.
     * @param pwc <code>PasswordCallback</code> para el PIN de la tarjeta. */
    public void setPasswordCallback(final PasswordCallback pwc) {
    	this.passwordCallback = pwc;
    }

    /** Establece el <code>CallbackHandler</code>.
     * @param callh <code>CallbackHandler</code> a establecer. */
	public void setCallbackHandler(final CallbackHandler callh) {
		this.callbackHandler = callh;
	}

    /** Conecta con el lector del sistema que tenga una tarjeta insertada.
     * @param conn Conexi&oacute;n hacia la tarjeta.
     * @throws IOException Cuando hay errores de entrada / salida. */
    public static void connect(final ApduConnection conn) throws IOException {
        if (conn == null) {
            throw new IllegalArgumentException("La conexion no puede ser nula"); //$NON-NLS-1$
        }
        if (!conn.isOpen()) {
            conn.open();
        }
        checkAtr(conn.reset());
    }

    private void preloadCertificates() throws FileNotFoundException,
                                              Iso7816FourCardException,
                                              IOException,
                                              Asn1Exception,
                                              TlvException {
        selectMasterFile();

        // Seleccionamos el ODF, no nos devuelve FCI ni nada
        selectFileById(ODF_PATH);

        // Leemos el ODF
        final byte[] odfBytes = readBinaryComplete(162);
        final Odf odf = new Odf();
        odf.setDerValue(odfBytes);

        // Sacamos del ODF la ruta del CDF
        final Path cdfPath = odf.getCdfPath();

        // Leemos el CDF
        final Cdf cdf = new Cdf();
        try {
            selectMasterFile();
            final byte[] cdfBytes = selectFileByIdAndRead(cdfPath.getPathBytes());
            cdf.setDerValue(cdfBytes);
        }
        catch (final Exception e) {
            throw new ApduConnectionException(
                "No se ha podido cargar el CDF de la tarjeta: " + e, e //$NON-NLS-1$
            );
        }

        if (cdf.getCertificateCount() < 1) {
        	LOGGER.warning("La tarjeta no contiene ningun certificado"); //$NON-NLS-1$
        }
        for (int i = 0; i < cdf.getCertificateCount(); i++) {
            try {
            	int fileLength = -1;
            	Location certLocation = new Location(cdf.getCertificatePath(i));
                while (certLocation != null) {
                    final byte[] id = certLocation.getFile();
                    try {
                    	fileLength = selectFileById(id);
                    }
                    catch(final FileNotFoundException e) {
                    	System.out.println(
                			"El CDF indicaba un certificado en la ruta '" + certLocation + "', pero un elemento de esta no existe, se ignorara: " + e //$NON-NLS-1$//$NON-NLS-2$
            			);
                    }
                    certLocation = certLocation.getChild();
                }

                final byte[] certBytes;
                if (fileLength <= 0) {
                	// A veces hay punteros que apuntan a localizaciones vacias
                	LOGGER.warning(
            			"El certificado " + i + " del dispositivo esta vacio" //$NON-NLS-1$ //$NON-NLS-2$
        			);
                	continue;
                }
				certBytes = readBinaryComplete(fileLength);

                CERTS_BY_ALIAS.put(
                    cdf.getCertificateAlias(i),
                    CertificateUtils.generateCertificate(certBytes)
                );
            }
            catch (final Exception e) {
            	// Puede darse el caso de que el puntero apunte a algo que no es un certificado
                LOGGER.severe(
            		"Error en la lectura del certificado " + i + " del dispositivo: " + e //$NON-NLS-1$ //$NON-NLS-2$
        		);
                continue;
            }
        }

    }

    @Override
    public String getCardName() {
        return "G&D SmartCafe 3.2 (PKCS#15 Applet)"; //$NON-NLS-1$
    }

    @Override
    public String[] getAliases() {
        return CERTS_BY_ALIAS.keySet().toArray(new String[0]);
    }

    @Override
    public X509Certificate getCertificate(final String alias) {
        return CERTS_BY_ALIAS.get(alias);
    }

    @Override
    protected void selectMasterFile() throws ApduConnectionException, Iso7816FourCardException {
        selectFileById(MF_PATH);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(getCardName())
            .append("\n Tarjeta con ") //$NON-NLS-1$
            	.append(CERTS_BY_ALIAS.size())
            		.append(" certificado(s):\n"); //$NON-NLS-1$
        final String[] aliases = getAliases();
        for (int i = 0; i < aliases.length; i++) {
            sb.append("  "); //$NON-NLS-1$
            sb.append(i + 1);
            sb.append(" - "); //$NON-NLS-1$
            sb.append(aliases[i]);
        }
        return sb.toString();
    }

    /** Selecciona un fichero (DF o EF).
     * @param id Identificador del fichero a seleccionar.
     * @return Tama&ntilde;o del fichero seleccionado.
     * @throws ApduConnectionException Si hay problemas en el env&iacute;o de la APDU.
     * @throws Iso7816FourCardException Si falla la selecci&oacute;n de fichero. */
    @Override
    public int selectFileById(final byte[] id) throws ApduConnectionException, Iso7816FourCardException {
        final CommandApdu selectCommand = new SelectFileByIdApduCommand(getCla(), id);
        final ResponseApdu res = getConnection().transmit(selectCommand);
        if (HexUtils.arrayEquals(res.getBytes(), new byte[] { (byte) 0x6a, (byte) 0x82 })) {
            throw new FileNotFoundException(id);
        }
        final SelectFileApduResponse response = new SelectFileApduResponse(res);
        if (response.isOk()) {
        	return HexUtils.getUnsignedInt(
    			new byte[] {
					response.getData()[4],
					response.getData()[5]
				},
    			0 // Offset
			);
        }
        final StatusWord sw = response.getStatusWord();
        if (sw.equals(new StatusWord((byte) 0x6A, (byte) 0x82))) {
            throw new FileNotFoundException(id);
        }
        throw new Iso7816FourCardException(sw, selectCommand);
    }

    @Override
    public void verifyPin(final PasswordCallback psc) throws ApduConnectionException, PinException {
    	if(psc == null) {
    		throw new IllegalArgumentException(
    			"No se puede verificar el titular con un PasswordCallback nulo" //$NON-NLS-1$
        	);
    	}
    	VerifyApduCommand verifyCommandApdu = new VerifyApduCommand(psc);
    	final ResponseApdu verifyResponse = getConnection().transmit(
			verifyCommandApdu
    	);
    	verifyCommandApdu = null;
    	if (!verifyResponse.isOk()) {
    		if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
    			throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
    		}
			if (
        		verifyResponse.getStatusWord().getMsb() == (byte)0x69 &&
        		verifyResponse.getStatusWord().getLsb() == (byte)0x83
    		) {
            	throw new AuthenticationModeLockedException();
            }
			throw new ApduConnectionException(
				new Iso7816FourCardException(
					"Error en la verificacion de PIN (" + verifyResponse.getStatusWord() + ")", //$NON-NLS-1$ //$NON-NLS-2$
					verifyResponse.getStatusWord()
				)
			);
    	}
    }

    @Override
    public PrivateKeyReference getPrivateKey(final String alias) {
    	if (!KEYNO_BY_ALIAS.containsKey(alias)) {
    		return null;
    	}
    	return new SmartCafePrivateKeyReference(KEYNO_BY_ALIAS.get(alias));
    }

    @Override
    public byte[] sign(final byte[] data,
    		           final String algorithm,
    		           final PrivateKeyReference keyRef) throws CryptoCardException,
                                                                PinException {
		if (data == null) {
			throw new CryptoCardException("Los datos a firmar no pueden ser nulos"); //$NON-NLS-1$
		}
		if (keyRef == null) {
			throw new IllegalArgumentException("La clave privada no puede ser nula"); //$NON-NLS-1$
		}
		if (!(keyRef instanceof SmartCafePrivateKeyReference)) {
			throw new IllegalArgumentException(
				"La clave proporcionada debe ser de tipo " + //$NON-NLS-1$
					SmartCafePrivateKeyReference.class.getName() +
						", pero se ha recibido de tipo " + //$NON-NLS-1$
							keyRef.getClass().getName()
			);
		}

		final SmartCafePrivateKeyReference scPrivateKey = (SmartCafePrivateKeyReference) keyRef;

		// Pedimos el PIN si no se ha pedido antes
		if (!this.authenticated) {
			try {
				verifyPin(getInternalPasswordCallback());
				this.authenticated = true;
			}
			catch (final ApduConnectionException e1) {
				throw new CryptoCardException("Error en la verificacion de PIN: " + e1, e1); //$NON-NLS-1$
			}
		}

		// Enviamos el MSE SET for Computation
		ResponseApdu res = null;
		try {
			res = sendArbitraryApdu(
				new MseSetComputationApduCommand(
					(byte) 0x01, // CLA
					new byte[] { (byte) scPrivateKey.getKeyOrdinal() },
					new byte[] { (byte) 0x02 } // RSA
				)
			);
		}
		catch (final ApduConnectionException e) {
			throw new CryptoCardException(
				"Error estableciendo la clave y el algoritmo de firma (repuesta=" + res + "): " + e, e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
		if (res == null || !res.isOk()) {
			throw new CryptoCardException(
				"No se ha podido establecer la clave y el algoritmo de firma" + (res != null ? " (repuesta=" + res + ")" : "") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			);
		}

		// Creamos el DigestInfo
        final byte[] digestInfo;
        try {
            digestInfo = DigestInfo.encode(algorithm, data, this.cryptoHelper);
        }
        catch (final IOException e) {
            throw new CryptoCardException("Error en el calculo de la huella para firmar: " + e, e); //$NON-NLS-1$
        }

        // Y lo enviamos a firmar
        try {
			res = sendArbitraryApdu(new PsoSignHashApduCommand((byte) 0x01, digestInfo));
		}
        catch (final ApduConnectionException e) {
        	throw new CryptoCardException(
				"Error firmando (repuesta=" + res + "): " + e, e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
        if (res == null || !res.isOk()) {
			throw new CryptoCardException(
				"No se ha podido firmar el DigestInfo" + (res != null ? " (repuesta=" + res + ")" : "") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			);
		}

        return res.getData();
    }

    private int getPinRetriesLeft() throws PinException {
    	final CommandApdu verifyCommandApdu = new RetriesLeftApduCommand();
    	final ResponseApdu verifyResponse;
		try {
			verifyResponse = getConnection().transmit(
				verifyCommandApdu
			);
		}
		catch (final ApduConnectionException e) {
			throw new PinException(
				"Error obteniendo el PIN del CallbackHandler: " + e, e  //$NON-NLS-1$
			);
		}
		if (verifyResponse.isOk() || verifyResponse.getBytes().length > 2) {
			return verifyResponse.getBytes()[1];
		}
		throw new PinException(
			"Error comprobando los intentos restantes de PIN con respuesta: " + //$NON-NLS-1$
				verifyResponse.getStatusWord()
		);
    }

    private PasswordCallback getInternalPasswordCallback() throws PinException {
    	if (this.passwordCallback != null) {
    		final int retriesLeft = getPinRetriesLeft();
    		if(retriesLeft == 0) {
    			throw new AuthenticationModeLockedException();
    		}
    		return this.passwordCallback;
    	}
    	if (this.callbackHandler != null) {
        	final int retriesLeft = getPinRetriesLeft();
        	if(retriesLeft == 0) {
        		throw new AuthenticationModeLockedException();
        	}
        	final PasswordCallback pwc = new PasswordCallback(
    			CardMessages.getString("Gen.0", Integer.toString(retriesLeft)), //$NON-NLS-1$
				false
			);
			try {
				this.callbackHandler.handle(
					new Callback[] {
						pwc
					}
				);
			}
			catch (final IOException e) {
				throw new PinException(
					"Error obteniendo el PIN del CallbackHandler: " + e, e//$NON-NLS-1$
				);
			}
			catch (final UnsupportedCallbackException e) {
				throw new PinException(
					"El CallbackHandler no soporta pedir el PIN al usuario: " + e, e //$NON-NLS-1$
				);
			}
			return pwc;
    	}
    	throw new PinException("No hay ningun metodo para obtener el PIN"); //$NON-NLS-1$
    }

    private static void checkAtr(final byte[] atrBytes) throws InvalidCardException {
    	final Atr tmpAtr = new Atr(atrBytes, ATR_MASK);
    	if (ATR.equals(tmpAtr)) {
    		LOGGER.info("Detectada G&D SmartCafe 3.2"); //$NON-NLS-1$
    	}
    	else if (ATR_MSC.equals(tmpAtr)) {
    		LOGGER.info("Detectada G&D Mobile Security Card"); //$NON-NLS-1$
    	}
    	else if (ATR_TCL.equals(tmpAtr)) {
    		LOGGER.info("Detectada G&D SmartCafe 3.2 via T=CL (conexion inalambrica)"); //$NON-NLS-1$
    	}
    	else {
	    	throw new InvalidCardException(
				"La tarjeta no es una SmartCafe 3.2 (ATR encontrado: " + HexUtils.hexify(atrBytes, false) + ")" //$NON-NLS-1$ //$NON-NLS-2$
			);
    	}
    }

}
