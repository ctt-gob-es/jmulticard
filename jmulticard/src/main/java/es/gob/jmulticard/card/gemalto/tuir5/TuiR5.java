package es.gob.jmulticard.card.gemalto.tuir5;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
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

    private static final Location CDF_LOCATION = new Location("50005003"); //$NON-NLS-1$

	/** Construye una clase que representa una tarjeta Gemalto TUI R5 MPCOS.
     * @param conn Conexi&oacute;n con la tarjeta
	 * @throws Iso7816FourCardException
	 * @throws IOException */
	public TuiR5(final ApduConnection conn) throws Iso7816FourCardException, IOException {
		super((byte) 0x00, conn);

		// Conectamos
		connect(conn);

		// Seleccionamos el Applet GemXpresso
		selectPkcs15Applet();

		// Precargamos los certificados
		preloadCertificates();
	}

    /** Conecta con el lector del sistema que tenga una TUI insertada.
     * @throws Iso7816FourCardException
     * @throws IOException */
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
    	final byte[] cdfData = selectFileByLocationAndRead(CDF_LOCATION);
    	System.out.println("CDF: " + HexUtils.hexify(cdfData, true)); //$NON-NLS-1$
    	System.out.println("CDF: " + new String(cdfData)); //$NON-NLS-1$
    	final OutputStream fos = new FileOutputStream(File.createTempFile("CDF_", ".der"));
    	fos.write(cdfData);
    	fos.flush();
    	fos.close();
        final Cdf cdf = new Cdf();
        try {
			cdf.setDerValue(cdfData);
		}
        catch (final Exception e) {
        	throw new IllegalStateException(e);
		}
    }

    private void init() throws Iso7816FourCardException, IOException {

    	selectPkcs15Applet();

    	final ResponseApdu res;

    	// Raiz
    	selectFileById(new byte[] { (byte) 0x3F, (byte) 0x00});

    	// PKCS#15
    	selectFileById(new byte[] { (byte) 0x50, (byte) 0x00});

    	// CDF
    	final byte[] cdf = selectFileByIdAndRead(new byte[] { (byte) 0x50, (byte) 0x03});


//    	res = sendArbitraryApdu(new CommandApdu(
//			(byte) 0x00,
//			(byte) 0xCA,
//			(byte) 0x9F,
//			(byte) 0x7F,
//			null,
//			Integer.valueOf(45)
//		));

//    	res = sendArbitraryApdu(new CommandApdu(
//			(byte) 0x00,
//			(byte) 0xCB,
//			(byte) 0x00,
//			(byte) 0xFF,
//			new byte[] {
//				(byte) 0xB6, // DST
//					(byte) 0x03, // Long
//						(byte) 0x83, // Referencia a clave publica
//							(byte) 0x01, // Len
//								(byte) 0x06, // Valor
//				(byte) 0x7F, (byte) 0x49, (byte) 0x02, (byte) 0x81, (byte) 0x00
//			},
//			null
//		));

//    	System.out.println(HexUtils.hexify(res.getBytes(), true));
    	System.out.println(new String(cdf));

//    	// Verificacion del PIN
//    	sendArbitraryApdu(new CommandApdu(
//			(byte) 0x00, // CLA
//			(byte) 0x20, // INS
//			(byte) 0x00, // P1
//			(byte) 0x81, // P2
//			new byte[] { // PIN
//				(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x00,
//				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//				(byte) 0x00
//			},
//			null // Ne
//		));

//    	sendArbitraryApdu(new CommandApdu(
//			(byte) 0x00,
//			(byte) 0xA4,
//			(byte) 0x02,
//			(byte) 0x00,
//			new byte[] {
//				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
//				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
//			},
//			null
//		));

//    	// Seleccion del EF con el certificado
//    	sendArbitraryApdu(new CommandApdu(
//			(byte) 0x00,
//			(byte) 0xA4,
//			(byte) 0x08,
//			(byte) 0x0C,
//			new byte[] {
//				(byte) 0x50, (byte) 0x00, (byte) 0x50, (byte) 0x01
//			},
//			null
//		));
//
//    	// Lectura del EF con el certificado
//    	sendArbitraryApdu(new CommandApdu(
//			(byte) 0x00,
//			(byte) 0xB0,
//			(byte) 0x00,
//			(byte) 0x00,
//			null,
//			Integer.valueOf(134)
//		));

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

	@Override
	public String[] getAliases() throws CryptoCardException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate getCertificate(final String alias)
			throws CryptoCardException, BadPinException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrivateKeyReference getPrivateKey(final String alias)
			throws CryptoCardException {
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
			(byte) 0x00,
			(byte) 0xA4,
			(byte) 0x08,
			(byte) 0x0C,
			new byte[] { (byte) 0x50, (byte) 0x00, (byte) 0x50, (byte) 0x01},
			null
		);
		System.out.println("Select MF: " + HexUtils.hexify(selectMf.getBytes(), true)); //$NON-NLS-1$
		sendArbitraryApdu(selectMf);

	}

	@Override
	public String getCardName() {
		return "Gemalto TUI R5 (MPCOS)"; //$NON-NLS-1$
	}

	private static final class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Contruye una Callback con una contrase&ntilda; preestablecida.
	     * @param password
	     *        Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        this.setPassword(password);
	    }
	}

}
