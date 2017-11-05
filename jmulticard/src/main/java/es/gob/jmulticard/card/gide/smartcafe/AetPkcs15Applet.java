package es.gob.jmulticard.card.gide.smartcafe;

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
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.gide.VerifyApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse;
import es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Odf;
import es.gob.jmulticard.asn1.der.pkcs15.Path;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta G&amp;D SmartCafe con el Applet PKCS#15 de AET.
 * @author Vicente Ortiz
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class AetPkcs15Applet extends Iso7816FourCard implements CryptoCard {

    private static final byte[] PKCS15_NAME = new byte[] {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x63, (byte) 0x50,
        (byte) 0x4B, (byte) 0x43, (byte) 0x53, (byte) 0x2D, (byte) 0x31, (byte) 0x35
    };

    private static final byte[] ODF_PATH = new byte[] { (byte) 0x50, (byte) 0x31 };
    private static final byte[] MF_PATH  = new byte[] { (byte) 0x3F, (byte) 0x00 };

    private static byte CLA = (byte) 0x00;

    private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    private static final Map<String, X509Certificate> CERTS_BY_ALIAS = new LinkedHashMap<>();

    /** Octeto que identifica una verificaci&oacute;n fallida del PIN. */
    private final static byte ERROR_PIN_SW1 = (byte) 0x63;

    /** Construye un objeto que representa una tarjeta G&amp;D SmartCafe con el
     * Applet PKCS#15 de AET.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @throws IOException Si hay errores de entrada / salida. */
    public AetPkcs15Applet(final ApduConnection conn) throws IOException {
        super(CLA, conn);

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

        // Cargamos la localizacion de los certificados
        try {
            preloadCertificates();
        }
        catch (final Exception e) {
            throw new IOException(
        		"No se han podido leer los certificados: " + e, e //$NON-NLS-1$
    		);
        }

    }

    /** Conecta con el lector del sistema que tenga una tarjeta insertada.
     * @param conn Conexi&oacute;n hacia la tarjeta.
     * @throws IOException Cuando hay errores de entrada / salida. */
    private static void connect(final ApduConnection conn) throws IOException {
        if (conn == null) {
            throw new IllegalArgumentException("La conexion no puede ser nula"); //$NON-NLS-1$
        }
        if (!conn.isOpen()) {
            conn.open();
        }
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

        final CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
        }
        catch (final CertificateException e) {
            throw new IOException("Error obteniendo la factoria de certificados X.509: " + e, e); //$NON-NLS-1$
        }
        if (cdf.getCertificateCount() < 1) {
        	LOGGER.warning("La tarjeta no contiene ningun certificado"); //$NON-NLS-1$
        }
        for (int i = 0; i < cdf.getCertificateCount(); i++) {
            try {
                selectMasterFile();
                CERTS_BY_ALIAS.put(
                    cdf.getCertificateAlias(i),
                    (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(
                    		// En la ruta de la tarjeta pone 3FFF... en vez de 3F00, parece que el CDF es incorrecto
                            selectFileByLocationAndRead(new Location("3F00" + cdf.getCertificatePath(i).substring(4))) //$NON-NLS-1$
                        )
                    )
                );
            }
            catch (final CertificateException e) {
                throw new IOException(
            		"Error en la lectura del certificado " + i + " del dispositivo: " + e, e //$NON-NLS-1$ //$NON-NLS-2$
        		);
            }
        }

    }

    @Override
    public String getCardName() {
        return "G&D SmartCafe 3.2 (AET PKCS#15 Applet)"; //$NON-NLS-1$
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
            .append("\n Tarjeta con ").append(CERTS_BY_ALIAS.size()).append(" certificado(s):\n"); //$NON-NLS-1$ //$NON-NLS-2$
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
            return response.getData()[4] << 8 + response.getData()[5];
        }
        final StatusWord sw = response.getStatusWord();
        if (sw.equals(new StatusWord((byte) 0x6A, (byte) 0x82))) {
            throw new FileNotFoundException(id);
        }
        throw new Iso7816FourCardException(sw, selectCommand);
    }

    //************ NO IMPLEMENTADAS AUN ***************************

    @Override
    public PrivateKeyReference getPrivateKey(final String alias) {
    	throw new UnsupportedOperationException();
    }

    @Override
    public byte[] sign(final byte[] data, final String algorithm, final PrivateKeyReference keyRef) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void verifyPin(final PasswordCallback psc) throws ApduConnectionException, PinException {
    	if(psc == null) {
    		throw new IllegalArgumentException(
    			"No se puede verificar el titular con un PasswordCallback nulo" //$NON-NLS-1$
        	);
    	}
    	VerifyApduCommand verifyCommandApdu = new VerifyApduCommand((byte) 0x01, psc);
    	final ResponseApdu verifyResponse = getConnection().transmit(
			verifyCommandApdu
    	);
    	verifyCommandApdu = null;
    	if (!verifyResponse.isOk()) {
    		if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
    			throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
    		}
            else if (verifyResponse.getStatusWord().getMsb() == (byte)0x69 && verifyResponse.getStatusWord().getLsb() == (byte)0x83) {
            	throw new AuthenticationModeLockedException();
            }
            else {
            	throw new ApduConnectionException(
        			new Iso7816FourCardException(
    	        		"Error en la verificacion de PIN (" + verifyResponse.getStatusWord() + ")", //$NON-NLS-1$ //$NON-NLS-2$
    	        		verifyResponse.getStatusWord()
    				)
    			);
            }
    	}
    }

}
