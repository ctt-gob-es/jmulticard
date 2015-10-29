/*
 * Controlador Java de la Secretaria de Estado de Administraciones Publicas
 * para el DNI electronico.
 *
 * El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
 * que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
 * para la realizacion de procesos de autenticacion, firma electronica y validacion
 * de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
 * el acceso a los certificados y claves del DNI electronico, asi como la realizacion
 * de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
 * sido disenado para su funcionamiento independiente del sistema operativo final.
 *
 * Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
 * e Impulso de la Administracion Electronica
 *
 * Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
 * o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
 * licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
 * en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
 * su compatibilidad con otros componentes.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * Lesser GNU General Public License publicada por la Free Software Foundation,
 * tanto en la version 2.1 de la Licencia, o en una version posterior.
 *
 * El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
 * European Union Public License publicada por la Comision Europea,
 * tanto en la version 1.1 de la Licencia, o en una version posterior.
 *
 * Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
 *
 * Deberia recibir una copia de la European Union Public License, si aplica, junto
 * con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
 *
 * Este programa es distribuido con la esperanza de que sea util, pero
 * SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
 * o idoneidad para un proposito particular.
 */
package es.gob.jmulticard.card.dnie;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneConnection;
import es.gob.jmulticard.apdu.connection.cwa14890.SecureChannelException;
import es.gob.jmulticard.apdu.dnie.GetChipInfoApduCommand;
import es.gob.jmulticard.apdu.dnie.MseSetSignatureKeyApduCommand;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ExternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.InternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationKeyApduCommand;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import es.gob.jmulticard.card.iso7816eight.Iso7816EightCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** DNI Electr&oacute;nico.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Dnie extends Iso7816EightCard implements CryptoCard, Cwa14890Card {

	private static Cwa14890Constants cwa14890Constants;

	private static final boolean SHOW_SIGN_CONFIRM_DIALOG = true;

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    /** Octeto que identifica una verificaci&oacute;n fallida del PIN */
    private final static byte ERROR_PIN_SW1 = (byte) 0x63;

    private static final CertificateFactory certFactory;
    static {
    	try {
			certFactory = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		}
    	catch (final Exception e) {
			throw new IllegalStateException(
				"No se ha podido obtener la factoria de certificados X.509: " + e, e //$NON-NLS-1$
			);
		}
    }

    private static final boolean PIN_AUTO_RETRY;
    static {
    	// No hacemos el reintento de PIN en Android
    	if ("Dalvik".equals(System.getProperty("java.vm.name"))) { //$NON-NLS-1$ //$NON-NLS-2$
    		PIN_AUTO_RETRY = false;
    	}
    	else {
    		PIN_AUTO_RETRY = true;
    	}
    }

    /** Identificador del fichero del certificado de componente del DNIe. */
    private static final byte[] CERT_ICC_FILE_ID = new byte[] {
            (byte) 0x60, (byte) 0x1F
    };

    /** Nombre del Master File del DNIe. */
    private static final String MASTER_FILE_NAME = "Master.File"; //$NON-NLS-1$

    private static final String CERT_ALIAS_AUTH = "CertAutenticacion"; //$NON-NLS-1$
    private static final String CERT_ALIAS_SIGN = "CertFirmaDigital"; //$NON-NLS-1$
    private static final String CERT_ALIAS_CYPHER = "CertCifrado"; //$NON-NLS-1$
    private static final String CERT_ALIAS_INTERMEDIATE_CA = "CertCAIntermediaDGP"; //$NON-NLS-1$

    private static final String AUTH_KEY_LABEL = "KprivAutenticacion"; //$NON-NLS-1$
    private static final String SIGN_KEY_LABEL = "KprivFirmaDigital"; //$NON-NLS-1$
    private static final String CYPH_KEY_LABEL = "KprivCifrado"; //$NON-NLS-1$

    private static final Location CDF_LOCATION = new Location("50156004"); //$NON-NLS-1$

    private static final Location PRKDF_LOCATION = new Location("50156001"); //$NON-NLS-1$

    private X509Certificate authCert;
    private X509Certificate signCert;
    private X509Certificate cyphCert;
    private X509Certificate intermediateCaCert;

    private Location authCertPath;
    private Location signCertPath;

    /** Localizaci&oacute;n del certificado de de cifrado.
     * Es opcional, ya que solo est&aacute; presente en las TIF, no en los DNIe normales. */
    private Location cyphCertPath = null;

    private DniePrivateKeyReference authKeyRef;
    private DniePrivateKeyReference signKeyRef;

    /** Referencia a la clave privada de cifrado.
     * Es opcional, ya que solo est&aacute; presente en las TIF, no en los DNIe normales. */
    private DniePrivateKeyReference cyphKeyRef = null;

    /** Manejador de funciones criptograficas. */
    private CryptoHelper cryptoHelper = null;

    private static final byte[] ATR_MASK = new byte[] {
            (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF
    };

    private static final Atr ATR = new Atr(new byte[] {
            (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44, (byte) 0x4E, (byte) 0x49,
            (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
    }, ATR_MASK);

    private static final Atr ATR_TIF = new Atr(new byte[] {
            (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x54, (byte) 0x49, (byte) 0x46,
            (byte) 0x31, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00
    }, ATR_MASK);

    private final PasswordCallback passwordCallback;

    /** Conecta con el lector del sistema que tenga un DNIe insertado.
     * @param conn Conexi&oacute;n hacia el DNIe.
     * @throws BurnedDnieCardException Si el DNIe tiene su memoria vol&aacute;til borrada.
     * @throws InvalidCardException Si la tarjeta no es un DNIe.
     * @throws ApduConnectionException Si hay problemas de conexi&oacute;n con la tarjeta. */
    public static void connect(final ApduConnection conn) throws BurnedDnieCardException,
                                                           InvalidCardException,
                                                           ApduConnectionException {
    	if (conn == null) {
    		throw new IllegalArgumentException("La conexion no puede ser nula"); //$NON-NLS-1$
    	}
    	byte[] responseAtr;
    	Atr actualAtr;
    	InvalidCardException invalidCardException = null;
    	CardNotPresentException cardNotPresentException = null;
    	final long[] terminals = conn.getTerminals(false);
    	if (terminals.length < 1) {
    	    throw new NoReadersFoundException();
    	}
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
    		final byte[] actualAtrBytes = actualAtr.getBytes();

    		if (ATR.equals(actualAtr)) {
    			if (actualAtrBytes[15] == 0x04 &&
    				actualAtrBytes[16] == 0x00) {
    					LOGGER.info("Detectado DNIe 3.0"); //$NON-NLS-1$
    					cwa14890Constants = new Dnie3Cwa14890Constants();
    			}
    			else {
    				cwa14890Constants = new DnieCwa14890Constants();
    			}
    		}
    		else if (ATR_TIF.equals(actualAtr)) {
    			cwa14890Constants = new TifCwa14890Constants();
    		}
    		else { // La tarjeta encontrada no es un DNIe
        		// Vemos si es un DNIe quemado, en el que el ATR termina en 65-81 en vez de
        		// en 90-00
        		if (actualAtrBytes[actualAtrBytes.length -1] == (byte) 0x81 &&
        			actualAtrBytes[actualAtrBytes.length -2] == (byte) 0x65) {
                    	throw new BurnedDnieCardException(actualAtr);
                }
    			invalidCardException = new InvalidCardException("DNIe", ATR, responseAtr); //$NON-NLS-1$
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

    /** Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre m&aacute;quinas virtuales.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla.
     * @throws es.gob.jmulticard.card.InvalidCardException Si la tarjeta conectada no es un DNIe.
     * @throws BurnedDnieCardException Si la tarjeta conectada es un DNIe con la memoria vol&aacute;til borrada. */
    public Dnie(final ApduConnection conn,
    		    final PasswordCallback pwc,
    		    final CryptoHelper cryptoHelper) throws ApduConnectionException,
                                                        InvalidCardException,
                                                        BurnedDnieCardException {
        super((byte) 0x00, conn);
        conn.reset();
        connect(conn);

        try {
			selectMasterFile();
		}
        catch (final Iso7816FourCardException e) {
			LOGGER.warning(
				"No se ha podido seleccionar el directorio raiz antes de leer las estructuras: " + e //$NON-NLS-1$
			);
		}

        this.passwordCallback = pwc;
        if (cryptoHelper == null) {
            throw new IllegalArgumentException("El CryptoHelper no puede ser nulo"); //$NON-NLS-1$
        }
        this.cryptoHelper = cryptoHelper;

        // Cargamos la localizacion de los certificados y el certificado
        // de CA intermedia de los certificados de firma, autenticacion y, si existe, cifrado
        preloadCertificates();

        // Cargamos la informacion publica con la referencia a las claves
        loadKeyReferences();

    }

    /** Carga la informaci&oacute;n p&uacute;blica con la referencia a las claves de firma. */
    private void loadKeyReferences() {
        final PrKdf prKdf = new PrKdf();
        try {
            prKdf.setDerValue(
        		selectFileByLocationAndRead(PRKDF_LOCATION)
    		);
        }
        catch (final Exception e) {
            throw new IllegalStateException(
        		"No se ha podido cargar el PrKDF de la tarjeta: " + e.toString() //$NON-NLS-1$
    		);
        }

        for (int i = 0; i < prKdf.getKeyCount(); i++) {
            if (AUTH_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                this.authKeyRef = new DniePrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), AUTH_KEY_LABEL);
            }
            else if (SIGN_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                this.signKeyRef = new DniePrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), SIGN_KEY_LABEL);
            }
            else if (CYPH_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                this.cyphKeyRef = new DniePrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), CYPH_KEY_LABEL);
            }
        }
    }

    /** Recupera el n&uacute;mero de serie de un DNIe.
     * @return Un array de bytes que contiene el n&uacute;mero de serie del DNIe.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla. */
    @Override
    public byte[] getSerialNumber() throws ApduConnectionException {
        final ResponseApdu response = this.getConnection().transmit(new GetChipInfoApduCommand());
        if (response.isOk()) {
        	return response.getData();
        }
        throw new ApduConnectionException("Respuesta invalida en la obtencion del numero de serie con el codigo: " + response.getStatusWord()); //$NON-NLS-1$
    }

    /** {@inheritDoc} */
	@Override
    public String getCardName() {
        return "DNIe"; //$NON-NLS-1$
    }

    /** {@inheritDoc} */
    @Override
    public String[] getAliases() {
    	if (this.cyphCertPath != null) {
            return new String[] {
                CERT_ALIAS_AUTH,
                CERT_ALIAS_SIGN,
                CERT_ALIAS_CYPHER
            };
    	}
        return new String[] {
            CERT_ALIAS_AUTH,
            CERT_ALIAS_SIGN
        };
    }

    /** Carga el certificado de la CA intermedia y las localizaciones de los certificados de firma y autenticacion. */
    private void preloadCertificates() {
        final Cdf cdf = new Cdf();
        try {
        	selectMasterFile();
        	final byte[] cdfBytes = selectFileByLocationAndRead(CDF_LOCATION);
            cdf.setDerValue(cdfBytes);
        }
        catch (final Exception e) {
            throw new IllegalStateException("No se ha podido cargar el CDF de la tarjeta: " + e.toString(), e); //$NON-NLS-1$
        }

        for (int i = 0; i < cdf.getCertificateCount(); i++) {
        	final String currentAlias = cdf.getCertificateAlias(i);
            if (CERT_ALIAS_AUTH.equals(currentAlias)) {
                this.authCertPath = new Location(cdf.getCertificatePath(i));
            }
            else if (CERT_ALIAS_SIGN.equals(currentAlias)) {
                this.signCertPath = new Location(cdf.getCertificatePath(i));
            }
            else if (CERT_ALIAS_CYPHER.equals(currentAlias)) {
            	this.cyphCertPath = new Location(cdf.getCertificatePath(i));
            }
            else if (CERT_ALIAS_INTERMEDIATE_CA.equals(currentAlias)) {
            	try {
            		final byte[] intermediateCaCertEncoded = deflate(
        				selectFileByLocationAndRead(
    						new Location(
								cdf.getCertificatePath(i)
							)
        				)
    				);
            		this.intermediateCaCert = (X509Certificate) certFactory.generateCertificate(
    					new ByteArrayInputStream(intermediateCaCertEncoded)
					);
            	}
            	catch (final Exception e) {
            		Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
        				"No se ha podido cargar el certificado de la autoridad intermedia del CNP: " + e //$NON-NLS-1$
    				);
            		this.intermediateCaCert = null;
            	}
            }
            else {
            	LOGGER.warning("La tarjeta contiene un certificado no esperado: " + cdf.getCertificateAlias(i)); //$NON-NLS-1$
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public X509Certificate getCertificate(final String alias) throws CryptoCardException, BadPinException {

        if (this.authCert == null) {
            loadCertificates();
        }

        if (CERT_ALIAS_AUTH.equals(alias)) {
            return this.authCert;
        }
        if (CERT_ALIAS_SIGN.equals(alias)) {
            return this.signCert;
        }
        if (CERT_ALIAS_INTERMEDIATE_CA.equals(alias)) {
            return this.intermediateCaCert;
        }
        if (CERT_ALIAS_CYPHER.equals(alias)) {
        	return this.cyphCert;
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public void verifyCaIntermediateIcc() throws CertificateException, IOException {
        // No se comprueba
    }

    /** {@inheritDoc} */
    @Override
    public void verifyIcc() throws CertificateException, IOException {
        // No se comprueba
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getIccCertEncoded() throws IOException {
        byte[] iccCertEncoded;
        try {
        	this.selectMasterFile();
            iccCertEncoded = this.selectFileByIdAndRead(CERT_ICC_FILE_ID);
        }
        catch (final ApduConnectionException e) {
            throw new IOException("Error en el envio de APDU para la seleccion del certificado de componente de la tarjeta: " + e, e); //$NON-NLS-1$
        }
        catch (final Iso7816FourCardException e) {
            throw new IOException("Error en la seleccion del certificado de componente de la tarjeta: " + e, e); //$NON-NLS-1$
        }
        return iccCertEncoded;
    }

    /** {@inheritDoc} */
    @Override
    public void verifyIfdCertificateChain() throws ApduConnectionException {

        // Seleccionamos en la tarjeta la clave publica de la CA raiz del controlador
        try {
            this.setPublicKeyToVerification(Dnie.cwa14890Constants.getRefCCvCaPublicKey());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error al seleccionar para verificacion la " +//$NON-NLS-1$
                     "clave publica de la CA raiz de los certificados verificables por la tarjeta", e //$NON-NLS-1$
    		);
        }

        // Verificamos la CA intermedia del controlador. La clave publica queda almacenada en memoria
        try {
            this.verifyCertificate(Dnie.cwa14890Constants.getCCvCa());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException("Error en la verificacion del certificado de la CA intermedia de Terminal: " + e, e); //$NON-NLS-1$
        }

        // Seleccionamos a traves de su CHR la clave publica del certificado recien cargado en memoria
        // (CA intermedia de Terminal) para su verificacion
        try {
            this.setPublicKeyToVerification(Dnie.cwa14890Constants.getChrCCvCa());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error al establecer la clave publica del certificado de CA intermedia de Terminal para su verificacion en tarjeta: " + e, e //$NON-NLS-1$
    		);
        }

        // Enviamos el certificado de Terminal (C_CV_IFD) para su verificacion por la tarjeta
        try {
            this.verifyCertificate(Dnie.cwa14890Constants.getCCvIfd());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException("Error en la verificacion del certificado de Terminal: " + e, e); //$NON-NLS-1$
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getRefIccPrivateKey() {
        return Dnie.cwa14890Constants.getRefIccPrivateKey();
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getChrCCvIfd() {
        return Dnie.cwa14890Constants.getChrCCvIfd();
    }

    /** {@inheritDoc} */
    @Override
    public RSAPrivateKey getIfdPrivateKey() {
        return Dnie.cwa14890Constants.getIfdPrivateKey();
    }

    /** {@inheritDoc} */
    @Override
    public void setKeysToAuthentication(final byte[] refPublicKey, final byte[] refPrivateKey) throws ApduConnectionException {
        final CommandApdu apdu = new MseSetAuthenticationKeyApduCommand((byte) 0x00, refPublicKey, refPrivateKey);
        final ResponseApdu res = this.getConnection().transmit(apdu);
        if (!res.isOk()) {
            throw new SecureChannelException(
        		"Error durante el establecimiento de las claves publica y privada " + //$NON-NLS-1$
                     "para atenticacion (error: " + HexUtils.hexify(res.getBytes(), true) + ")" //$NON-NLS-1$ //$NON-NLS-2$
            );
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getInternalAuthenticateMessage(final byte[] randomIfd, final byte[] chrCCvIfd) throws ApduConnectionException {
        final CommandApdu apdu = new InternalAuthenticateApduCommand((byte) 0x00, randomIfd, chrCCvIfd);
        final ResponseApdu res = this.getConnection().transmit(apdu);
        if (res.isOk()) {
        	return res.getData();
        }
        throw new ApduConnectionException(
    		"Respuesta invalida en la obtencion del mensaje de autenticacion interna con el codigo: " + res.getStatusWord() //$NON-NLS-1$
		);
    }

    /** {@inheritDoc} */
    @Override
    public boolean externalAuthentication(final byte[] extAuthenticationData) throws ApduConnectionException {
        final CommandApdu apdu = new ExternalAuthenticateApduCommand((byte) 0x00, extAuthenticationData);
        return this.getConnection().transmit(apdu).isOk();
    }

    /** {@inheritDoc} */
    @Override
    public PrivateKeyReference getPrivateKey(final String alias) {
        if (CERT_ALIAS_AUTH.equals(alias)) {
            return this.authKeyRef;
        }
        else if (CERT_ALIAS_SIGN.equals(alias)) {
            return this.signKeyRef;
        }
        else if (CERT_ALIAS_CYPHER.equals(alias)) {
        	return this.cyphKeyRef;
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] sign(final byte[] data, final String signAlgorithm, final PrivateKeyReference privateKeyReference) throws CryptoCardException, BadPinException {

        if (!(privateKeyReference instanceof DniePrivateKeyReference)) {
            throw new IllegalArgumentException("La referencia a la clave privada tiene que ser de tipo DniePrivateKeyReference"); //$NON-NLS-1$
        }

        if (SHOW_SIGN_CONFIRM_DIALOG) {

        	boolean permissionDenied;
        	try {
        		final Class<?> dialogBuilderClass = Class.forName("es.gob.jmulticard.ui.passwordcallback.DialogBuilder"); //$NON-NLS-1$
        		final Class<?> componentClass = Class.forName("java.awt.Component"); //$NON-NLS-1$
        		final Method showSignatureConfirmDialogMethod = dialogBuilderClass.getMethod("showSignatureConfirmDialog", componentClass, Boolean.TYPE); //$NON-NLS-1$

        		final Integer result = (Integer) showSignatureConfirmDialogMethod.invoke(
    				null,
    				null,
    				Boolean.valueOf(!AUTH_KEY_LABEL.equals(((DniePrivateKeyReference) privateKeyReference).toString()))
				);
        		permissionDenied = result.intValue() == 1;

        	}
        	catch (final Exception e) {
        		Logger.getLogger("es.gob.afirma").severe( //$NON-NLS-1$
    				"No se ha podido mostrar el dialogo grafico para la autorizacion de la firma, se realizara sin aprobacion expresa: " + e //$NON-NLS-1$
				);
        		permissionDenied = false;
        	}

	        if (permissionDenied) {
	        	final RuntimeException re;
	        	try {
	        		final Class<?> cancelledOperationExceptionClass = Class.forName(
        				"es.gob.jmulticard.ui.passwordcallback.CancelledOperationException" //$NON-NLS-1$
    				);
	        		final Constructor<?> cancelledOperationExceptionConstructor = cancelledOperationExceptionClass.getConstructor(String.class);
	        		re = (RuntimeException) cancelledOperationExceptionConstructor.newInstance("Operacion de firma no autorizada por el usuario"); //$NON-NLS-1$
	        	}
	        	catch (final Exception e) {
	        		throw new IllegalArgumentException("No se ha instanciar CancelledOperationException", e); //$NON-NLS-1$
	        	}

	            throw re;
	        }
        }

        return signOperation(data, signAlgorithm, privateKeyReference);
    }

    /** Realiza la operaci&oacute;n de firma.
     * @param data Datos que se desean firmar.
     * @param signAlgorithm Algoritmo de firma (por ejemplo, SHA512withRSA, SHA1withRSA, etc.).
     * @param privateKeyReference Referencia a la clave privada para la firma.
     * @return Firma de los datos.
     * @throws CryptoCardException Cuando se produce un error durante la operaci&oacute;n de firma.
     * @throws es.gob.jmulticard.card.BadPinException Si el PIN proporcionado en la <i>PasswordCallback</i>
     *                                                es incorrecto y no estaba habilitado el reintento autom&aacute;tico
     * @throws es.gob.jmulticard.card.AuthenticationModeLockedException Cuando el DNIe est&aacute; bloqueado. */
    private byte[] signOperation(final byte[] data,
    		                     final String signAlgorithm,
    		                     final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                           BadPinException {
        this.openSecureChannelIfNotAlreadyOpened();

        ResponseApdu res;
        try {
            CommandApdu apdu = new MseSetSignatureKeyApduCommand(
        		(byte) 0x00, ((DniePrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath()
    		);

            res = this.getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
            		"Error en el establecimiento de las variables de entorno para firma", res.getStatusWord() //$NON-NLS-1$
        		);
            }

            // TODO: Modificar esta llamada y la clase DigestInfo para que reciba el algoritmo
            // de digest directamente

            final byte[] digestInfo;
            try {
                digestInfo = DigestInfo.encode(signAlgorithm, data, this.cryptoHelper);
            }
            catch (final IOException e) {
                throw new DnieCardException("Error en el calculo del hash para firmar: " + e, e); //$NON-NLS-1$
            }

            apdu = new PsoSignHashApduCommand((byte) 0x00, digestInfo);
            res = this.getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException("Error durante la operacion de firma", res.getStatusWord()); //$NON-NLS-1$
            }
        }
        catch(final LostChannelException e) {
            try {
                this.getConnection().close();
                if (this.getConnection() instanceof Cwa14890OneConnection) {
                    this.setConnection(((Cwa14890OneConnection) this.getConnection()).getSubConnection());
                }
            }
            catch (final Exception ex) {
                throw new DnieCardException("No se pudo recuperar el canal seguro para firmar: " + ex, ex); //$NON-NLS-1$
            }
            return signOperation(data, signAlgorithm, privateKeyReference);
        }
        catch (final ApduConnectionException e) {
            throw new DnieCardException("Error en la transmision de comandos a la tarjeta: " + e, e); //$NON-NLS-1$
        }

        return res.getData();
    }

    /** Establece y abre el canal seguro CWA-14890 si no lo estaba ya hecho.
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws BadPinException Si el PIN usado para la apertura de canal no es v&aacute;lido. */
    private void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, BadPinException {
        // Abrimos el canal seguro si no lo esta ya
        if (!this.isSecurityChannelOpen()) {
        	// Aunque el canal seguro estuviese cerrado, podria si estar enganchado
            if (!(this.getConnection() instanceof Cwa14890OneConnection)) {
                final Cwa14890OneConnection secureConnection = new Cwa14890OneConnection(this, this.getConnection(), this.cryptoHelper);
                try {
                    this.setConnection(secureConnection);
                }
                catch (final ApduConnectionException e) {
                    throw new CryptoCardException("Error en el establecimiento del canal seguro: " + e, e); //$NON-NLS-1$
                }
            }
            try {
                verifyPin(this.passwordCallback);
                if (this.passwordCallback != null) {
                	this.passwordCallback.clearPassword();
                }
            }
            catch (final ApduConnectionException e) {
                throw new CryptoCardException("Error en la apertura del canal seguro: " + e, e); //$NON-NLS-1$
            }
        }
    }

    private X509Certificate loadCertificate(final Location location) throws IOException, Iso7816FourCardException, CertificateException {
        final byte[] certEncoded = deflate(
    		selectFileByLocationAndRead(location)
		);
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certEncoded));
    }

    /** Carga los certificados del usuario para utilizarlos cuando se desee (si no estaban ya cargados), abriendo el canal seguro de
     * la tarjeta si fuese necesario, mediante el PIN de usuario.
     * @throws CryptoCardException Cuando se produce un error en la operaci&oacute;n con la tarjeta
     * @throws es.gob.jmulticard.card.BadPinException Si el PIN proporcionado en la <i>PasswordCallback</i>
     *                                                es incorrecto y no estaba habilitado el reintento autom&aacute;tico
     * @throws es.gob.jmulticard.card.AuthenticationModeLockedException Cuando el DNIe est&aacute; ha bloqueado
     * @throws es.gob.jmulticard.ui.passwordcallback.CancelledOperationException Cuando se ha cancelado la inserci&oacute;n del PIN
     *                                                                           usando el di&aacute;logo gr&aacute;fico integrado. */
    private void loadCertificates() throws CryptoCardException, BadPinException {

    	// Abrimos el canal si es necesario
    	openSecureChannelIfNotAlreadyOpened();

        // Cargamos certificados si es necesario
    	if (this.authCert == null || this.signCert == null || this.cyphCert == null && this.cyphCertPath != null) {
	        try {

        		this.signCert = loadCertificate(this.signCertPath);
            	this.authCert = loadCertificate(this.authCertPath);
	            if (this.cyphCertPath != null) {
	            		this.cyphCert = loadCertificate(this.cyphCertPath);
            	}
	        }
	        catch (final CertificateException e) {
	            throw new CryptoCardException(
	        		"Error al cargar los certificados del DNIe, no es posible obtener una factoria de certificados X.509: " + e, e //$NON-NLS-1$
	    		);
	        }
	        catch (final IOException e) {
	            throw new CryptoCardException(
	        		"Error al cargar los certificados del DNIe, error en la descompresion de los datos: " + e, e //$NON-NLS-1$
	    		);
			}
	        catch (final Iso7816FourCardException e) {
	            throw new CryptoCardException(
	        		"Error al cargar los certificados del DNIe: " + e, e //$NON-NLS-1$
	    		);
			}
    	}
    }

	@Override
    protected void selectMasterFile() throws ApduConnectionException, Iso7816FourCardException {
    	selectFileByName(MASTER_FILE_NAME);
    }

    /** Descomprime un certificado contenido en el DNIe.
     * @param compressedCertificate Certificado comprimido en ZIP a partir del 9 byte.
     * @return Certificado codificado.
     * @throws IOException Cuando se produce un error en la descompresion del certificado. */
    private static byte[] deflate(final byte[] compressedCertificate) throws IOException {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        final Inflater decompressor = new Inflater();
        decompressor.setInput(compressedCertificate, 8, compressedCertificate.length - 8);
        final byte[] buf = new byte[1024];
        try {
            // Descomprimimos los datos
            while (!decompressor.finished()) {
                final int count = decompressor.inflate(buf);
                if (count == 0) {
                    throw new DataFormatException();
                }
                buffer.write(buf, 0, count);
            }
            // Obtenemos los datos descomprimidos
            return buffer.toByteArray();
        }
        catch (final DataFormatException ex) {
            throw new IOException("Error al descomprimir el certificado: " + ex, ex); //$NON-NLS-1$
        }
    }

    private boolean isSecurityChannelOpen() {
        // Si estan cargados los certificados entonces ya se abrio el canal seguro
        return this.getConnection() instanceof Cwa14890OneConnection && this.getConnection().isOpen();
    }

    @Override
	public void verifyPin(final PasswordCallback pinPc) throws ApduConnectionException, BadPinException {
    	verifyPin(pinPc, Integer.MAX_VALUE);
    }

    /** Verifica el PIN de la tarjeta. Si se establece la constante <code>PIN_AUTO_RETRY</code> a <code>true</code>,
     * el m&eacute;todo reintenta hasta que se introduce el PIN correctamente, se bloquea la tarjeta por exceso de
     * intentos de introducci&oacute;n de PIN o se recibe una excepci&oacute;n
     * (derivada de <code>RuntimeException</code> o una <code>ApduConnectionException</code>.
     * @param pinPc PIN de la tarjeta
     * @param retriesLeft Intentos restantes que quedan antes de bloquear la tarjeta. Un valor de Integer.MAX_VALUE
     *                    indica un valor desconocido
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con la tarjeta.
     * @throws es.gob.jmulticard.card.AuthenticationModeLockedException Cuando el DNI tiene el PIN bloqueado.
     * @throws es.gob.jmulticard.card.BadPinException Si el PIN proporcionado en la <i>PasswordCallback</i>
     *                                                es incorrecto y no estaba habilitado el reintento autom&aacute;tico */
    private void verifyPin(final PasswordCallback pinPc, final int retriesLeft) throws ApduConnectionException, BadPinException {

    	PasswordCallback psc = null;
    	try {
	    	if (pinPc != null) {
	    		psc = pinPc;
	    	}
	    	else if (retriesLeft < Integer.MAX_VALUE) {
	    		final Class<?> commonPasswordCallbackClass = Class.forName("es.gob.jmulticard.ui.passwordcallback.gui.CommonPasswordCallback"); //$NON-NLS-1$
	        	final Method getDnieBadPinPasswordCallbackMethod = commonPasswordCallbackClass.getMethod("getDnieBadPinPasswordCallback", Integer.TYPE); //$NON-NLS-1$
	        	psc = (PasswordCallback) getDnieBadPinPasswordCallbackMethod.invoke(null, Integer.valueOf(retriesLeft));
	    	}
	    	else {
	    		final Class<?> commonPasswordCallbackClass = Class.forName("es.gob.jmulticard.ui.passwordcallback.gui.CommonPasswordCallback"); //$NON-NLS-1$
	        	final Method getDniePinForCertificateReadingPasswordCallbackMethod = commonPasswordCallbackClass.getMethod("getDniePinForCertificateReadingPasswordCallback"); //$NON-NLS-1$
	        	psc = (PasswordCallback) getDniePinForCertificateReadingPasswordCallbackMethod.invoke(null);
	    	}
    	}
    	catch (final Exception e) {
    		throw new IllegalArgumentException("pinPc no puede ser nulo cuando no hay un PasswordCallback por defecto: " + e, e); //$NON-NLS-1$
    	}

    	VerifyApduCommand verifyCommandApdu = new VerifyApduCommand((byte) 0x00, psc);

    	final ResponseApdu verifyResponse = this.getConnection().transmit(
			verifyCommandApdu
    	);
    	verifyCommandApdu = null;

        // Comprobamos si ocurrio algun error durante la verificacion del PIN para volverlo
        // a pedir si es necesario
    	psc.clearPassword();
        if (!verifyResponse.isOk()) {
            if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
            	// Si no hay reintento automatico se lanza la excepcion
            	if (!PIN_AUTO_RETRY) {
            		throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
            	}
            	// Si hay reintento automativo volvemos a pedir el PIN con la misma CallBack
            	verifyPin(
        			pinPc,
        			verifyResponse.getStatusWord().getLsb() - (byte) 0xC0
            	);
            }
            else if (verifyResponse.getStatusWord().getMsb() == (byte)0x69 && verifyResponse.getStatusWord().getLsb() == (byte)0x83) {
            	throw new AuthenticationModeLockedException();
            }
        }
    }
}