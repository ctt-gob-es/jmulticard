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
import java.security.AccessControlException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV1Connection;
import es.gob.jmulticard.apdu.connection.cwa14890.SecureChannelException;
import es.gob.jmulticard.apdu.dnie.ChangePINApduCommand;
import es.gob.jmulticard.apdu.dnie.GetChipInfoApduCommand;
import es.gob.jmulticard.apdu.dnie.RetriesLeftApduCommand;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ExternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.InternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationKeyApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetComputationApduCommand;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.iso7816eight.Iso7816EightCard;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.card.pace.PaceConnection;

/** DNI Electr&oacute;nico.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class Dnie extends Iso7816EightCard implements Dni, Cwa14890Card {

	private static final int DEFAULT_KEY_SIZE = 2048;

	@SuppressWarnings("static-method")
	protected Cwa14890PublicConstants getCwa14890PublicConstants() {
		return new DnieCwa14890Constants();
	}

	@SuppressWarnings("static-method")
	protected Cwa14890PrivateConstants getCwa14890PrivateConstants() {
		return new DnieCwa14890Constants();
	}

	protected static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    /** Octeto que identifica una verificaci&oacute;n fallida del PIN. */
    private final static byte ERROR_PIN_SW1 = (byte) 0x63;

    private CallbackHandler callbackHandler;

	private String[] aliases = null;

    protected static final CertificateFactory CERT_FACTORY;
    static {
    	try {
			CERT_FACTORY = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		}
    	catch (final Exception e) {
			throw new IllegalStateException(
				"No se ha podido obtener la factoria de certificados X.509: " + e, e //$NON-NLS-1$
			);
		}
    }

    private static final boolean PIN_AUTO_RETRY;
    static {
    	PIN_AUTO_RETRY = true;
    }

    /** Identificador del fichero del certificado de componente del DNIe. */
    private static final byte[] CERT_ICC_FILE_ID = new byte[] {
            (byte) 0x60, (byte) 0x1F
    };

    /** Nombre del <i>Master File</i> del DNIe. */
    private static final String MASTER_FILE_NAME = "Master.File"; //$NON-NLS-1$

	/** Alias del certificado de autenticaci&oacute;n del DNIe. */
    public static final String CERT_ALIAS_AUTH = "CertAutenticacion"; //$NON-NLS-1$

    /** Alias del certificado de firma del DNIe. */
    public static final String CERT_ALIAS_SIGN = "CertFirmaDigital"; //$NON-NLS-1$

    private static final String CERT_ALIAS_SIGNALIAS = "CertFirmaSeudonimo"; //$NON-NLS-1$
    private static final String CERT_ALIAS_CYPHER = "CertCifrado"; //$NON-NLS-1$
    private static final String CERT_ALIAS_INTERMEDIATE_CA = "CertCAIntermediaDGP"; //$NON-NLS-1$

    private static final String AUTH_KEY_LABEL = "KprivAutenticacion"; //$NON-NLS-1$
    private static final String SIGN_KEY_LABEL = "KprivFirmaDigital"; //$NON-NLS-1$
    private static final String CYPH_KEY_LABEL = "KprivCifrado"; //$NON-NLS-1$

    protected static final Location CDF_LOCATION = new Location("50156004"); //$NON-NLS-1$
    protected static final Location PRKDF_LOCATION = new Location("50156001"); //$NON-NLS-1$

    private X509Certificate authCert;
    private X509Certificate signCert;
    private X509Certificate cyphCert;
    private X509Certificate signAliasCert;
    private X509Certificate intermediateCaCert;

    private Location authCertPath;
    private Location signCertPath;

    /** Localizaci&oacute;n del certificado de cifrado.
     * Es opcional, ya que solo est&aacute; presente en las TIF, no en los DNIe normales. */
    private Location cyphCertPath = null;

    /** Localizaci&oacute;n del certificado de firma con seud&oacute;nimo.
     * Es opcional, ya que solo est&aacute; presente en las TIF, no en los DNIe normales. */
    private Location signAliasCertPath = null;

    private DniePrivateKeyReference authKeyRef;
    private DniePrivateKeyReference signKeyRef;

    /** Referencia a la clave privada de cifrado.
     * Es opcional, ya que solo est&aacute; presente en las TIF, no en los DNIe normales. */
    private DniePrivateKeyReference cyphKeyRef = null;

    /** Referencia a la clave privada de firma con seud&oacute;nimo.
     * Es opcional, ya que solo est&aacute; presente en las TIF, no en los DNIe normales. */
    private DniePrivateKeyReference signAliasKeyRef = null;

    /** Conexi&oacute;n inicial con la tarjeta, sin ning&uacute;n canal seguro. */
    protected ApduConnection rawConnection;

    /** Manejador de funciones criptograficas. */
    protected final CryptoHelper cryptoHelper;

    protected CryptoHelper getCryptoHelper() {
    	return this.cryptoHelper;
    }

    private PasswordCallback passwordCallback;

    protected PasswordCallback getPasswordCallback() {
    	return this.passwordCallback;
    }

    /** Conecta con el lector del sistema que tenga un DNIe insertado.
     * @param conn Conexi&oacute;n hacia el DNIe.
     * @throws ApduConnectionException Si hay problemas de conexi&oacute;n con la tarjeta. */
    public static void connect(final ApduConnection conn) throws ApduConnectionException {
    	if (!conn.isOpen()) {
    		conn.open();
    	}
    }

    /** Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que
     *                     pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.*/
    Dnie(final ApduConnection conn,
    	 final PasswordCallback pwc,
    	 final CryptoHelper cryptoHelper,
    	 final CallbackHandler ch) throws ApduConnectionException {
        super((byte) 0x00, conn);
        conn.reset();
        connect(conn);

        this.rawConnection = conn;
        this.callbackHandler = ch;

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
    protected void loadKeyReferences() {
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
                this.authKeyRef = new DniePrivateKeyReference(
            		this,
            		prKdf.getKeyIdentifier(i),
            		new Location(prKdf.getKeyPath(i)),
            		AUTH_KEY_LABEL,
            		prKdf.getKeyReference(i),
            		DEFAULT_KEY_SIZE
        		);
            }
            else if (SIGN_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                this.signKeyRef = new DniePrivateKeyReference(
            		this,
            		prKdf.getKeyIdentifier(i),
            		new Location(prKdf.getKeyPath(i)),
            		SIGN_KEY_LABEL,
            		prKdf.getKeyReference(i),
            		DEFAULT_KEY_SIZE
        		);
            }
            else if (CYPH_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                this.cyphKeyRef = new DniePrivateKeyReference(
            		this,
            		prKdf.getKeyIdentifier(i),
            		new Location(prKdf.getKeyPath(i)),
            		CYPH_KEY_LABEL,
            		prKdf.getKeyReference(i),
            		DEFAULT_KEY_SIZE
        		);
            }
            else {
            	// Certificado de firma con seudonimo
            	this.signAliasKeyRef = new DniePrivateKeyReference(
        			this,
        			prKdf.getKeyIdentifier(i),
        			new Location(prKdf.getKeyPath(i)),
        			prKdf.getKeyName(i),
        			prKdf.getKeyReference(i),
        			DEFAULT_KEY_SIZE
    			);
            }
        }
    }

    /** Recupera el n&uacute;mero de serie de un DNIe.
     * @return Un array de bytes que contiene el n&uacute;mero de serie del DNIe.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona cerrada y no es posible abrirla. */
    @Override
    public byte[] getSerialNumber() throws ApduConnectionException {
        final ResponseApdu response = getConnection().transmit(new GetChipInfoApduCommand());
        if (response.isOk()) {
        	return response.getData();
        }
        throw new ApduConnectionException(
    		"Respuesta invalida en la obtencion del numero de serie con el codigo: " + response.getStatusWord() //$NON-NLS-1$
		);
    }

    /** {@inheritDoc} */
	@Override
    public String getCardName() {
        return "DNIe"; //$NON-NLS-1$
    }

    /** {@inheritDoc} */
    @Override
    public String[] getAliases() {
    	if (this.aliases == null) {
	    	final List<String> aliasesList = new ArrayList<>();
	    	aliasesList.add(CERT_ALIAS_AUTH);
	    	aliasesList.add(CERT_ALIAS_SIGN);
	    	if (this.cyphCertPath != null) {
	    		aliasesList.add(CERT_ALIAS_CYPHER);
	    	}
	    	if (this.signAliasCertPath != null) {
	    		aliasesList.add(CERT_ALIAS_SIGNALIAS);
	    	}
	    	this.aliases = aliasesList.toArray(new String[0]);
    	}
    	return this.aliases;
    }

    /** Carga el certificado de la CA intermedia y las localizaciones de los
     * certificados de firma y autenticaci&oacute;n.
     * @throws ApduConnectionException Si hay problemas en la precarga. */
    protected void preloadCertificates() throws ApduConnectionException {
        final Cdf cdf = new Cdf();
        try {
        	selectMasterFile();
        	final byte[] cdfBytes = selectFileByLocationAndRead(CDF_LOCATION);
            cdf.setDerValue(cdfBytes);
        }
        catch (final Exception e) {
            throw new ApduConnectionException (
        		"No se ha podido cargar el CDF de la tarjeta: " + e.toString(), e //$NON-NLS-1$
    		);
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
            		byte[] intermediateCaCertEncoded = selectFileByLocationAndRead(
						new Location(
							cdf.getCertificatePath(i)
						)
    				);
            		try {
	            		intermediateCaCertEncoded = deflate(
	        				intermediateCaCertEncoded
	    				);
            		}
                    catch(final Exception e) {
                    	LOGGER.warning(
                			"Ha fallado la descompresion del certificado de CA intermedia de CNP, se probara sin descomprimir: " + e //$NON-NLS-1$
            			);
                    }
            		this.intermediateCaCert = (X509Certificate) CERT_FACTORY.generateCertificate(
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
            	this.signAliasCertPath = new Location(cdf.getCertificatePath(i));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public X509Certificate getCertificate(final String alias) throws CryptoCardException, PinException {

        if (this.authCert == null) { // Este certificado esta presente en todas las variantes del DNIe
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
        if (CERT_ALIAS_SIGNALIAS.equals(alias)) {
        	return this.signAliasCert;
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public void verifyCaIntermediateIcc() {
        // No se comprueba
    }

    /** {@inheritDoc} */
    @Override
    public void verifyIcc() {
        // No se comprueba
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getIccCertEncoded() throws IOException {
        byte[] iccCertEncoded;
        try {
        	selectMasterFile();
            iccCertEncoded = selectFileByIdAndRead(CERT_ICC_FILE_ID);
        }
        catch (final ApduConnectionException e) {
            throw new IOException(
        		"Error en el envio de APDU para la seleccion del certificado de componente de la tarjeta: " + e, e //$NON-NLS-1$
    		);
        }
        catch (final Iso7816FourCardException e) {
            throw new IOException("Error en la seleccion del certificado de componente de la tarjeta: " + e, e); //$NON-NLS-1$
        }
        return iccCertEncoded;
    }

    /** {@inheritDoc} */
    @Override
    public void verifyIfdCertificateChain(final Cwa14890PublicConstants consts) throws ApduConnectionException {

        // Seleccionamos en la tarjeta la clave publica de la CA raiz del controlador
    	// (clave publica de la autoridad certificadora raiz de la jerarquia de certificados
    	// verificable por la tarjeta).
        try {
            setPublicKeyToVerification(consts.getRefCCvCaPublicKey());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error al seleccionar para verificacion la " +//$NON-NLS-1$
                     "clave publica de la CA raiz de los certificados verificables por la tarjeta", e //$NON-NLS-1$
    		);
        }

        // Verificamos la CA intermedia del controlador. La clave publica queda almacenada en memoria
        try {
            verifyCertificate(consts.getCCvCa());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error en la verificacion del certificado de la CA intermedia de Terminal: " + e, e //$NON-NLS-1$
    		);
        }

        // Seleccionamos a traves de su CHR la clave publica del certificado recien cargado en memoria
        // (CA intermedia de Terminal) para su verificacion
        try {
            setPublicKeyToVerification(consts.getChrCCvCa());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error al establecer la clave publica del certificado de CA intermedia de Terminal para su verificacion en tarjeta: " + e, e //$NON-NLS-1$
    		);
        }

        // Enviamos el certificado de Terminal (C_CV_IFD) para su verificacion por la tarjeta
        try {
            verifyCertificate(consts.getCCvIfd());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error en la verificacion del certificado de Terminal: " + e, e //$NON-NLS-1$
    		);
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getRefIccPrivateKey(final Cwa14890PublicConstants consts) {
        return consts.getRefIccPrivateKey();
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getChrCCvIfd(final Cwa14890PublicConstants consts) {
        return consts.getChrCCvIfd();
    }

    /** {@inheritDoc} */
    @Override
    public RSAPrivateKey getIfdPrivateKey(final Cwa14890PrivateConstants consts) {
        return consts.getIfdPrivateKey();
    }

    /** {@inheritDoc} */
    @Override
    public void setKeysToAuthentication(final byte[] refPublicKey,
    		                            final byte[] refPrivateKey) throws ApduConnectionException {
        final CommandApdu apdu = new MseSetAuthenticationKeyApduCommand((byte) 0x00, refPublicKey, refPrivateKey);
        final ResponseApdu res = getConnection().transmit(apdu);
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
        final ResponseApdu res = getConnection().transmit(apdu);
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
        return getConnection().transmit(apdu).isOk();
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
        else if (CERT_ALIAS_SIGNALIAS.equals(alias)){
        	return this.signAliasKeyRef;
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                 PinException {
    	final byte[] ret = signInternal(data, signAlgorithm, privateKeyReference);

        // Reestablecemos el canal inicial, para que en una segunda firma se tenga que volver a pedir
    	// el PIN y rehacer los canales CWA
        try {
        	this.rawConnection.reset();
    		setConnection(this.rawConnection);
		}
        catch (final ApduConnectionException e) {
        	throw new CryptoCardException(
        		"Error en el establecimiento del canal inicial previo al seguro de PIN: " + e, e //$NON-NLS-1$
    		);
		}

    	return ret;
    }

    protected byte[] signInternal(final byte[] data,
    		                      final String signAlgorithm,
    		                      final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                            PinException {
        if (!(privateKeyReference instanceof DniePrivateKeyReference)) {
            throw new IllegalArgumentException(
        		"La referencia a la clave privada tiene que ser de tipo DniePrivateKeyReference" //$NON-NLS-1$
    		);
        }

        if (this.callbackHandler != null) {
        	Callback cc;
        	// Callback para autorizar la firma
    		cc = new CustomAuthorizeCallback();

        	try {
				this.callbackHandler.handle(
					new Callback[] {
						cc
					}
				);
			}
        	catch (final Exception e) {
    			throw new AccessControlException(
    				"No ha sido posible pedir la confirmacion de firma al usuario: " + e //$NON-NLS-1$
    			);
			}

        	if (!((CustomAuthorizeCallback)cc).isAuthorized()) {
				throw new CancelledSignOperationException(
					"El usuario ha denegado la operacion de firma" //$NON-NLS-1$
				);
			}
        }
        else {
        	LOGGER.warning(
    			"No se ha proporcionado un CallbackHandler para mostrar el dialogo de confirmacion de firma" //$NON-NLS-1$
			);
        }

        return signOperation(data, signAlgorithm, privateKeyReference);
    }

    /** Realiza la operaci&oacute;n de firma.
     * @param data Datos que se desean firmar.
     * @param signAlgorithm Algoritmo de firma (por ejemplo, SHA512withRSA, SHA1withRSA, etc.).
     * @param privateKeyReference Referencia a la clave privada para la firma.
     * @return Firma de los datos.
     * @throws CryptoCardException Cuando se produce un error durante la operaci&oacute;n de firma.
     * @throws PinException Si el PIN proporcionado en la <i>PasswordCallback</i>
     *                      es incorrecto y no estaba habilitado el reintento autom&aacute;tico.
     * @throws es.gob.jmulticard.card.AuthenticationModeLockedException Cuando el DNIe est&aacute; bloqueado. */
    protected byte[] signOperation(final byte[] data,
    		                       final String signAlgorithm,
    		                       final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                             PinException {
        openSecureChannelIfNotAlreadyOpened();

        ResponseApdu res;
        try {
            CommandApdu apdu = new MseSetComputationApduCommand(
        		(byte) 0x00, ((DniePrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath(),
        		null
    		);

            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
            		"Error en el establecimiento de las clave de firma con respuesta: " + res.getStatusWord(), res.getStatusWord() //$NON-NLS-1$
        		);
            }

            final byte[] digestInfo;
            try {
                digestInfo = DigestInfo.encode(signAlgorithm, data, this.cryptoHelper);
            }
            catch (final IOException e) {
                throw new DnieCardException("Error en el calculo del hash para firmar: " + e, e); //$NON-NLS-1$
            }

            apdu = new PsoSignHashApduCommand((byte) 0x00, digestInfo);
            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
                	"Error durante la operacion de firma con respuesta: " + res.getStatusWord(), res.getStatusWord() //$NON-NLS-1$
                );
            }
        }
        catch(final LostChannelException e) {
            try {
                getConnection().close();
                if (getConnection() instanceof Cwa14890Connection) {
                    setConnection(((Cwa14890Connection) getConnection()).getSubConnection());
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
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido o no se ha proporcionado
     * 						un PIN para validar.  */
    protected void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, PinException {
        // Abrimos el canal seguro si no lo esta ya
        if (!isSecurityChannelOpen()) {
        	// Aunque el canal seguro estuviese cerrado, podria si estar enganchado
            if (!(getConnection() instanceof Cwa14890Connection)) {
            	final ApduConnection secureConnection;
        		secureConnection = new Cwa14890OneV1Connection(
            		this,
            		getConnection(),
            		this.cryptoHelper,
            		getCwa14890PublicConstants(),
            		getCwa14890PrivateConstants()
        		);
                try {
                    setConnection(secureConnection);
                }
                catch (final ApduConnectionException e) {
                    throw new CryptoCardException("Error en el establecimiento del canal seguro: " + e, e); //$NON-NLS-1$
                }
            }
            try {
                verifyPin(getInternalPasswordCallback());
            }
            catch (final ApduConnectionException e) {
                throw new CryptoCardException("Error en la apertura del canal seguro: " + e, e); //$NON-NLS-1$
            }
        }
    }

    private int getPinRetriesLeft() throws PinException {
    	final CommandApdu verifyCommandApdu = new RetriesLeftApduCommand();

    	ResponseApdu verifyResponse = null;
		try {
			verifyResponse = getConnection().transmit(
				verifyCommandApdu
			);
		} catch (final ApduConnectionException e) {
			throw new PinException(
					"Error obteniendo el PIN del CallbackHandler: " + e  //$NON-NLS-1$
				);
		}
    	return verifyResponse.getStatusWord().getLsb() - (byte) 0xC0;
    }

    protected PasswordCallback getInternalPasswordCallback() throws PinException {
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
        	final PasswordCallback  pwc = new PasswordCallback(
    			CardMessages.getString("Dnie.0", Integer.toString(retriesLeft)), //$NON-NLS-1$
				false
			);
			try {
				this.callbackHandler.handle(new Callback[] { pwc });
			}
			catch (final IOException e) {
				throw new PinException(
					"Error obteniendo el PIN del CallbackHandler: " + e, //$NON-NLS-1$
					e
				);
			}
			catch (final UnsupportedCallbackException e) {
				throw new PinException(
					"El CallbackHandler no soporta pedir el PIN al usuario: " + e, //$NON-NLS-1$
					e
				);
			}
			if (pwc.getPassword() == null || pwc.getPassword().toString().isEmpty()) {
				throw new PinException(
					"El PIN no puede ser nulo ni vacio" //$NON-NLS-1$
				);
			}
			return pwc;
    	}
    	throw new PinException("No hay ningun metodo para obtener el PIN"); //$NON-NLS-1$
    }

    private X509Certificate loadCertificate(final Location location) throws IOException,
                                                                            Iso7816FourCardException,                                                                         CertificateException {
    	selectMasterFile();
        byte[] certEncoded = selectFileByLocationAndRead(location);
        try {
	        certEncoded = deflate(
        		certEncoded
			);
        }
        catch(final Exception e) {
        	LOGGER.warning(
    			"Ha fallado la descompresion del certificado, se probara sin descomprimir: " + e //$NON-NLS-1$
			);
        }
        return (X509Certificate) CERT_FACTORY.generateCertificate(new ByteArrayInputStream(certEncoded));
    }

    protected void loadCertificatesInternal() throws CryptoCardException {

        // Cargamos certificados si es necesario
    	if (this.authCert == null ||
    		this.signCert == null ||
    		this.cyphCert == null && this.cyphCertPath != null ||
    		this.signAliasCert == null && this.signAliasCertPath != null) {
		        try {
	        		this.signCert = loadCertificate(this.signCertPath);
	        		this.authCert = loadCertificate(this.authCertPath);
		            if (this.cyphCertPath != null) {
	            		this.cyphCert = loadCertificate(this.cyphCertPath);
	            	}
		            if (this.signAliasCertPath != null) {
		            	this.signAliasCert = loadCertificate(this.signAliasCertPath);
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

    /** Carga los certificados del usuario para utilizarlos cuando se desee (si no estaban ya cargados), abriendo el canal seguro de
     * la tarjeta si fuese necesario, mediante el PIN de usuario.
     * @throws CryptoCardException Cuando se produce un error en la operaci&oacute;n con la tarjeta
     * @throws PinException Si el PIN proporcionado en la <i>PasswordCallback</i>
     *                                                es incorrecto y no estaba habilitado el reintento autom&aacute;tico
     * @throws es.gob.jmulticard.card.AuthenticationModeLockedException Cuando el DNIe est&aacute; ha bloqueado
     * @throws es.gob.jmulticard.card.dnie.CancelledSignOperationException Cuando se ha cancelado la inserci&oacute;n del PIN
     *                                                                           usando el di&aacute;logo gr&aacute;fico integrado. */
    protected void loadCertificates() throws CryptoCardException, PinException {
    	// Abrimos el canal si es necesario
    	openSecureChannelIfNotAlreadyOpened();
        // Cargamos certificados si es necesario
    	loadCertificatesInternal();
    }

	@Override
    protected void selectMasterFile() throws ApduConnectionException, Iso7816FourCardException {
    	selectFileByName(MASTER_FILE_NAME);
    }

    /** Descomprime un certificado contenido en el DNIe.
     * @param compressedCertificate Certificado comprimido en ZIP a partir del 9 byte.
     * @return Certificado codificado.
     * @throws IOException Cuando se produce un error en la descompresion del certificado. */
    protected static byte[] deflate(final byte[] compressedCertificate) throws IOException {
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

    protected boolean isSecurityChannelOpen() {
	    //Devuelve true si el canal actual es de PIN o de usuario
        return getConnection() instanceof Cwa14890Connection && getConnection().isOpen() && !(getConnection() instanceof PaceConnection);
    }

    @Override
    public void verifyPin(final PasswordCallback psc) throws ApduConnectionException,
    		                                             PinException {
    	if(psc == null) {
    		throw new IllegalArgumentException(
    			"No se puede verificar el titular con un PasswordCallback nulo" //$NON-NLS-1$
        	);
    	}
    	VerifyApduCommand verifyCommandApdu = new VerifyApduCommand((byte) 0x00, psc);

    	final ResponseApdu verifyResponse = getConnection().transmit(
			verifyCommandApdu
    	);
    	verifyCommandApdu = null;

        // Comprobamos si ocurrio algun error durante la verificacion del PIN para volverlo
        // a pedir si es necesario
        if (!verifyResponse.isOk()) {
            if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
            	// Si no hay reintento automatico se lanza la excepcion
            	// Incluimos una proteccion en el caso de usar algun "CachePasswordCallback" del
            	// Cliente @firma, que derivaria en DNI bloqueado
            	if (!PIN_AUTO_RETRY || psc.getClass().getName().endsWith("CachePasswordCallback")) { //$NON-NLS-1$
            		throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
            	}
            	// Si hay reintento automatico volvemos a pedir el PIN con la misma CallBack
            	verifyPin(
            		getInternalPasswordCallback()
            	);
            }
            else if (verifyResponse.getStatusWord().getMsb() == (byte)0x69 && verifyResponse.getStatusWord().getLsb() == (byte)0x83) {
            	throw new AuthenticationModeLockedException();
            }
            else if (verifyResponse.getStatusWord().getMsb() == (byte)0x00 && verifyResponse.getStatusWord().getLsb() == (byte)0x00) {
            	throw new ApduConnectionException("Se ha perdido el canal NFC"); //$NON-NLS-1$
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

	@Override
	public int getIfdKeyLength(final Cwa14890PublicConstants consts) {
		return consts.getIfdKeyLength();
	}

	/** Realiza la operaci&oacute;n de cambio de PIN. Necesita tener un canal administrativo abierto.
	 * @param oldPin PIN actual.
	 * @param newPin PIN nuevo.
	 * @return APDU de respuesta de la operaci&oacute;n.
	 * @throws CryptoCardException Cuando se produce un error durante la operaci&oacute;n de firma.
	 * @throws PinException Si el PIN actual es incorrecto
	 * @throws AuthenticationModeLockedException Cuando el DNIe est&aacute; bloqueado. */
	public byte[] changePIN(final String oldPin, final String newPin) throws CryptoCardException,
	                                                                         PinException,
	                                                                         AuthenticationModeLockedException {
		openSecureChannelIfNotAlreadyOpened();
		try {
			//Seleccion de directorio maestro
			selectMasterFile();
			//Seleccion de fichero de PIN por Id
			final byte[] pinFile = new byte[] {(byte)0x00, (byte) 0x00};
			selectFileById(pinFile);
			//Envio de APDU de cambio de PIN
			final CommandApdu apdu = new ChangePINApduCommand(oldPin.getBytes(), newPin.getBytes());
			final ResponseApdu res = getConnection().transmit(apdu);
			if (!res.isOk()) {
				throw new DnieCardException(
					"Error en el establecimiento de las variables de entorno para el cambio de PIN", res.getStatusWord() //$NON-NLS-1$
				);
			}
			return res.getData();
		}
		catch(final LostChannelException e) {
			LOGGER.warning("Se ha perdido el canal seguro para cambiar el PIN, se procede a recuperarlo: " + e); //$NON-NLS-1$
			try {
				getConnection().close();
				if (getConnection() instanceof Cwa14890Connection) {
					setConnection(((Cwa14890Connection) getConnection()).getSubConnection());
				}
				// Se vuelve a llamar ya con el canal recuperado.
				// Como no hay control de la recursividad, si hay continuas perdidas de canal
				// se terminara provocando un desbordamiento de pila.
				return changePIN(oldPin, newPin);
			}
			catch (final Exception ex) {
				throw new DnieCardException("No se pudo recuperar el canal seguro para firmar: " + ex, ex); //$NON-NLS-1$
			}
		}
		catch (final ApduConnectionException e) {
			throw new DnieCardException("Error en la transmision de comandos a la tarjeta: " + e, e); //$NON-NLS-1$
		}
		catch (final Iso7816FourCardException e) {
			throw new DnieCardException("No se pudo seleccionar el fichero de PIN de la tarjeta: " + e, e); //$NON-NLS-1$
		}
	}

    /** Asigna un CallbackHandler a la tarjeta.
     * @param handler CallbackHandler a asignar. */
    public void setCallbackHandler(final CallbackHandler handler) {
    	this.callbackHandler = handler;
    }

	/** Asigna un <code>PasswordCallback</code> a la tarjeta.
	 * @param pwc <code>PasswordCallback</code> a asignar. */
	public void setPasswordCallback(final PasswordCallback pwc) {
		this.passwordCallback = pwc;
	}
}