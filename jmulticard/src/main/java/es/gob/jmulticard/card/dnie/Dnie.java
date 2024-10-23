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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JmcLogger;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.dnie.ChangePinApduCommand;
import es.gob.jmulticard.apdu.dnie.GetChipInfoApduCommand;
import es.gob.jmulticard.apdu.dnie.LoadDataApduCommand;
import es.gob.jmulticard.apdu.dnie.RetriesLeftApduCommand;
import es.gob.jmulticard.apdu.dnie.SignDataApduCommand;
import es.gob.jmulticard.apdu.dnie.VerifyApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ExternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.InternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationKeyApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetComputationApduCommand;
import es.gob.jmulticard.asn1.custom.fnmt.ceressc.CeresScPrKdf;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Pkcs15Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.BadPinException;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CompressionUtils;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PasswordCallbackNotFoundException;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.iso7816eight.AbstractIso7816EightCard;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionException;
import es.gob.jmulticard.connection.LostChannelException;
import es.gob.jmulticard.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.connection.cwa14890.Cwa14890OneV1Connection;
import es.gob.jmulticard.connection.cwa14890.SecureChannelException;
import es.gob.jmulticard.connection.pace.PaceConnection;

/**
 * DNI Electr&oacute;nico.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 */
public class Dnie extends AbstractIso7816EightCard implements Dni, Cwa14890Card {

	/** Octeto que identifica una verificaci&oacute;n fallida del PIN. */
    private static final byte ERROR_PIN_SW1 = (byte) 0x63;

    /** Identificador del fichero del certificado de componente del DNIe. */
    private static final byte[] CERT_ICC_FILE_ID = { (byte) 0x60, (byte) 0x1F };

    /** Nombre del <i>Master File</i> del DNIe. */
    private static final String MASTER_FILE_NAME = "Master.File"; //$NON-NLS-1$

    /** Localizaci&oacute;n del CDF PKCS#15. */
    private static final Location CDF_LOCATION = new Location("50156004"); //$NON-NLS-1$

    /** Localizaci&oacute;n del PrKDF PKCS#15. */
    private static final Location PRKDF_LOCATION = new Location("50156001"); //$NON-NLS-1$

    /** Localizaci&oacute;n del EF IDESP. */
	private static final Location IDESP_LOCATION = new Location("3F000006"); //$NON-NLS-1$

	private final Set<String> aliases = new HashSet<>();

    /** Certificados de la tarjeta indexados por su alias. */
    private final Map<String, X509Certificate> certs = new LinkedHashMap<>();

    /**
     * Alias de los certificados de la tarjeta indexados por el identificador
     * interno del certificado (pasado de <code>byte[]</code> a <code>String</code>).
     */
    private final Map<String, String> aliasByCertAndKeyId = new LinkedHashMap<>();

    /** Referencias a las claves privadas de la tarjeta indexadas por el alias de su certificado asociado. */
    private final Map<String, DniePrivateKeyReference> keyReferences = new LinkedHashMap<>();

    /** Manejador de funciones criptogr&aacute;ficas. */
    private final CryptoHelper cryptoHelper;

    /** Conexi&oacute;n inicial con la tarjeta, sin ning&uacute;n canal seguro. */
    protected ApduConnection rawConnection;

    private PasswordCallback passwordCallback;
    private CallbackHandler callbackHandler;

	//*************************************************************************
	//************************ CONSTRUCTORES **********************************

    /**
     * Construye una clase que representa un DNIe.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN del DNIe.
     * @param cryptoHlpr Funcionalidades criptogr&aacute;ficas de utilidad que
     *                   pueden variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se proporciona
     *                                 cerrada y no es posible abrirla.
     */
    protected Dnie(final ApduConnection conn,
    	           final PasswordCallback pwc,
    	           final CryptoHelper cryptoHlpr,
    	           final CallbackHandler ch) throws ApduConnectionException {
        super((byte) 0x00, conn);
        conn.reset();
        connect(conn);

        this.rawConnection = conn;
        this.callbackHandler = ch;

        this.passwordCallback = pwc;

        if (cryptoHlpr == null) {
            throw new IllegalArgumentException("El CryptoHelper no puede ser nulo"); //$NON-NLS-1$
        }
        this.cryptoHelper = cryptoHlpr;

		loadCertificates();
    }

	//*************************************************************************
	//********************* METODOS PROTEGIDOS ********************************

    /**
     * Obtiene la clase con funcionalidades de base de criptograf&iacute;a.
     * @return Clase con funcionalidades de base de criptograf&iacute;a.
     */
    protected final CryptoHelper getCryptoHelper() {
    	return this.cryptoHelper;
    }

    /**
     * Obtiene la <code>PasswordCallback</code>.
	 * @return <code>PasswordCallback</code>.
	 */
    protected final PasswordCallback getPasswordCallback() {
    	return this.passwordCallback;
    }

	/**
	 * Obtiene las constantes p&uacute;blicas CWA-14890 para el cifrado de canal.
	 * @return Constantes p&uacute;blicas CWA-14890 para el cifrado de canal.
	 */
	@SuppressWarnings("static-method")
	protected Cwa14890PublicConstants getCwa14890PublicConstants() {
		return new DnieCwa14890Constants();
	}

	/**
	 * Obtiene las constantes privadas CWA-14890 para el cifrado de canal.
	 * @return Constantes privadas CWA-14890 para el cifrado de canal.
	 */
	@SuppressWarnings("static-method")
	protected Cwa14890PrivateConstants getCwa14890PrivateConstants() {
		return new DnieCwa14890Constants();
	}

    /**
     * Ejecuta la operaci&oacute;n interna de firma de la tarjeta.
     * @param data Datos a firmar.
     * @param signAlgorithm Algoritmo de firma.
     * @param privateKeyReference Referencia a la clave privada de firma.
     * @return Datos firmados.
     * @throws CryptoCardException Si hay problemas durante el proceso.
     * @throws PinException Si no se ha podido realizar la firma por un problema con el PIN
     *                      (no estar hecha la autenticaci&oacute;n de PIN).
     */
    protected final byte[] signInternal(final byte[] data,
    		                      final String signAlgorithm,
    		                      final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                            PinException {
        if (!(privateKeyReference instanceof DniePrivateKeyReference)) {
            throw new IllegalArgumentException(
        		"La referencia a la clave privada tiene que ser de tipo DniePrivateKeyReference" //$NON-NLS-1$
    		);
        }
        return signOperation(data, signAlgorithm, privateKeyReference);
    }

    /**
     * Realiza la operaci&oacute;n de firma.
     * @param data Datos que se desean firmar.
     * @param signAlgorithm Algoritmo de firma (por ejemplo, <code>SHA512withRSA</code>, <code>SHA1withRSA</code>, etc.).
     * @param privateKeyReference Referencia a la clave privada para la firma.
     * @return Firma de los datos.
     * @throws CryptoCardException Cuando se produce un error durante la operaci&oacute;n de firma.
     * @throws PinException Si el PIN proporcionado en la <i>PasswordCallback</i> es incorrecto o
     *                      la tarjeta tiene el PIN bloqueado.
     * @throws PasswordCallbackNotFoundException Si no se ha proporcionado una forma de obtener el PIN.
     */
    private byte[] signOperation(final byte[] data,
    		                     final String signAlgorithm,
    		                     final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                           PinException {
        openSecureChannelIfNotAlreadyOpened();

        ResponseApdu res;
        try {
            CommandApdu apdu = new MseSetComputationApduCommand(
        		(byte) 0x00,
        		((DniePrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath(),
        		null
    		);
            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
            		"Error en el establecimiento de las clave de firma con respuesta: " + res.getStatusWord(), //$NON-NLS-1$
    				res.getStatusWord()
        		);
            }

            JmcLogger.info(Dnie.class.getName(), "signOperation", "Establecidas las claves de firma"); //$NON-NLS-1$ //$NON-NLS-2$

            final byte[] digestInfo;
            try {
                digestInfo = DigestInfo.encode(signAlgorithm, data, this.cryptoHelper);
            }
            catch (final IOException e) {
                throw new DnieCardException("Error en el calculo de la huella para firmar", e); //$NON-NLS-1$
            }

            apdu = new PsoSignHashApduCommand((byte) 0x00, digestInfo);
            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
            	JmcLogger.severe(
            		"Recibida APDU inesperada de respuesta al PSOSignHash:\n" + //$NON-NLS-1$
        				HexUtils.hexify(res.getBytes(), true)
        		);
                throw new DnieCardException(
                	"Error durante la operacion de firma con respuesta: " + res.getStatusWord(), //$NON-NLS-1$
                	res.getStatusWord()
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
            catch (final ApduConnectionException ex) {
                throw new DnieCardException("No se pudo recuperar el canal seguro para firmar (" + e + ")", ex); //$NON-NLS-1$ //$NON-NLS-2$
            }
            return signOperation(data, signAlgorithm, privateKeyReference);
        }
        catch (final ApduConnectionException e) {
            throw new DnieCardException("Error en la transmision de comandos para firma a la tarjeta", e); //$NON-NLS-1$
        }

        JmcLogger.info(Dnie.class.getName(), "signOperation", "Realizada correctamente la firma electronica"); //$NON-NLS-1$ //$NON-NLS-2$
        return res.getData();
    }

    /**
     * Obtiene la <code>PasswordCallback</code> predefinida.
	 * @return <code>PasswordCallback</code> predefinida.
	 * @throws BadPinException Si el <code>PasswordCallback</code> devuelve un PIN nulo o vac&iacute;o.
     * @throws PasswordCallbackNotFoundException Si no hay una <code>PasswordCallback</code> definida.
     */
    protected PasswordCallback getInternalPasswordCallback() throws PinException {
    	final int retriesLeft;
    	try {
    		retriesLeft = getPinRetriesLeft();
    	}
    	catch(final ApduConnectionException e) {
    		throw new PinException("No se ha podido obtener el numero de intentos restantes de PIN", e); //$NON-NLS-1$
    	}
		if (retriesLeft == 0) {
			throw new AuthenticationModeLockedException();
		}

    	// Si hay establecido un PasswordCallback, devolvemos ese
    	if (this.passwordCallback != null) {
    		return this.passwordCallback;
    	}

    	// Si hay establecido un CallbackHandler, le solicitamos un PasswordCallback
    	if (this.callbackHandler != null) {
        	final PasswordCallback  pwc = new PasswordCallback(
    			getPinMessage(retriesLeft),
				false
			);
			try {
				this.callbackHandler.handle(new Callback[] { pwc });
			}
			catch (final IOException | UnsupportedCallbackException e) {
				throw new PasswordCallbackNotFoundException(
					"El CallbackHandler no ha permitido pedir el PIN al usuario", e//$NON-NLS-1$
				);
			}
			if (pwc.getPassword() == null || pwc.getPassword().length < 1) {
				throw new BadPinException("El PIN no puede ser nulo ni vacio"); //$NON-NLS-1$
			}
			return pwc;
    	}
    	throw new PasswordCallbackNotFoundException("No hay ningun metodo para obtener el PIN"); //$NON-NLS-1$
    }

    /**
     * Devuelve el texto del di&aacute;logo de inserci&oacute;n de PIN.
     * @param retriesLeft Intentos restantes antes de bloquear la tarjeta.
     * @return Mensaje que mostrar en el cuerpo del di&aacute;logo de inserci&oacute;n de PIN.
     */
    @SuppressWarnings("static-method")
	protected String getPinMessage(final int retriesLeft) {
    	return CardMessages.getString("Dnie.0", Integer.toString(retriesLeft)); //$NON-NLS-1$
    }

    /**
     * Indica si el canal CWA-14890 est&aacute; o no abierto.
     * @return <code>true</code> si el canal CWA-14890 est&aacute; abierto,
     *         <code>false</code> en caso contrario.
     */
    protected final boolean isSecurityChannelOpen() {
	    //Devuelve true si el canal actual es de PIN o de usuario
        return getConnection() instanceof Cwa14890Connection &&
        		getConnection().isOpen() &&
        			!(getConnection() instanceof PaceConnection);
    }

    /**
     * Indica si es necesario haber verificado o no el PIN para poder leer los certicados.
     * @return <code>true</code> si es necesario haber verificado o no el PIN para poder leer los certicados,
     *         <code>false</code> en caso contrario.
     */
	@SuppressWarnings("static-method")
	protected boolean needsPinForLoadingCerts() {
		return true; // "true" en DNIe 1.0, "false" en cualquier otro.
	}

	//*************************************************************************
	//********************** METODOS HEREDADOS ********************************

	@Override
	protected final void selectMasterFile() throws ApduConnectionException, Iso7816FourCardException {
    	selectFileByName(MASTER_FILE_NAME);
    }

	@Override
	public String toString() {
		return getCardName();
	}

    @Override
    public final byte[] getSerialNumber() throws ApduConnectionException {
        final ResponseApdu response = getConnection().transmit(new GetChipInfoApduCommand());
        if (response.isOk()) {
        	return response.getData();
        }
        throw new ApduConnectionException(
    		"Respuesta invalida en la obtencion del numero de serie con el codigo: " + response.getStatusWord() //$NON-NLS-1$
		);
    }

	@Override
    public String getCardName() {
        return "DNIe"; //$NON-NLS-1$
    }

    @Override
    public final String[] getAliases() {
    	return this.aliases.toArray(new String[0]);
    }

	@Override
	public final X509Certificate getCertificate(final String alias) {
		return this.certs.get(alias);
	}

    @Override
    public final void verifyIcc() {
        // No se comprueba
    }

    @Override
    public final RSAPublicKey getIccCertPublicKey() throws IOException {
        final byte[] iccCertEncoded;
        try {
        	selectMasterFile();
            iccCertEncoded = selectFileByIdAndRead(CERT_ICC_FILE_ID);
        }
        catch (final ApduConnectionException e) {
            throw new IOException(
        		"Error en el envio de APDU para la seleccion del certificado de componente de la tarjeta", e //$NON-NLS-1$
    		);
        }
        catch (final Iso7816FourCardException e) {
            throw new IOException("Error en la seleccion del certificado de componente de la tarjeta", e); //$NON-NLS-1$
        }
        final X509Certificate iccCert;
        try {
        	iccCert = CryptoHelper.generateCertificate(iccCertEncoded);
		}
        catch (final CertificateException e) {
        	throw new IOException("No se pudo obtener el certificado de componente", e); //$NON-NLS-1$
		}
        return this.cryptoHelper.getRsaPublicKey(iccCert);
    }

    @Override
    public final void verifyIfdCertificateChain(final Cwa14890PublicConstants consts) throws ApduConnectionException {

        // Seleccionamos en la tarjeta la clave publica de la CA raiz del controlador
    	// (clave publica de la autoridad certificadora raiz de la jerarquia de certificados
    	// verificable por la tarjeta), indicandole su referencia dentro de la tarjeta
        try {
            setPublicKeyToVerification(consts.getRefCCvCaPublicKey());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error al seleccionar para verificacion la clave publica de la " +//$NON-NLS-1$
                     "CA raiz de los certificados verificables por la tarjeta", e //$NON-NLS-1$
    		);
        }

        // Verificamos la CA intermedia del controlador. La clave publica queda almacenada en memoria
        try {
            verifyCertificate(consts.getCCvCa());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error en la verificacion del certificado de la CA intermedia de Terminal", e //$NON-NLS-1$
    		);
        }

        // Seleccionamos a traves de su CHR la clave publica del certificado recien cargado en memoria
        // (CA intermedia de Terminal) para su verificacion
        try {
            setPublicKeyToVerification(consts.getChrCCvCa());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException(
        		"Error al establecer la clave publica del certificado de CA intermedia de Terminal para su verificacion en tarjeta", e //$NON-NLS-1$
    		);
        }

        // Enviamos el certificado de Terminal (C_CV_IFD) para su verificacion por la tarjeta
        try {
            verifyCertificate(consts.getCCvIfd());
        }
        catch (final SecureChannelException e) {
            throw new SecureChannelException("Error en la verificacion del certificado de Terminal", e); //$NON-NLS-1$
        }
    }

    @Override
    public final byte[] getRefIccPrivateKey(final Cwa14890PublicConstants consts) {
        return consts.getRefIccPrivateKey();
    }

    @Override
    public final byte[] getChrCCvIfd(final Cwa14890PublicConstants consts) {
        return consts.getChrCCvIfd();
    }

    @Override
    public final RSAPrivateKey getIfdPrivateKey(final Cwa14890PrivateConstants consts) {
        return consts.getIfdPrivateKey();
    }

    @Override
    public final void setKeysToAuthentication(final byte[] refPublicKey,
    		                            final byte[] refPrivateKey) throws ApduConnectionException {
        final CommandApdu apdu = new MseSetAuthenticationKeyApduCommand((byte) 0x00, refPublicKey, refPrivateKey);
        final ResponseApdu res = getConnection().transmit(apdu);
        if (!res.isOk()) {
            throw new SecureChannelException(
        		"Error durante el establecimiento de las claves publica y privada " + //$NON-NLS-1$
                     "para autenticacion (error: " + res.getStatusWord() + ")" //$NON-NLS-1$ //$NON-NLS-2$
            );
        }
    }

    @Override
    public byte[] getInternalAuthenticateMessage(final byte[] randomIfd,
    		                                     final byte[] chrCCvIfd) throws ApduConnectionException {
        final CommandApdu apdu = new InternalAuthenticateApduCommand((byte) 0x00, randomIfd, chrCCvIfd);
        final ResponseApdu res = getConnection().transmit(apdu);
        if (res.isOk()) {
        	return res.getData();
        }
        throw new ApduConnectionException(
    		"Respuesta invalida en la obtencion del mensaje de autenticacion interna con el codigo: " + res.getStatusWord() //$NON-NLS-1$
		);
    }

    @Override
    public final boolean externalAuthentication(final byte[] extAuthenticationData) throws ApduConnectionException {
        final CommandApdu apdu = new ExternalAuthenticateApduCommand((byte) 0x00, extAuthenticationData);
        return getConnection().transmit(apdu).isOk();
    }

    @Override
    public final PrivateKeyReference getPrivateKey(final String alias) {
    	return this.keyReferences.get(alias);
    }

    @Override
    public byte[] sign(final byte[] data,
    		           final String signAlgorithm,
    		           final PrivateKeyReference privateKeyReference) throws CryptoCardException,
    		                                                                 PinException {
    	final byte[] signBytes = signInternal(data, signAlgorithm, privateKeyReference);
    	try {
			getConnection().close();
		}
    	catch (final ApduConnectionException e) {
    		JmcLogger.severe(
				"No se ha podido cerrar el canal despues de una firma, es posible que fallen operaciones: " + e //$NON-NLS-1$
			);
		}
    	return signBytes;
    }

    @Override
    public final void verifyPin(final PasswordCallback psc) throws ApduConnectionException,
    		                                                 PinException {
    	if (psc == null) {
    		throw new IllegalArgumentException("No se puede verificar el titular con un PasswordCallback nulo"); //$NON-NLS-1$
    	}

    	final ResponseApdu verifyResponse = getConnection().transmit(new VerifyApduCommand((byte) 0x00, psc));

        // Comprobamos si ocurrio algun error durante la verificacion del PIN,
    	// para volverlo a pedir si es necesario
        if (!verifyResponse.isOk()) {
            if (verifyResponse.getStatusWord().getMsb() == ERROR_PIN_SW1) {
        		throw new BadPinException(verifyResponse.getStatusWord().getLsb() - (byte) 0xC0);
            }
			if (
				verifyResponse.getStatusWord().getMsb() == (byte)0x69 &&
            	verifyResponse.getStatusWord().getLsb() == (byte)0x83
        	) {
            	throw new AuthenticationModeLockedException(); // 6983
            }
			if (
				verifyResponse.getStatusWord().getMsb() == (byte)0x00 &&
            	verifyResponse.getStatusWord().getLsb() == (byte)0x00
        	) {
            	throw new ApduConnectionException("Se ha perdido el canal NFC"); //$NON-NLS-1$
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
	public final int getIfdKeyLength(final Cwa14890PublicConstants consts) {
		return consts.getIfdKeyLength();
	}

	//*************************************************************************
	//*********************** METODOS PUBLICOS ********************************

	/**
	 * Realiza un cifrado RSA directo con una clave privada.
	 * @param data Datos a cifrar.
	 * @param privateKeyReference Referencia a la clave privada RSA a usar.
	 * @return Datos cifrados.
	 * @throws CryptoCardException Si hay errores en el proceso en la tarjeta o en la comunicaci&oacute;n con ella.
	 * @throws PinException Si el PIN introducido no es correcto.
	 * @throws LostChannelException Si se pierde el canal de cifrado.
	 */
	public final byte[] cipherData(final byte[] data,
                                   final PrivateKeyReference privateKeyReference) throws CryptoCardException,
                                                                                         PinException,
                                                                                         LostChannelException {
        openSecureChannelIfNotAlreadyOpened();

        ResponseApdu res;
        try {
        	CommandApdu apdu = new LoadDataApduCommand(data);
			res = getConnection().transmit(apdu);
			if(!res.isOk()) {
				JmcLogger.severe(
            		"Recibida APDU inesperada de respuesta a la carga de datos para cifrado RSA:\n" + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
        		);
                throw new DnieCardException(
                	"Error durante la operacion de carga de datos para cifrado RSA: " +  res.getStatusWord(), //$NON-NLS-1$
        			res.getStatusWord()
                );
			}

			apdu = new SignDataApduCommand(
        		((DniePrivateKeyReference) privateKeyReference).getKeyReference(), // Referencia
        		((DniePrivateKeyReference) privateKeyReference).getKeyBitSize()    // Tamano en bits de la clave
    		);

            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
            	JmcLogger.severe(
            		"Recibida APDU inesperada de respuesta al SignData:\n" + HexUtils.hexify(res.getBytes(), true) //$NON-NLS-1$
        		);
                throw new DnieCardException(
                	"Error durante la operacion de cifrado RSA con respuesta: " + res.getStatusWord(), //$NON-NLS-1$
                	res.getStatusWord()
                );
            }
        }
        catch(final LostChannelException e) {
        	throw e;
        }
        catch (final ApduConnectionException e) {
            throw new DnieCardException("Error en la transmision de comandos para cifrado a la tarjeta", e); //$NON-NLS-1$
        }

        return res.getData();
	}

    /**
     * Establece y abre el canal seguro CWA-14890 si no lo estaba ya.
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido o
     *                      la tarjeta tiene el PIN bloqueado.
     * @throws PasswordCallbackNotFoundException Si no se ha proporcionado una forma de obtener el PIN.
     */
    public void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException,
                                                             PinException {
    	openSecureChannelIfNotAlreadyOpened(true);
    }

    /**
     * Establece y abre el canal seguro CWA-14890 si no lo estaba ya.
     * @param doChv <code>true</code> si la apertura de canal seguro debe incluir la verificaci&oacute;n
     *              de PIN, <code>false</code> si debe abrirse canal seguro <b>sin verificar PIN</b>.
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido o
     *         la tarjeta tiene el PIN bloqueado.
     * @throws PasswordCallbackNotFoundException Si no se ha proporcionado una forma de obtener el PIN.
     */
    public void openSecureChannelIfNotAlreadyOpened(final boolean doChv) throws CryptoCardException,
                                                                                PinException {
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
                    throw new CryptoCardException("Error en el establecimiento del canal seguro", e); //$NON-NLS-1$
                }
            }
            if (doChv) {
	            try {
	                verifyPin(getInternalPasswordCallback());
	            }
	            catch (final ApduConnectionException e) {
	                throw new CryptoCardException("Error en la apertura del canal seguro", e); //$NON-NLS-1$
	            }
            }
        }
    }

    /**
     * Devuelve los intentos restantes de comprobaci&oacute;n de PIN del DNIe.
     * @return Intentos restantes de comprobaci&oacute;n de PIN del DNIe.
     * @throws ApduConnectionException Cuando hay problemas en el proceso.
     */
    public int getPinRetriesLeft() throws ApduConnectionException {
    	final CommandApdu verifyCommandApdu = new RetriesLeftApduCommand();
    	final ResponseApdu verifyResponse = getConnection().transmit(verifyCommandApdu);
    	final StatusWord resSw = verifyResponse.getStatusWord();
    	if (resSw.getMsb() == (byte) 0x69 && resSw.getLsb() == (byte) 0x82) {
    		throw new ApduConnectionException("Error obteniendo los intentos restantes de PIN: " + resSw); //$NON-NLS-1$
    	}
    	return resSw.getLsb() - (byte) 0xC0;
    }

	/**
	 * Realiza la operaci&oacute;n de cambio de PIN. Necesita tener un canal administrativo abierto.
	 * @param oldPin PIN actual.
	 * @param newPin PIN nuevo.
	 * @return APDU de respuesta de la operaci&oacute;n.
	 * @throws CryptoCardException Cuando se produce un error en el cambio de PIN.
	 * @throws PinException Si el PIN actual es incorrecto.
	 * @throws AuthenticationModeLockedException Cuando el DNIe est&aacute; bloqueado.
	 */
	public final byte[] changePIN(final String oldPin, final String newPin) throws CryptoCardException,
	                                                                               PinException {
		openSecureChannelIfNotAlreadyOpened();
		try {
			selectMasterFile(); //Seleccion de directorio maestro
			final byte[] pinFile = {(byte)0x00, (byte) 0x00}; //Seleccion de fichero de PIN por Id
			selectFileById(pinFile);
			//Envio de APDU de cambio de PIN
			final CommandApdu apdu = new ChangePinApduCommand(oldPin.getBytes(), newPin.getBytes());
			final ResponseApdu res = getConnection().transmit(apdu);
			if (!res.isOk()) {
				throw new DnieCardException(
					"Error en el establecimiento de las variables de entorno para el cambio de PIN", res.getStatusWord() //$NON-NLS-1$
				);
			}
			return res.getData();
		}
		catch(final LostChannelException e) {
			JmcLogger.warning("Se ha perdido el canal seguro para cambiar el PIN, se procede a recuperarlo: " + e); //$NON-NLS-1$
			try {
				getConnection().close();
				if (getConnection() instanceof Cwa14890Connection) {
					setConnection(((Cwa14890Connection) getConnection()).getSubConnection());
				}
				// Se vuelve a llamar ya con el canal recuperado.
				// Como no hay control de la recursividad, si hay perdidas de canal continuadas
				// se puede provocar un desbordamiento de pila.
				return changePIN(oldPin, newPin);
			}
			catch (final Exception ex) {
				throw new DnieCardException("No se pudo recuperar el canal seguro para firmar", ex); //$NON-NLS-1$
			}
		}
		catch (final ApduConnectionException e) {
			throw new DnieCardException(
				"Error en la transmision de comandos para cambio de PIN a la tarjeta", e //$NON-NLS-1$
			);
		}
		catch (final Iso7816FourCardException e) {
			throw new DnieCardException("No se pudo seleccionar el fichero de PIN de la tarjeta", e); //$NON-NLS-1$
		}
	}

    /**
     * Asigna un <code>CallbackHandler</code> a la tarjeta.
     * @param handler <code>CallbackHandler</code> a asignar.
     */
    public final void setCallbackHandler(final CallbackHandler handler) {
    	this.callbackHandler = handler;
    }

	/**
	 * Asigna un <code>PasswordCallback</code> a la tarjeta.
	 * @param pwc <code>PasswordCallback</code> a asignar.
	 */
	public final void setPasswordCallback(final PasswordCallback pwc) {
		this.passwordCallback = pwc;
	}

	/**
	 * Obtiene el n&uacute;mero de soporte (IDESP) del DNIe.
	 * @return Obtiene el n&uacute;mero de soporte (IDESP) del DNIe.
	 * @throws Iso7816FourCardException Si hay problemas enviando la APDU.
	 * @throws FileNotFoundException Si no se encuentra el fichero que contiene el IDESP.
	 * @throws IOException Si no se puede conectar con la tarjeta.
	 */
	public String getIdesp() throws Iso7816FourCardException, IOException {
		final String idEsp = new String(selectFileByLocationAndRead(IDESP_LOCATION));
		JmcLogger.info(Dnie.class.getName(), "getIdesp", "Leido el IDESP del DNIe: " + idEsp.trim()); //$NON-NLS-1$ //$NON-NLS-2$
		return idEsp;
	}

    /**
     * Conecta con el lector del sistema que tenga un DNIe insertado.
     * @param conn Conexi&oacute;n hacia el DNIe.
     * @throws ApduConnectionException Si hay problemas de conexi&oacute;n con la tarjeta.
     */
    public static void connect(final ApduConnection conn) throws ApduConnectionException {
    	if (!conn.isOpen()) {
    		conn.open();
    	}
    }

	//*************************************************************************
	//*********************** METODOS PRIVADOS ********************************

    /**
     * Carga localizaciones de claves, alias y certificados.
     * @throws ApduConnectionException Si hay problemas en la carga.
     */
	private void loadCertificates() throws ApduConnectionException {
    	if (needsPinForLoadingCerts()) {
    		try {
				openSecureChannelIfNotAlreadyOpened(true);
			}
    		catch (final CryptoCardException | PinException e) {
				throw new ApduConnectionException("Error en la verificacion de PIN para la carga de certificados", e); //$NON-NLS-1$
			}
    	}
		PrKdf prkdf;
		try {
			// Nos vamos al raiz antes de nada
			selectMasterFile();

			// Leemos el CDF
			final byte[] cdfBytes = selectFileByLocationAndRead(CDF_LOCATION);

			// Cargamos el CDF
			final Pkcs15Cdf cdf = new Cdf();
			cdf.setDerValue(cdfBytes);

			JmcLogger.info(
				Dnie.class.getName(),
				"loadCertificates", //$NON-NLS-1$
				"Ledido el CDF del DNIe: " + cdf.getCertificateCount() + " certificados" //$NON-NLS-1$ //$NON-NLS-2$
			);

			for (int i = 0; i < cdf.getCertificateCount(); i++) {
				final Location loc = new Location(cdf.getCertificatePath(i).replace("\\", "").trim()); //$NON-NLS-1$ //$NON-NLS-2$
				final X509Certificate cert = CompressionUtils.getCertificateFromCompressedOrNotData(
					selectFileByLocationAndRead(loc),
					this.cryptoHelper
				);
				final String alias = cdf.getCertificateAlias(i);
				this.aliasByCertAndKeyId.put(HexUtils.hexify(cdf.getCertificateId(i), false), alias);
				this.certs.put(alias, cert);
				JmcLogger.info(
					Dnie.class.getName(),
					"loadCertificates", //$NON-NLS-1$
					"Cargado certificado: " + alias //$NON-NLS-1$
				);
			}

			// Leemos el PrKDF
			final byte[] prkdfBytes = selectFileByLocationAndRead(PRKDF_LOCATION);

			// Establecemos el valor del PrKDF
			try {
				prkdf = new PrKdf();
				prkdf.setDerValue(prkdfBytes);
			}
			catch(final Exception e) {
				JmcLogger.warning(
					"Detectado posible PrKDF con CommonPrivateKeyAttributes vacio, se prueba con estructura alternativa: " + e //$NON-NLS-1$
				);
				prkdf = new CeresScPrKdf();
				prkdf.setDerValue(prkdfBytes);
			}
			JmcLogger.info(
				Dnie.class.getName(),
				"loadCertificates", //$NON-NLS-1$
				"Cargado PrKDF: " + prkdf.getKeyCount() + " claves privadas" //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
		catch (final Exception e) {
			throw new ApduConnectionException("Error cargando las estructuras iniciales de la tarjeta", e); //$NON-NLS-1$
		}

		for (int i = 0; i < prkdf.getKeyCount(); i++) {
			final String alias = this.aliasByCertAndKeyId.get(HexUtils.hexify(prkdf.getKeyId(i), false));
			if (alias != null) {
				this.keyReferences.put(
					alias,
					new DniePrivateKeyReference(
						this,
						prkdf.getKeyIdentifier(i),
	            		new Location(prkdf.getKeyPath(i)),
	            		prkdf.getKeyName(i),
	            		prkdf.getKeyReference(i),
	            		((RSAPublicKey)this.certs.get(alias).getPublicKey()).getModulus().bitLength()
					)
				);
			}
		}

		this.aliases.addAll(this.certs.keySet());

		// Sincronizamos claves y certificados
		hideCertsWithoutKey();
    }

	/**
	 * Oculta los alias certificados que no tienen una clave privada asociada.
	 * Los certificados se mantienen, y se pueden seguir obteniendo si se conoce el alias.
	 */
	private void hideCertsWithoutKey() {
		for (final String alias : this.aliases) {
			if (this.keyReferences.get(alias) == null) {
				this.aliases.remove(alias);
			}
		}
	}
}