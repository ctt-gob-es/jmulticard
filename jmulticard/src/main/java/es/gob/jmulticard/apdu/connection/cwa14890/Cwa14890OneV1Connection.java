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
package es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.apdu.connection.AbstractApduEncrypter;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.ApduConnectionProtocol;
import es.gob.jmulticard.apdu.connection.ApduEncrypterDes;
import es.gob.jmulticard.apdu.connection.CardConnectionListener;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;

/** Utilidad para el establecimiento y control del canal seguro con tarjeta inteligente.
 * @author Carlos Gamuci
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class Cwa14890OneV1Connection implements Cwa14890Connection {

	private static final int KICC_LENGTH = 32;
	private static final int KIFD_LENGTH = 32;
	private static final byte ISO_9796_2_PADDING_START = (byte) 0x6a;
	private static final byte ISO_9796_2_PADDING_END = (byte) 0xbc;

	private static final StatusWord INVALID_CRYPTO_CHECKSUM = new StatusWord((byte)0x66, (byte)0x88);

	/** Octeto de valor m&aacute;s significativo que indica un <code>Le</code> incorrecto en la petici&oacute;n. */
	private static final byte MSB_INCORRECT_LE = (byte) 0x6C;

	/** Octeto de valor m&aacute;s significativo que indica un <code>Le</code> incorrecto en la petici&oacute;n. */
	private static final byte MSB_INCORRECT_LE_PACE = (byte) 0x62;

    /** C&oacute;digo auxiliar para el c&aacute;lculo de la clave <code>Kenc</code> del canal seguro. */
    private static final byte[] SECURE_CHANNEL_KENC_AUX = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    /** C&oacute;digo auxiliar para el c&aacute;lculo de la clave <code>Kmac</code> del canal seguro. */
    private static final byte[] SECURE_CHANNEL_KMAC_AUX = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02
    };

    /** Utilidad para la ejecuci&oacute;n de funciones criptogr&aacute;ficas. */
    protected transient final CryptoHelper cryptoHelper;

    /** Tarjeta CWA-14890 con la que se desea establecer el canal seguro. */
    private transient Cwa14890Card card;

    /** Conexi&oacute;n subyacente para el env&iacute;o de APDUs. */
    protected transient ApduConnection subConnection;

    /** Clave Triple DES (TDES o DESEDE) para encriptar y desencriptar criptogramas. */
    private transient byte[] kenc = null;

    /** Clave Triple DES (TDES o DESEDE) para calcular y verificar <i>checksums</i>. */
    private transient byte[] kmac = null;

    /** Contador de secuencia. */
    private transient byte[] ssc = null;

    /** Indica el estado de la conexi&oacute;n. */
    protected transient boolean openState = false;

    /** Clase de utilidad para encriptar las APDU. */
    protected transient final AbstractApduEncrypter apduEncrypter;

    private transient Cwa14890PublicConstants pubConsts;
    private transient Cwa14890PrivateConstants privConsts;

    /** Obtiene la clase de utilidad para encriptar las APDU.
     * @return Clase de utilidad para encriptar las APDU. */
    @SuppressWarnings("static-method")
	protected AbstractApduEncrypter instantiateApduEncrypter() {
    	return new ApduEncrypterDes();
    }

    @Override
	public String toString() {
    	return "Conexion de tipo CWA-14890-V1 " + //$NON-NLS-1$
			(isOpen()
				? "abierta sobre " + getSubConnection() //$NON-NLS-1$
					: "cerrada"); //$NON-NLS-1$
    }

    /** Crea el canal seguro CWA-14890 para la comunicaci&oacute;n de la tarjeta.
     * Es necesario abrir el canal asoci&aacute;ndolo a una conexi&oacute;n para
     * poder trasmitir APDUs.
     * Si no se indica una conexi&oacute;n se utilizar&aacute;a la conexi&oacute;n
     * impl&iacute;cita de la tarjeta indicada.
     * @param connection Conexi&oacute;n sobre la cual montar el canal seguro.
     * @param cryptoHlpr Motor de operaciones criptogr&aacute;ficas. */
    public Cwa14890OneV1Connection(final ApduConnection connection,
    		                       final CryptoHelper cryptoHlpr) {

        if (cryptoHlpr == null) {
            throw new IllegalArgumentException(
        		"CryptoHelper no puede ser nulo" //$NON-NLS-1$
            );
        }

    	subConnection = connection instanceof Cwa14890Connection ?
			((Cwa14890Connection)connection).getSubConnection() :
				connection;
        cryptoHelper = cryptoHlpr;
    	apduEncrypter = instantiateApduEncrypter();
    }

    /** Crea el canal seguro CWA-14890 para la comunicaci&oacute;n de la tarjeta.
     * Es necesario abrir el canal asoci&aacute;ndolo a una conexi&oacute;n para
     * poder trasmitir APDUs.
     * Si no se indica una conexi&oacute;n se utilizar&aacute;a la conexi&oacute;n
     * impl&iacute;cita de la tarjeta indicada.
     * @param connectedCard Tarjeta con la funcionalidad CWA-14890.
     * @param connection Conexi&oacute;n sobre la cual montar el canal seguro.
     * @param cryptoHlpr Motor de operaciones criptogr&aacute;ficas.
     * @param cwaConsts Clase de claves p&uacute;blicas CWA-14890.
     * @param cwaPrivConsts Clase de claves privadas CWA-14890. */
    public Cwa14890OneV1Connection(final Cwa14890Card connectedCard,
    		                       final ApduConnection connection,
    		                       final CryptoHelper cryptoHlpr,
    		                       final Cwa14890PublicConstants cwaConsts,
    		                       final Cwa14890PrivateConstants cwaPrivConsts) {

        if (connectedCard == null) {
            throw new IllegalArgumentException(
        		"No se ha proporcionado la tarjeta CWA-14890 con la que abrir el canal seguro" //$NON-NLS-1$
            );
        }

        if (cryptoHlpr == null) {
            throw new IllegalArgumentException(
        		"CryptoHelper no puede ser nulo" //$NON-NLS-1$
            );
        }

        if (cwaConsts == null) {
        	throw new IllegalArgumentException(
        		"las claves CWA-14890 no pueden ser nulas" //$NON-NLS-1$
            );
        }

        card = connectedCard;
        subConnection = connection instanceof Cwa14890Connection ?
			((Cwa14890Connection)connection).getSubConnection() :
				connection;
        cryptoHelper = cryptoHlpr;
    	apduEncrypter = instantiateApduEncrypter();
    	pubConsts = cwaConsts;
    	privConsts = cwaPrivConsts;
    }

	/** Abre el canal seguro con la tarjeta.
	 * La conexi&oacute;n se reiniciar&aacute; previamente a la apertura del canal. */
    @Override
    public void open() throws ApduConnectionException {

        final ApduConnection conn = subConnection;
		conn.open();

        // Obtenemos el numero de serie de la tarjeta.
        // IMPORTANTE: Esta operacion debe realizarse antes del inicio del proceso de autenticacion
        final byte[] serial = getPaddedSerial();

        // --- STAGE 1 ---
        // Verificamos el certificado de la tarjeta.
        // ---------------

        try {
            card.verifyCaIntermediateIcc();
            card.verifyIcc();
        }
        catch (final SecurityException e) {
            conn.close();
            throw new IllegalStateException(
        		"Condicion de seguridad no satisfecha en la validacion de los certificados CWA-14890", e //$NON-NLS-1$
            );
        }
        catch (final CertificateException e) {
            conn.close();
            throw new IllegalStateException(
        		"No se han podido tratar los certificados CWA-14890", e //$NON-NLS-1$
            );
        }
        catch (final IOException e) {
            conn.close();
            throw new IllegalStateException(
        		"No se han podido validar los certificados CWA-14890", e //$NON-NLS-1$
            );
        }

        // Clave publica del certificado de componente de la tarjeta.
        // Necesario para autenticacion interna y externa.
        final RSAPublicKey iccPublicKey;
        try {
            iccPublicKey = (RSAPublicKey) card.getIccCert().getPublicKey();
        }
        catch (final IOException e) {
        	conn.close();
            throw new ApduConnectionException(
        		"No se pudo leer certificado de componente", e //$NON-NLS-1$
            );
		}

        // --- STAGE 2 ---
        // Permitimos que la tarjeta verifique la cadena de certificacion del controlador.
        // ---------------
        try {
            card.verifyIfdCertificateChain(pubConsts);
        }
        catch (final Exception e) {
            conn.close();
            throw new ApduConnectionException(
        		"Error al verificar la cadena de certificados del controlador", e //$NON-NLS-1$
    		);
        }

        // --- STAGE 3 ---
        // Autenticacion interna (el driver comprueba la tarjeta)
        // ---------------
        final byte[] randomIfd;
        try {
            randomIfd = cryptoHelper.generateRandomBytes(8);
        }
        catch (final IOException e1) {
            conn.close();
            throw new SecureChannelException(
        		"No se pudo generar el array de aleatorios", e1 //$NON-NLS-1$
    		);
        }

        final byte[] kicc;
        try {
            kicc = internalAuthentication(randomIfd, iccPublicKey);
        }
        catch (final Exception e) {
            conn.close();
            throw new ApduConnectionException(
        		"Error durante el proceso de autenticacion interna de la tarjeta", e //$NON-NLS-1$
    		);
        }

        // --- STAGE 4 ---
        // Autenticacion externa (la tarjeta comprueba el driver)
        // ---------------
        final byte[] randomIcc = card.getChallenge();
        final byte[] kifd;
        try {
            kifd = externalAuthentication(serial, randomIcc, iccPublicKey);
        }
        catch (final Exception e) {
            conn.close();
            throw new ApduConnectionException(
        		"Error durante el proceso de autenticacion externa de la tarjeta", e //$NON-NLS-1$
    		);
        }

        // --- STAGE 5 ---
        // Esta fase no pertenece al procedimiento de apertura del canal seguro (ya esta
        // establecido), sino a la obtencion de las claves necesarias para su control. Estas
        // son:
        // - Kenc: Clave TripleDES (TDES o DESEDE) para encriptar y desencriptar criptogramas.
        // - Kmac: Clave TripleDES (TDES o DESEDE) para calcular y verificar checksums.
        // - SSC: Contador de secuencia.
        // ---------------

        // Calculamos Kifdicc como el XOR de los valores Kifd y Kicc
        final byte[] kidficc = HexUtils.xor(kicc, kifd);
        try {
            kenc = generateKenc(kidficc);
        }
        catch (final IOException e) {
            conn.close();
            throw new ApduConnectionException(
        		"Error al generar la clave Kenc para el tratamiento del canal seguro", e //$NON-NLS-1$
            );
        }

        try {
            kmac = generateKmac(kidficc);
        }
        catch (final IOException e) {
            conn.close();
            throw new ApduConnectionException(
        		"Error al generar la clave Kmac para el tratamiento del canal seguro", e //$NON-NLS-1$
            );
        }

        ssc = generateSsc(randomIfd, randomIcc);

        openState = true;
    }

    /** Genera la clave <code>KENC</code> para encriptar y desencriptar criptogramas.
     * La clave de cifrado Kenc se obtiene como los 16 primeros octetos de la huella SHA-1 de la
     * concatenaci&oacute;n de <i>kifdicc</i> con el valor "00 00 00 01" (SECURE_CHANNEL_KENC_AUX).
     * @param kidficc XOR de los valores <code>Kifd</code> y <code>Kicc</code>.
     * @return Clave Triple-DES.
     * @throws IOException Cuando no puede generarse la clave. */
    private byte[] generateKenc(final byte[] kidficc) throws IOException {

    	final byte[] kidficcConcat = HexUtils.concatenateByteArrays(kidficc, SECURE_CHANNEL_KENC_AUX);

        final byte[] keyEnc = new byte[16];
        System.arraycopy(
    		cryptoHelper.digest(
				CryptoHelper.DigestAlgorithm.SHA1,
				kidficcConcat
			),
			0,
			keyEnc,
			0,
			keyEnc.length
		);

        return keyEnc;
    }

    /** Genera la clave <code>KMAC</code> para calcular y verificar <i>checksums</i>.
     * La clave para el c&aacute;lculo del MAC Kmac se obtiene como los 16 primeros octetos
     * de la huella SHA-1 de la concatenaci&oacute;n de <i>kifdicc</i> con el valor
     * "00 00 00 02" (SECURE_CHANNEL_KMAC_AUX).
     * @param kidficc XOR de los valores <code>Kifd</code> y <code>Kicc</code>.
     * @return Clave Triple-DES.
     * @throws IOException Cuando no puede generarse la clave. */
    private byte[] generateKmac(final byte[] kidficc) throws IOException {

        final byte[] kidficcConcat = HexUtils.concatenateByteArrays(kidficc, SECURE_CHANNEL_KMAC_AUX);

        final byte[] keyMac = new byte[16];
        System.arraycopy(
    		cryptoHelper.digest(
				CryptoHelper.DigestAlgorithm.SHA1,
				kidficcConcat
			),
    		0,
    		keyMac,
    		0,
    		keyMac.length
		);

        return keyMac;
    }

    /** Genera el contador de secuencia SSC a partir de los semillas aleatorias calculadas
     * en los procesos de autenticaci&oacute;n interna y externa.
     * El contador de secuencia SSC se obtiene concatenando los 4 octetos menos
     * significativos del desaf&iacute;o de la tarjeta (RND.ICC) con los 4 menos
     * significativos del desaf&iacute;o del terminal (RND.IFD)
     * @param randomIfd Aleatorio del desaf&iacute;o del terminal.
     * @param randomIcc Aleatorio del desaf&iacute;o de la tarjeta.
     * @return Contador de secuencia. */
    private static byte[] generateSsc(final byte[] randomIfd, final byte[] randomIcc) {

        final byte[] ssc = new byte[8];
        System.arraycopy(randomIcc, 4, ssc, 0, 4);
        System.arraycopy(randomIfd, 4, ssc, 4, 4);

        return ssc;
    }

    /** Solicita a la tarjeta un mensaje firmado de autenticaci&oacute;n interna.
     * @param card Tarjeta que se desea autenticar.
     * @param pubConsts Constantes p&uacute;blicas para la apertura de canal CWA-14890.
     * @param randomIfd Aleatorio del desaf&iacute;o del terminal.
     * @return Mensaje de autenticaci&oacute;n interna firmado por la tarjeta con su clave
     *         privada de componente.
     * @throws ApduConnectionException Si hay cualquier error durante el proceso. */
    public static byte[] internalAuthGetInternalAuthenticateMessage(final Cwa14890Card card,
    		                                                        final Cwa14890PublicConstants pubConsts,
    		                                                        final byte[] randomIfd) throws ApduConnectionException {
        // Seleccionamos la clave publica del certificado de Terminal a la vez
        // que aprovechamos para seleccionar la clave privada de componente para autenticar
        // este certificado de Terminal
        try {
            card.setKeysToAuthentication(
        		card.getChrCCvIfd(pubConsts),
        		card.getRefIccPrivateKey(pubConsts)
    		);
        }
        catch (final Exception e) {
            throw new SecureChannelException(
        		"Error durante el establecimiento de la clave " + //$NON-NLS-1$
    				"publica de Terminal y la privada de Componente para su autenticacion", e //$NON-NLS-1$
            );
        }

        // Iniciamos la autenticacion interna de la clave privada del certificado de componente
        return card.getInternalAuthenticateMessage(
    		randomIfd,
    		card.getChrCCvIfd(pubConsts)
		);

    }

    /** Valida un mensaje de autenticaci&oacute;n interna generado por una tarjeta.
     * @param chrCCvIfd CHR de la clave p&uacute;blica del certificado de terminal.
     * @param sigMinCiphered Mensaje de autenticaci&oacute;n generado por la tarjeta.
     * @param randomIfd Aleatorio del desaf&iacute;o del terminal.
     * @param ifdPrivateKey Clave privada del certificado de terminal.
     * @param ifdKeyLength Longitud, <u>en octetos</u>, de las claves RSA del certificado de
     *                     componente del terminal.
     * @param privConsts Constantes privadas para la apertura de canal CWA-14890.
     * @param pubConsts Constantes p&uacute;blicas para la apertura de canal CWA-14890.
     * @param iccPublicKey Clave p&uacute;blica del certificado de componente.
     * @param cryptoHelper Utilidad para la ejecuci&oacute;n de funciones criptogr&aacute;ficas.
     * @return Kicc para el cifrado de APDUs con esta tarjeta.
     * @throws IOException Si el mensaje no es v&aacute;lido o no se ha podido validar. */
    public static byte[] internalAuthValidateInternalAuthenticateMessage(final byte[] chrCCvIfd,
    		                                                             final byte[] sigMinCiphered,
    				                                                     final byte[] randomIfd,
    				                                                     final RSAPrivateKey ifdPrivateKey,
    				                                                     final int ifdKeyLength,
    			                                                         final Cwa14890PrivateConstants privConsts,
    	    		                                                     final Cwa14890PublicConstants pubConsts,
    			                                                         final RSAPublicKey iccPublicKey,
    			                                                         final CryptoHelper cryptoHelper) throws IOException {
        // -- Descifrado con la clave privada del Terminal
        final byte[] sigMin = cryptoHelper.rsaDecrypt(
    		sigMinCiphered,
    		ifdPrivateKey
		);

        // Este resultado es el resultado de la funcion SIGMIN que es minimo de SIG (los
        // datos sobre los que se ejecuto la funcion) y N.ICC-SIG.
        // Debemos averiguar cual de los dos es. Empezamos por comprobar si es SIG con lo que no
        // habra que deshacer la funcion y podemos descifrar directamente con la clave publica del
        // certificado de componente de la tarjeta.

        final byte[] sig = sigMin;
        byte[] desMsg = cryptoHelper.rsaEncrypt(sig, iccPublicKey);

        // Si el resultado no empieza por 0x6a [ISO_9796_2_PADDING_START] y termina por
        // 0xbc [ISO_9796_2_PADDING_END] (Valores definidos en la ISO 9796-2), se considera que
        // es erroneo y deberemos probar la segunda opcion.
        // Esto es, calcular N.ICC-SIG y volver a descifrar con la clave publica del
        // certificado de componente

        // Comprobamos que empiece por 0x6a [ISO_9796_2_PADDING_START] y termine con 0xbc [ISO_9796_2_PADDING_END]
        if (desMsg[0] != ISO_9796_2_PADDING_START || desMsg[desMsg.length - 1] != ISO_9796_2_PADDING_END) {

            // Calculamos N.ICC-SIG
            final byte[] sub = iccPublicKey.getModulus().subtract(new BigInteger(sigMin)).toByteArray();
            final byte[] niccMinusSig = new byte[ifdKeyLength];
            // Ignoramos los ceros de la izquierda
            if (sub.length > ifdKeyLength && sub[0] == (byte) 0x00) {
                System.arraycopy(sub, 1, niccMinusSig, 0, sub.length - 1);
            }
            else {
                System.arraycopy(sub, 0, niccMinusSig, 0, sub.length);
            }

            // Desciframos el mensaje con N.ICC-SIG
            desMsg = cryptoHelper.rsaDecrypt(niccMinusSig, iccPublicKey);

            // Si en esta ocasion no empieza por 0x6a [ISO_9796_2_PADDING_START] y termina con 0xbc [ISO_9796_2_PADDING_END],
            // la autenticacion interna habra fallado
            if (desMsg[0] != ISO_9796_2_PADDING_START || desMsg[desMsg.length - 1] != ISO_9796_2_PADDING_END) {
                throw new SecureChannelException(
            		"Error en la autenticacion interna para el establecimiento del canal seguro. " + //$NON-NLS-1$
                    "El mensaje descifrado es:\n" + HexUtils.hexify(desMsg, true) //$NON-NLS-1$
                );
            }
        }

        // -- Descomponemos el resultado anterior en sus partes:
        // Byte 0: Relleno segun ISO 9796-2 (DS scheme 1)
        // Bytes [PRND1] Bytes de relleno aleatorios para completar la longitud de la clave RSA
        // Bytes [Kicc] Semilla de 32 [KICC_LENGTH] bytes generada por la tarjeta para la derivacion de claves
        // Bytes [h: PRND1||Kicc||RND.IFD||SN.IFD] Hash SHA1
        // Ultimo Byte: Relleno segun ISO-9796-2 (option 1)
        final byte[] prnd1 = new byte[ifdKeyLength - KICC_LENGTH - CryptoHelper.DigestAlgorithm.SHA1.getDigestLength() - 2];
        System.arraycopy(
    		desMsg,
    		1,
    		prnd1,
    		0,
    		prnd1.length
		);

        final byte[] kicc = new byte[KICC_LENGTH];
        System.arraycopy(
    		desMsg,
    		prnd1.length + 1,
    		kicc,
    		0,
    		kicc.length
		);

        final byte[] hash = new byte[CryptoHelper.DigestAlgorithm.SHA1.getDigestLength()];
        System.arraycopy(
    		desMsg,
    		prnd1.length + kicc.length + 1,
    		hash,
    		0,
    		hash.length
		);

        // -- Calculamos el hash para la comprobacion de la autenticacion. Si coincide con el hash
        // extraido en el paso anterior, se confirma que se ha realizado correctamente

        // El hash se calcula a partir de la concatenacion de:
        // - PRND1: Extraido del paso anterior
        // - Kicc: Extraido del paso anterior
        // - RND.IFD: Numero aleatorio generado en pasos anteriores
        // - SN.IFD: CHR del IFD
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(prnd1);
        baos.write(kicc);
        baos.write(randomIfd);
        baos.write(chrCCvIfd);

        final byte[] calculatedHash = cryptoHelper.digest(
    		CryptoHelper.DigestAlgorithm.SHA1,
    		baos.toByteArray()
		);
        if (!HexUtils.arrayEquals(hash, calculatedHash)) {
            throw new SecureChannelException(
        		"Error en la comprobacion de la clave de autenticacion interna. Se obtuvo el hash '" + //$NON-NLS-1$
                     HexUtils.hexify(calculatedHash, false)
                         + "' cuando se esperaba: '" + HexUtils.hexify(hash, false) + "'" //$NON-NLS-1$ //$NON-NLS-2$
            );
        }

    	return kicc;
    }

    /** Lleva a cabo el proceso de autenticaci&oacute;n interna de la tarjeta mediante el
     * cual el controlador comprueba la tarjeta.
     * @param randomIfd Array de 8 bytes aleatorios (generados por el controlador, de forma externa a la tarjeta).
     * @param iccPublicKey Clave p&uacute;blica del certificado de componente.
     * @return Semilla de 32 [KICC_LENGTH] bits, generada por la tarjeta, para la derivaci&oacute;n de
     *         claves del canal seguro.
     * @throws SecureChannelException Cuando ocurre un error en el establecimiento de claves.
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con la tarjeta.
     * @throws IOException Cuando ocurre un error en el cifrado/descifrado de los mensajes. */
    private byte[] internalAuthentication(final byte[] randomIfd,
    		                              final RSAPublicKey iccPublicKey) throws SecureChannelException,
                                                                                  ApduConnectionException,
                                                                                  IOException {

        // Iniciamos la autenticacion interna de la clave privada del certificado de componente
        final byte[] sigMinCiphered = internalAuthGetInternalAuthenticateMessage(card, pubConsts, randomIfd);

        // Validamos el mensaje obtenido por la tarjeta y obtenemos la semilla de KICC generada por la tarjeta
        // para la derivacion de claves del canal seguro.
        return internalAuthValidateInternalAuthenticateMessage(
    		card.getChrCCvIfd(pubConsts),
    		sigMinCiphered,
    		randomIfd,
    		card.getIfdPrivateKey(privConsts),
    		card.getIfdKeyLength(pubConsts),
    		privConsts,
    		pubConsts,
    		iccPublicKey,
    		cryptoHelper
		);
    }

    /** Lleva a cabo el proceso de autenticaci&oacute;n externa mediante el cual la tarjeta
     * comprueba el controlador. La implementaci&oacute;n usa siempre SHA-1 para las huellas.
     * @param serial N&uacute;mero de serie de la tarjeta.
     * @param randomIcc Array de 8 octetos aleatorios generados por la tarjeta.
     * @param iccPublicKey Clava p&uacute;blica del certificado de componente.
     * @return Semilla de 32 [KIFD_LENGTH] bytes, generada por el Terminal, para la
     *         derivaci&oacute;n de claves del canal seguro.
     * @throws SecureChannelException Cuando ocurre un error en el establecimiento de claves.
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con
     *                                 la tarjeta.
     * @throws IOException Cuando ocurre un error en el cifrado o en el descifrado de los mensajes. */
    private byte[] externalAuthentication(final byte[] serial,
    		                              final byte[] randomIcc,
    		                              final RSAPublicKey iccPublicKey) throws IOException {

        // Construimos el campo de datos para el comando "External authentication" de acuerdo
        // al siguiente formato:
        // ----------------------
        // E[PK.ICC.AUT](SIGMIN)
        //
        // Donde:
        // SIGMIN = min (SIG, N.IFD - SIG)
        // y
        // SIG= DS[SK.IFD.AUT]
        // (
        // "6A" = relleno segun ISO 9796-2 (DS scheme 1)
        // PRND2 ="XX ... XX" bytes de relleno aleatorios generados por el terminal. La longitud
        // debe ser la necesaria para que la longitud desde "6A" hasta "BC" coincida con
        // la longitud de la clave RSA
        // KIFD = Semilla de 32 [KIFD_LENGTH] bytes, generada por el terminal, para la derivacion
    	// de claves del canal seguro.
        // h[PRND2 || KIFD || RND.ICC || SN.ICC ] = hash SHA1 que incluye los datos aportados por
        // la tarjeta y por el terminal
        // "BC" = relleno segun ISO 9796-2 (option 1)
        // )
        // ----------------------

        // Generamos PRN2 y Kifd como valores aleatorios de la longitud apropiada
        final byte[] prnd2 = cryptoHelper.generateRandomBytes(
    		card.getIfdKeyLength(pubConsts) - 2 - KIFD_LENGTH - CryptoHelper.DigestAlgorithm.SHA1.getDigestLength()
		);
        final byte[] kifd = cryptoHelper.generateRandomBytes(KIFD_LENGTH);

        // Calculamos el hash que incorporaremos al mensaje a partir de los siguientes
        // datos concatenados:
        // - PRND2
        // - Kifd
        // - RND.ICC
        // - SN.ICC (Numero de serie del Chip, extraido del Chip Info). Debe tener 8 bytes.
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(prnd2);
        baos.write(kifd);
        baos.write(randomIcc);
        baos.write(serial);

        final byte[] hash = cryptoHelper.digest(
    		CryptoHelper.DigestAlgorithm.SHA1,
    		baos.toByteArray()
		);

        // Construimos el mensaje para el desafio a la tarjeta. Este estara compuesto por:
        // Byte 0: 0x6a [ISO_9796_2_PADDING_START] - Relleno segun ISO 9796-2 (DS scheme 1)
        // Bytes [PRND2] Bytes de relleno aleatorios para completar la longitud de la clave RSA
        // Bytes [Kifd] Semilla de 32 [KICC_LENGTH] bytes generada por la tarjeta para la derivacion de claves
        // Bytes [h: PRND2||Kifd||RND.ICC||SN.ICC] Hash SHA1
        // Ultimo Byte: 0xbc [ISO_9796_2_PADDING_END] - Relleno segun ISO-9796-2 (option 1)
        baos.reset();
        baos.write(ISO_9796_2_PADDING_START);
        baos.write(prnd2);
        baos.write(kifd);
        baos.write(hash);
        baos.write(ISO_9796_2_PADDING_END);

        final byte[] msg = baos.toByteArray();
        final RSAPrivateKey ifdPrivateKey = card.getIfdPrivateKey(privConsts);

        // Ciframos con la clave privada del terminal
        final byte[] sig = cryptoHelper.rsaDecrypt(msg, ifdPrivateKey);

        // Calculamos N.IFD-SIG para obtener SIGMIN (el menor de SIG y N.IFD-SIG)
        final BigInteger biSig = new BigInteger(1, sig);
        final byte[] sigMin = ifdPrivateKey.getModulus().subtract(biSig).min(biSig).toByteArray();

        // Ciframos con la clave publica de componente de la tarjeta
        final byte[] extAuthenticationData = cryptoHelper.rsaEncrypt(sigMin, iccPublicKey);

        final boolean valid = card.externalAuthentication(extAuthenticationData);
        if (!valid) {
            throw new SecureChannelException(
        		"Error durante la autenticacion externa del canal seguro" //$NON-NLS-1$
            );
        }

        return kifd;
    }

    /** Obtiene el n&uacute;mero de serie de la tarjeta en un array de 8 octetos, completando
     * con ceros a la izquierda si es necesario.
     * @return N&uacute;mero de serie en formato de 8 bytes.
     * @throws ApduConnectionException Cuando ocurre un error en la comunicaci&oacute;n con
     *         la tarjeta. */
    private byte[] getPaddedSerial() throws ApduConnectionException {
        // Completamos el numero de serie (SN.ICC) para que tenga 8 bytes
        final byte[] serial = card.getSerialNumber();
        byte[] paddedSerial = serial;
        if (paddedSerial.length < 8) {
            paddedSerial = new byte[8];
            int i;
            for (i = 0; i < 8 - serial.length; i++) {
                paddedSerial[i] = (byte) 0x00;
            }
            System.arraycopy(serial, 0, paddedSerial, i, serial.length);
        }
        return paddedSerial;
    }

    @Override
    public void close() throws ApduConnectionException {
    	if (openState) {
    		subConnection.close();
    		openState = false;
    	}
    }

    @Override
    public ResponseApdu transmit(final CommandApdu command) throws ApduConnectionException {

        final CommandApdu protectedApdu;
        try {
        	ssc = increment(ssc);
            protectedApdu = apduEncrypter.protectAPDU(
        		command,
        		kenc,
        		kmac,
        		ssc,
        		cryptoHelper
    		);
        }
        catch (final IOException e) {
            throw new SecureChannelException(
        		"Error en la encriptacion de la APDU para su envio por el canal seguro", e //$NON-NLS-1$
            );
        }

        final ResponseApdu responseApdu = subConnection.transmit(protectedApdu);
        if (INVALID_CRYPTO_CHECKSUM.equals(responseApdu.getStatusWord())) {
        	throw new InvalidCryptographicChecksumException();
        }

        // Desencriptamos la respuesta
        try {
        	ssc = increment(ssc);
        	final ResponseApdu decipherApdu = apduEncrypter.decryptResponseApdu(
    			responseApdu,
    			kenc,
    			ssc,
    			kmac,
    			cryptoHelper
			);

            // Si la APDU descifrada indicase que no se indico bien el tamano de la respuesta, volveriamos
            // a enviar el comando indicando la longitud correcta
            if (decipherApdu.getStatusWord().getMsb() == MSB_INCORRECT_LE) {
            	command.setLe(decipherApdu.getStatusWord().getLsb());
            	return transmit(command);
            }
			if (decipherApdu.getStatusWord().getMsb() == MSB_INCORRECT_LE_PACE) {
            	command.setLe(command.getLe().intValue()-1);
            	return transmit(command);
            }
            return decipherApdu;
        }
        catch (final Exception e) {
            throw new ApduConnectionException(
        		"Error en la desencriptacion de la APDU de respuesta recibida por el canal seguro", e //$NON-NLS-1$
            );
		}
    }

    @Override
    public byte[] reset() throws ApduConnectionException {

        openState = false;

        // Reseteamos para obtener el ATR de la tarjeta
        final byte[] atr = subConnection.reset();

        // Volvemos a abrir la conexion
        open();

        return atr;
    }

    @Override
    public void addCardConnectionListener(final CardConnectionListener ccl) {
        subConnection.addCardConnectionListener(ccl);
    }

    @Override
    public void removeCardConnectionListener(final CardConnectionListener ccl) {
        subConnection.removeCardConnectionListener(ccl);
    }

    @Override
    public long[] getTerminals(final boolean onlyWithCardPresent) throws ApduConnectionException {
        return subConnection.getTerminals(onlyWithCardPresent);
    }

    @Override
    public String getTerminalInfo(final int terminal) throws ApduConnectionException {
        return subConnection.getTerminalInfo(terminal);
    }

    @Override
    public void setTerminal(final int t) throws ApduConnectionException {
        subConnection.setTerminal(t);
    }

    @Override
    public boolean isOpen() {
        return openState && subConnection.isOpen();
    }

    /** Calcula y devuelve el valor entregado m&aacute;s 1.
     * @param data Datos a incrementar.
     * @return Valor incrementado. */
    private static byte[] increment(final byte[] data) {

        final BigInteger bi = new BigInteger(1, data).add(BigInteger.ONE);

        final byte[] biArray = bi.toByteArray();
        if (biArray.length > 8) {
        	final byte[] incrementedValue = new byte[8];
        	System.arraycopy(
    			biArray,
    			biArray.length - incrementedValue.length,
    			incrementedValue,
    			0,
    			incrementedValue.length
			);
        	return incrementedValue;
        }
		if (biArray.length < 8) {
        	final byte[] incrementedValue = new byte[8];
        	System.arraycopy(
    			biArray,
    			0,
    			incrementedValue,
    			incrementedValue.length - biArray.length,
    			biArray.length
			);
        	return incrementedValue;
        }
        return biArray;
    }

    @Override
	public ApduConnection getSubConnection() {
    	return subConnection;
    }

	@Override
	public void setProtocol(final ApduConnectionProtocol p) {
		if (subConnection != null) {
			subConnection.setProtocol(p);
		}
	}

	@Override
	public byte[] getKenc() {
		return kenc;
	}

	@Override
	public byte[] getKmac() {
		return kmac;
	}

	@Override
	public byte[] getSsc() {
		return ssc;
	}

}