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
package es.gob.jmulticard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.card.icao.IcaoException;
import es.gob.jmulticard.card.icao.WirelessInitializer;
import es.gob.jmulticard.de.tsenger.androsmex.iso7816.SecureMessaging;

/** Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre
 * JSE/JME/Dalvik.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public abstract class CryptoHelper {

	/** Tipos de relleno para cifrados. */
	public enum Padding {

		/** Sin relleno.  */
		NOPADDING("NOPADDING"), //$NON-NLS-1$

		/** Relleno ISO7816-4. */
		ISO7816_4PADDING("ISO7816-4Padding"); //$NON-NLS-1$

		private final String algName;

		Padding(final String alg) {
			this.algName = alg;
		}

		@Override
		public String toString() {
			return this.algName;
		}
	}

	/** Tipos de manejo de bbloques para cifrado. */
	public enum BlockMode {

		/** Cipher Block Chaining. */
		CBC,

		/** Electronic CodeBook. */
		ECB
	}

	/** Nombres de curva el&iacute;ptica. */
	public enum EcCurve {

		/** BrainpoolP256r1. */
		BRAINPOOL_P256_R1("brainpoolp256r1"); //$NON-NLS-1$

		private final String name;
		EcCurve(final String n) {
			this.name = n;
		}

		@Override
		public String toString() {
			return this.name;
		}
	}

	/** Algoritmo de huella digital. */
	public enum DigestAlgorithm {

		/** SHA-1. */
		SHA1("SHA1"), //$NON-NLS-1$

		/** SHA-256. */
		SHA256("SHA-256"), //$NON-NLS-1$

		/** SHA-384. */
		SHA384("SHA-384"), //$NON-NLS-1$

		/** SHA-512. */
		SHA512("SHA-512"); //$NON-NLS-1$

		/** Nombre del algoritmo de huella digital. */
		private final String name;

		/** Construye el algoritmo de huella digital.
		 * @param n Nombre del algoritmo. */
		DigestAlgorithm(final String n) {
			this.name = n;
		}

		@Override
		public String toString() {
			return this.name;
		}
	}

	private static final byte PKCS1_BLOCK_TYPE = (byte) 0x01;
	private static final byte PKCS1_FILL = (byte) 0xff;
	private static final byte PKCS1_DELIMIT = (byte) 0x00;

	/** A&ntilde;ade relleno PKCS#1 para operaciones con clave privada.
	 * @param inByteArray Datos a los que se quiere a&ntilde;adir relleno PKCS#1.
	 * @param keySize Tama&ntilde;o de la clave privada que operar&aacute; posteriormente con estos datos con
	 *                relleno.
	 * @return Datos con el relleno PKCS#1 a&ntilde;adido.
	 * @throws IOException En caso de error el el tratamiento de datos. */
	public final static byte[] addPkcs1PaddingForPrivateKeyOperation(final byte[] inByteArray,
			                                                         final int keySize) throws IOException {
		if (inByteArray == null) {
			throw new IllegalArgumentException("Los datos de entrada no pueden ser nulos"); //$NON-NLS-1$
		}
		final int len = keySize / 8;
		if (inByteArray.length > len - 3) {
			throw new IllegalArgumentException(
				"Los datos son demasiado grandes para el valor de clave indicado: " + inByteArray.length + " > " + len + "-3" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
		}
		final ByteArrayOutputStream baos = new ByteArrayOutputStream(len);
		baos.write(PKCS1_DELIMIT);    // Delimitador :   00
		baos.write(PKCS1_BLOCK_TYPE); // Tipo de bloque: 01
		while (baos.size() < len - (1 + inByteArray.length)) { // Se rellena hasta dejar sitio justo para un delimitador y los datos
			baos.write(PKCS1_FILL);
		}
		baos.write(PKCS1_DELIMIT);    // Delimitador :   00
		baos.write(inByteArray);               // Datos

		return baos.toByteArray();
	}

    /** Realiza una huella digital de los datos proporcionados.
     * @param algorithm Algoritmo de huella digital que debe utilizarse.
     * @param data Datos de entrada.
     * @return Huella digital de los datos.
     * @throws IOException Si ocurre alg&uacute;n problema generando la huella
     *                     digital. */
    public abstract byte[] digest(DigestAlgorithm algorithm, byte[] data) throws IOException;

    /** Encripta datos mediante Triple DES (modo CBC sin relleno) y con una
     * semilla (IV) de 8 bytes establecidos a cero. Si se le indica una clave de 24 bytes,
     * la utilizar&aacute;a tal cual. Si se le indica una clave de 16 bytes,
     * duplicar&aacute; los 8 primeros y los agregar&aacute; al final para
     * obtener una de 24.
     * @param data Datos a encriptar.
     * @param key Clave 3DES de cifrado.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         encriptado. */
    public abstract byte[] desedeEncrypt(byte[] data, byte[] key) throws IOException;

    /** Desencripta datos mediante Triple DES (modo CBC sin relleno) y con una
     * semilla (IV) de 8 bytes establecidos a cero. Si se le indica una clave de 24 bytes,
     * la utilizar&aacute;a tal cual. Si se le indica una clave de 16 bytes,
     * duplicar&aacute; los 8 primeros y los agregar&aacute; al final para obtener una de 24.
     * @param data Datos a desencriptar.
     * @param key Clave 3DES de descifrado.
     * @return Datos descifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         desencriptado. */
    public abstract byte[] desedeDecrypt(byte[] data, byte[] key) throws IOException;

    /** Encripta datos mediante DES (modo ECB sin relleno).
     * @param data Datos a encriptar.
     * @param key Clave DES de cifrado.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         encriptado. */
    public abstract byte[] desEncrypt(byte[] data, byte[] key) throws IOException;

    /** Desencripta datos mediante DES (modo ECB sin relleno).
     * @param data Datos a desencriptar.
     * @param key Clave DES de descifrado.
     * @return Datos descifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         desencriptado. */
    public abstract byte[] desDecrypt(byte[] data, byte[] key) throws IOException;

    /** Desencripta datos mediante AES.
     * @param data Datos a encriptar.
     * @param iv Vector de inicializaci&oacute;n. Si se proporciona <code>null</code> se usar&aacute;
     *           un vector con valores aleatorios.
     * @param key Clave AES de cifrado.
     * @param blockMode Modo de gesti&oacute;n de bloques.
     * @param padding Relleno a usar en los datos de entrada.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *                     encriptado. */
    public abstract byte[] aesDecrypt(byte[] data,
    		                          byte[] iv,
    		                          byte[] key,
    		                          BlockMode blockMode,
    		                          Padding padding) throws IOException;

    /** Encripta datos mediante AES.
     * @param data Datos a encriptar.
     * @param iv Vector de inicializaci&oacute;n. Si se proporciona <code>null</code>
     *           se usar&aacute; un vector con valores aleatorios.
     * @param key Clave AES de cifrado.
     * @param blockMode Modo de gesti&oacute;n de bloques.
     * @param padding Relleno a usar en los datos de entrada.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *                     encriptado. */
    public abstract byte[] aesEncrypt(byte[] data,
    		                          byte[] iv,
    		                          byte[] key,
    		                          BlockMode blockMode,
    		                          Padding padding) throws IOException;

    /** Desencripta datos mediante RSA.
     * @param cipheredData Datos a desencriptar.
     * @param key Clava RSA de descifrado.
     * @return Datos descifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *                     desencriptado. */
    public abstract byte[] rsaDecrypt(byte[] cipheredData, RSAKey key) throws IOException;

    /** Encripta datos mediante RSA.
     * @param data Datos a encriptar.
     * @param key Clava RSA de cifrado.
     * @return Datos encriptados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *                     encriptado. */
    public abstract byte[] rsaEncrypt(byte[] data, RSAKey key) throws IOException;

    /** Genera contenido aleatorio en un array de bytes.
     * @param numBytes N&uacute;mero de bytes aleatorios que generar.
     * @return Array de bytes aleatorios.
     * @throws IOException Si ocurre alg&uacute;n problema durante la
     *         generaci&oacute;n del aleatorio. */
    public abstract byte[] generateRandomBytes(int numBytes) throws IOException;

	/** Genera un par de claves de tipo curva el&iacute;ptica.
	 * @param curveName Tipo de curva el&iacute;ptica a utilizar.
	 * @return Par de claves generadas.
	 * @throws NoSuchAlgorithmException Si el sistema no soporta la generaci&oacute;n de
	 *                                  curvas el&iacute;pticas.
	 * @throws InvalidAlgorithmParameterException Si el sistema no soporta el tipo de curva
	 *                                            el&iacute;ptica indicada. */
	public abstract KeyPair generateEcKeyPair(EcCurve curveName) throws NoSuchAlgorithmException,
	                                                                    InvalidAlgorithmParameterException;

	/** Realiza un CMAC con AES.
	 * @param data Datos (deben estar ya con el relleno adecuado).
	 * @param key Clave AES.
	 * @return CMAC.
	 * @throws NoSuchAlgorithmException Si no se encuentra un proveedor que permita realizar
	 *                                  CMAC con AES.
	 * @throws InvalidKeyException Si la clave proporcionada no es una clave AES v&aacute;lida. */
	public abstract byte[] doAesCmac(byte[] data, byte[] key) throws NoSuchAlgorithmException,
	                                                                 InvalidKeyException;

	/** Realiza un acuerdo de claves <i>Diffie Hellman</i> con algoritmo de curva el&iacute;ptica.
	 * @param privateKey Clave privada.
	 * @param publicKey Clave p&uacute;blica.
	 * @param curveName Nombre de la curva a usar.
	 * @return Resultado de acuerdo de claves.
	 * @throws NoSuchAlgorithmException Si no hay ning&uacute;n proveedor en el sistema que soporte el
	 *                                  algoritmo <i>ECDH</i>.
	 * @throws InvalidKeySpecException Si alguna de las claves es inv&aacute;lida.
	 * @throws InvalidKeyException Si alguna de las claves es inv&aacute;lida. */
	public abstract byte[] doEcDh(Key privateKey,
			                      byte[] publicKey,
			                      EcCurve curveName) throws NoSuchAlgorithmException,
	                                                        InvalidKeyException,
	                                                        InvalidKeySpecException;

	/** Obtiene un punto en una curva el&iacute;ptica.
	 * @param nonceS Aleatorio de un solo uso.
	 * @param sharedSecretH Secreto compartido.
	 * @param curveName Nombre de la curva.
	 * @return Punto encapsulado. */
	public abstract AlgorithmParameterSpec getEcPoint(byte[] nonceS,
			                                          byte[] sharedSecretH,
			                                          EcCurve curveName);

	/** Obtiene el contenido firmado de una firma CMS/OPKCS#7.
	 * @param signedDataBytes Firma CMS/OPKCS#7.
	 * @return Contenido firmado de una firma CMS/OPKCS#7.
	 * @throws IOException Si los datos proporcionados no son una firma CMS/OPKCS#7 bien formada. */
	public abstract byte[] getCmsSignatureSignedContent(byte[] signedDataBytes) throws IOException;

	/** Valida una firma CMS/OPKCS#7. No comprueba la validez de los certificados de firma.
	 * @param signedDataBytes Firma CMS/OPKCS#7.
	 * @return Cadena de certificados del firmante (para validaci&oacute;n externa).
	 * @throws SignatureException Si la firma es inv&aacute;lida o est&aacute; mal formada.
	 * @throws IOException Si los datos proporcionados no son una firma CMS/OPKCS#7 bien formada.
	 * @throws CertificateException Si hay problemas relacionados con los certificados de firma. */
	public abstract X509Certificate[] validateCmsSignature(byte[] signedDataBytes) throws SignatureException,
	                                                                                      IOException,
	                                                                                      CertificateException;

	/** Obtiene las utilidades para el establecimiento de un canal PACE
	 * (Password Authenticated Connection Establishment).
	 * @return Utilidades para el establecimiento de un canal PACE */
	public abstract PaceChannelHelper getPaceChannelHelper();

	/** Utilidades para el establecimiento de un canal <a href="https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html">PACE</a>
	 * (Password Authenticated Connection Establishment).
	 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
	public abstract static class PaceChannelHelper {

		/** <code>Logger</code>. */
		protected static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

		/** Relleno para el CAN o la MRZ. */
		protected static final byte[] CAN_MRZ_PADDING = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03
		};

		/** Relleno para el <i>kenc</i>. */
		protected static final byte[] KENC_PADDING = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
		};

		/** Relleno para el <i>kmac</i>. */
		protected static final byte[] KMAC_PADDING = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02
		};

		/** Relleno para el MAC. */
		protected static final byte[] MAC_PADDING = {
			(byte) 0x7F, (byte) 0x49, (byte) 0x4F, (byte) 0x06
		};

		/** Relleno para el MAC2. */
		protected static final byte[] MAC2_PADDING = {
			(byte) 0x86, (byte) 0x41, (byte) 0x04
		};

		/** Etiqueta de los datos de autenticaci&oacute;n din&aacute;mica dentro de un
		 * comando <i>General Autenticate</i>. */
		protected static final byte TAG_DYNAMIC_AUTHENTICATION_DATA = (byte) 0x7C;

		/** Etiqueta del segundo TLV de los datos de autenticaci&oacute;n din&aacute;mica
		 * dentro de un comando <i>General Autenticate</i>. */
		protected static final byte TAG_GEN_AUTH_2 = (byte) 0x81;

		/** Etiqueta del tercer TLV de los datos de autenticaci&oacute;n din&aacute;mica
		 * dentro de un comando <i>General Autenticate</i>. */
		protected static final byte TAG_GEN_AUTH_3 = (byte) 0x83;

		/** Etiqueta del cuarto TLV de los datos de autenticaci&oacute;n din&aacute;mica
		 * dentro de un comando <i>General Autenticate</i>. */
		protected static final byte TAG_GEN_AUTH_4 = (byte) 0x85;

		/** Utilidad para operaciones criptogr&aacute;ficas. */
		protected transient final CryptoHelper cryptoHelper;

		/** Constructor
		 * @param ch Utilidad para operaciones criptogr&aacute;ficas. */
		public PaceChannelHelper(final CryptoHelper ch) {
			this.cryptoHelper = ch;
		}

		/** Abre un canal PACE.
		 * @param cla Clase de APDU para los comandos de establecimiento de canal.
		 * @param pi Valor de inicializaci&oacute;n del canal. Puede ser un CAN
		 *           (<i>Card Access Number</i>) o una MRZ (<i>Machine Readable Zone</i>).
		 * @param conn Conexi&oacute;n hacia la tarjeta inteligente.
		 * @return SecureMessaging Objeto para el env&iacute;o de mensajes seguros a trav&eacute;s de canal PACE.
		 * @throws ApduConnectionException Si hay problemas de conexi&oacute;n con la tarjeta.
		 * @throws IcaoException Si hay problemas en la apertura del canal. */
		public abstract SecureMessaging openPaceChannel(byte cla,
				                                        WirelessInitializer pi,
				                                        ApduConnection conn) throws ApduConnectionException,
				                                                                    IcaoException;

		/** Obtiene la representaci&oacute;n de un <code>BigInteger</code> como un
		 * array de octetos.
		 * @param bi <code>BigInteger</code> a convertir.
		 * @return Array de octetos que representa el <code>BigInteger</code> de entrada. */
		protected static byte[] bigIntToByteArray(final BigInteger bi) {
			final byte[] temp = bi.toByteArray();
			if (temp[0] == 0) {
				final byte[] returnbytes = new byte[temp.length - 1];
				System.arraycopy(temp, 1, returnbytes, 0, returnbytes.length);
				return returnbytes;
			}
			return temp;
		}

		/** Obtiene la representaci&oacute;n de una clave de curva el&iacute;ptica como un
		 * array de octetos.
		 * @param key Clave de curva el&iacute;ptica de entrada.
		 * @return Array de octetos que representa la clave de curva el&iacute;ptica de entrada.
		 * @throws TlvException Si hay problemas desempaquetando la clave como array de octetos. */
		protected static byte[] unwrapEcKey(final byte[] key) throws TlvException {
			return new Tlv(new Tlv(key).getValue()).getValue();
		}
	}

}
