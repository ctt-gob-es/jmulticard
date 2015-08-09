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
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/** Funcionalidades criptogr&aacute;ficas de utilidad que pueden variar entre
 * JSE/JME/Dalvik.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public abstract class CryptoHelper {

	/** Nombre de curva ek&iacute;ptica. */
	public enum EcCurve {

		/** BrainpoolP256r1. */
		BRAINPOOL_P256_R1("brainpoolP256R1"); //$NON-NLS-1$

		private final String name;
		private EcCurve(final String n) {
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

		private final String name;
		private DigestAlgorithm(final String n) {
			this.name = n;
		}

		@Override
		public String toString() {
			return this.name;
		}
	}

	private static final int PKCS1_LEN_1024 = 128;
	private static final int PKCS1_LEN_2048 = 256;
	private static final byte PKCS1_BLOCK_TYPE = (byte) 0x01;
	private static final byte PKCS1_FILL = (byte) 0xff;
	private static final byte PKCS1_DELIMIT = (byte) 0x00;

	/** A&ntilde;ade relleno PKCS#1 para operaciones con clave privada.
	 * @param in Datos a los que se quiere a&ntilde;adir relleno PKCS#1.
	 * @param keySize Tama&ntilde;o de la clave privada que operar&aacute; posteriormente con estos datos con relleno.
	 * @return Datos con el relleno PKCS#1 a&ntilde;adido.
	 * @throws IOException En caso de error el el tratamiento de datos. */
	public final static byte[] addPkcs1PaddingForPrivateKeyOperation(final byte[] in, final int keySize) throws IOException {
		if (in == null) {
			throw new IllegalArgumentException("Los datos de entrada no pueden ser nulos"); //$NON-NLS-1$
		}
		if (keySize != 1024 && keySize != 2048) {
			throw new IllegalArgumentException("Solo se soportan claves de 1024 o 2048 bits, y se ha indicado " + keySize); //$NON-NLS-1$
		}
		final int len = keySize == 1024 ? PKCS1_LEN_1024 : PKCS1_LEN_2048;
		if (in.length > len - 3) {
			throw new IllegalArgumentException(
				"Los datos son demasiado grandes para el valor de clave indicado: " + in.length + " > " + len + "-3" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
		}
		final ByteArrayOutputStream baos = new ByteArrayOutputStream(len);
		baos.write(PKCS1_DELIMIT);    // Delimitador :   00
		baos.write(PKCS1_BLOCK_TYPE); // Tipo de bloque: 01
		while (baos.size() < len - (1 + in.length)) { // Se rellena hasta dejar sitio justo para un delimitador y los datos
			baos.write(PKCS1_FILL);
		}
		baos.write(PKCS1_DELIMIT);    // Delimitador :   00
		baos.write(in);               // Datos

		return baos.toByteArray();
	}

    /** Realiza una huella digital de los datos proporcionados.
     * @param algorithm Algoritmo de huella digital que debe utilizarse.
     * @param data Datos de entrada.
     * @return Huella digital de los datos.
     * @throws IOException Si ocurre alg&uacute;n problema generando la huella
     *         digital. */
    public abstract byte[] digest(final DigestAlgorithm algorithm, final byte[] data) throws IOException;

    /** Encripta datos mediante Triple DES (modo CBC sin relleno) y con un
     * salto de (IV) de 8 bytes a cero. Si se le indica una clave de 24 bytes,
     * la utilizar&aacute;a tal cual. Si se le indica una clave de 16 bytes,
     * duplicar&aacute; los 8 primeros y los agregar&aacute; al final para
     * obtener una de 24.
     * @param data Datos a encriptar.
     * @param key Clave 3DES de cifrado.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         encriptado. */
    public abstract byte[] desedeEncrypt(final byte[] data, final byte[] key) throws IOException;

    /** Desencripta datos mediante Triple DES (modo CBC sin relleno) y con un
     * salto de (IV) de 8 bytes a cero. Si se le indica una clave de 24 bytes,
     * la utilizar&aacute;a tal cual. Si se le indica una clave de 16 bytes,
     * duplicar&aacute; los 8 primeros y los agregar&aacute; al final para obtener una de 24.
     * @param data Datos a desencriptar.
     * @param key Clave 3DES de descifrado.
     * @return Datos descifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         desencriptado. */
    public abstract byte[] desedeDecrypt(final byte[] data, final byte[] key) throws IOException;

    /** Encripta datos mediante DES (modo ECB sin relleno).
     * @param data Datos a encriptar.
     * @param key Clave DES de cifrado.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         encriptado. */
    public abstract byte[] desEncrypt(final byte[] data, final byte[] key) throws IOException;

    /** Desencripta datos mediante DES (modo ECB sin relleno).
     * @param data Datos a desencriptar.
     * @param key Clave DES de descifrado.
     * @return Datos descifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         desencriptado. */
    public abstract byte[] desDecrypt(final byte[] data, final byte[] key) throws IOException;

    /** Desencripta datos mediante AES (modo CBC sin relleno).
     * @param data Datos a encriptar.
     * @param key Clave AES de cifrado.
     * @return Datos cifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         encriptado. */
    public abstract byte[] aesDecrypt(final byte[] data, final byte[] key) throws IOException;

    /** Desencripta datos mediante RSA.
     * @param cipheredData Datos a desencriptar.
     * @param key Clava RSA de descifrado.
     * @return Datos descifrados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         desencriptado. */
    public abstract byte[] rsaDecrypt(final byte[] cipheredData, final Key key) throws IOException;

    /** Encripta datos mediante RSA.
     * @param data Datos a encriptar.
     * @param key Clava RSA de cifrado.
     * @return Datos encriptados.
     * @throws IOException Si ocurre alg&uacute;n problema durante el
     *         encriptado. */
    public abstract byte[] rsaEncrypt(final byte[] data, final Key key) throws IOException;

    /** Genera un certificado del tipo indicado a partir de su codificaci&oacute;n.
     * @param encode Codificaci&oacute;n del certificado.
     * @return Certificado generado.
     * @throws CertificateException Si ocurre alg&uacute;n problema durante la
     *         generaci&oacute;n. */
    public abstract Certificate generateCertificate(byte[] encode) throws CertificateException;

    /** Genera un aleatorio contenido en un array de bytes.
     * @param numBytes N&uacute;mero de bytes aleatorios que generar.
     * @return Array de bytes aleatorios.
     * @throws IOException Si ocurre alg&uacute;n problema durante la
     *         generaci&oacute;n del aleatorio. */
    public abstract byte[] generateRandomBytes(int numBytes) throws IOException;

	/** Genera un par de claves de tipo curva el&iacute;ptica.
	 * @param curveName Tipo de curva el&iacute;ptica a utilizar.
	 * @return Par de claves generadas.
	 * @throws NoSuchAlgorithmException Si el sistema no soporta la generaci&oacute;n de curvas el&iacute;pticas.
	 * @throws InvalidAlgorithmParameterException Si el sistema no soporta el tipo de curva el&iacute;ptica indicada. */
	public abstract KeyPair generateEcKeyPair(final EcCurve curveName) throws NoSuchAlgorithmException,
	                                                                          InvalidAlgorithmParameterException;
}
