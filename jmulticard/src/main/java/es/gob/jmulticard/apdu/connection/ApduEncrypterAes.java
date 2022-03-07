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

package es.gob.jmulticard.apdu.connection;

import java.io.IOException;
import java.util.logging.Logger;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.CryptoHelper.BlockMode;
import es.gob.jmulticard.CryptoHelper.Padding;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;

/** Operaciones de cifrado AES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Sergio Mart&iacute;nez Rico. */
public final class ApduEncrypterAes extends ApduEncrypter {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	/** Constructor de la clase para operaciones de cifrado AES. */
	public ApduEncrypterAes() {
		LOGGER.info(
			"Se usara AES y CMAC para el cifrado de mensajes en el canal seguro" //$NON-NLS-1$
		);
		this.paddingLength = 16;
	}

	@Override
	protected byte[] encryptData(final byte[] data,
			                     final byte[] key,
			                     final byte[] ssc,
			                     final CryptoHelper cryptoHelper) throws IOException {
		if (ssc == null) {
			throw new IllegalArgumentException(
				"El contador de secuencia no puede ser nulo en esta version de CWA-14890" //$NON-NLS-1$
			);
		}
		// El vector de inicializacion del cifrado AES se calcula cifrando el SSC igualmente en AES con la misma clave y un vector
		// de inicializacion todo a 0x00
		final byte[] iv = cryptoHelper.aesEncrypt(
			ssc,
			new byte[0], // Vector de inicializacion vacio
			key,
			BlockMode.CBC,
			Padding.NOPADDING // Sin relleno
		);
		return cryptoHelper.aesEncrypt(
			data,
			iv,
			key,
			BlockMode.CBC,
			Padding.NOPADDING // Sin relleno
		);
	}

	@Override
	protected byte[] generateMac(final byte[] dataPadded,
			                     final byte[] ssc,
			                     final byte[] kMac,
			                     final CryptoHelper cryptoHelper) throws IOException {
		final byte[] mac;
		try {
			mac = cryptoHelper.doAesCmac(HexUtils.concatenateByteArrays(ssc, dataPadded), kMac);
		}
		catch (final Exception e) {
			throw new IOException(
				"Error creando la CMAC de la APDU cifrada: " + e, e //$NON-NLS-1$
			);
		}
		final byte[] ret = new byte[8];
		System.arraycopy(mac, 0, ret, 0, 8);
		return ret;
	}

	@Override
	public ResponseApdu decryptResponseApdu(final ResponseApdu responseApdu,
			                                final byte[] keyCipher,
			                                final byte[] ssc,
			                                final byte[] kMac,
			                                final CryptoHelper cryptoHelper) {
		return null;
	}

}
