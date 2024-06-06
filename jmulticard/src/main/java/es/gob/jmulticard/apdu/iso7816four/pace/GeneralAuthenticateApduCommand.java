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
package es.gob.jmulticard.apdu.iso7816four.pace;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.asn1.Tlv;

/** APDU de autenticaci&oacute;n general (<i>General Authenticate</i>).
 * El comando <i>General Authenticate</i> se emplea para el establecimiento del canal PACE.
 * Tambi&eacute;n es empleado para establecer el canal PRO con curvas el&iacute;pticas seg&uacute;n
 * lo definido en el apartado 3.6 de la norma EN419212-3 y para establecer el paso
 * <i>Chip Authentication</i> del canal EAC seg&uacute;n lo definido en el apartado 3.7 de la norma EN419212-3.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class GeneralAuthenticateApduCommand extends CommandApdu {

	/** Octeto de instrucci&oacute;n de la APDU. */
	private static final byte INS_GENERAL_AUTHENTICATE = (byte) 0x86;

	/** Valor para indicar que no se dispone de informaci&oacute;n al respecto. */
	private static final byte NO_INFORMATION_GIVEN = (byte) 0x00;

	/** Crea una APDU de autenticaci&oacute;n general.
	 * @param cla Clase (CLA) de la APDU.
	 * @param data Datos de autenticaci&oacute;n. */
	public GeneralAuthenticateApduCommand(final byte cla, final GeneralAuthenticateData data) {
		super(
			cla,                      // CLA
			INS_GENERAL_AUTHENTICATE, // INS
			NO_INFORMATION_GIVEN,	  // P1
			NO_INFORMATION_GIVEN,     // P2
			data.getBytes(),	      // Data
			null                      // Le
		);
	}

	/** Datos para la APDU <i>General Authenticate</i>. */
	public abstract static class GeneralAuthenticateData {

		/** Etiqueta de los datos de autenticaci&oacute;n din&aacute;mica dentro de un
		 * comando <i>General Autenticate</i>. */
		protected static final byte TAG_DYNAMIC_AUTHENTICATION_DATA = (byte) 0x7C;

		/** Obtiene los datos como array de octetos.
		 * @return Datos como array de octetos. */
		public abstract byte[] getBytes();
	}

	/** Datos <i>Encrypted Nonce</i> para la APDU <i>General Authenticate</i>. */
	public static final class DataEncryptedNonce extends GeneralAuthenticateData {
		@Override
		public byte[] getBytes() {
			return new byte[] { (byte) 0x7C, (byte) 0x00 };
		}
	}

	/** Datos <i>Map Nonce</i> para la APDU <i>General Authenticate</i>. */
	public static final class DataMapNonce extends GeneralAuthenticateData {

		/** Etiqueta del segundo TLV de los datos de autenticaci&oacute;n din&aacute;mica
		 * dentro de un comando <i>General Autenticate</i>. */
		public static final byte TAG_GEN_AUTH_2 = (byte) 0x81;

		private final byte[] publicKeyIfdDh1;

		/** Crea datos <i>Map Nonce</i> para la APDU <i>General Authenticate</i>.
		 * @param puKIfdDh1UncompressedBytes Clave p&uacute;blica (1) del IFD. */
		public DataMapNonce(final byte[] puKIfdDh1UncompressedBytes) {
			publicKeyIfdDh1 = puKIfdDh1UncompressedBytes;
		}

		@Override
		public byte[] getBytes() {
			return new Tlv(
				TAG_DYNAMIC_AUTHENTICATION_DATA,
				new Tlv(TAG_GEN_AUTH_2, publicKeyIfdDh1).getBytes()
			).getBytes();
		}
	}

	/** Datos <i>Perform Key Agreement</i> para la APDU <i>General Authenticate</i>. */
	public static final class DataPerformKeyAgreement extends GeneralAuthenticateData {

		/** Etiqueta del tercer TLV de los datos de autenticaci&oacute;n din&aacute;mica
		 * dentro de un comando <i>General Autenticate</i>. */
		public static final byte TAG_GEN_AUTH_3 = (byte) 0x83;

		private final byte[] publicKeyIfdDh2;

		/** Crea datos <i>Perform Key Agreement</i> para la APDU <i>General Authenticate</i>.
		 * @param puKIfdDh2UncompressedBytes Clave p&uacute;blica (2) del IFD. */
		public DataPerformKeyAgreement(final byte[] puKIfdDh2UncompressedBytes) {
			publicKeyIfdDh2 = puKIfdDh2UncompressedBytes;
		}

		@Override
		public byte[] getBytes() {
			return new Tlv(
				TAG_DYNAMIC_AUTHENTICATION_DATA,
				new Tlv(TAG_GEN_AUTH_3, publicKeyIfdDh2).getBytes()
			).getBytes();
		}
	}

	/** Datos <i>Mutual Authentication</i> para la APDU <i>General Authenticate</i>. */
	public static final class DataMutualAuthentication extends GeneralAuthenticateData {

		/** Etiqueta del cuarto TLV de los datos de autenticaci&oacute;n din&aacute;mica
		 * dentro de un comando <i>General Autenticate</i>. */
		protected static final byte TAG_GEN_AUTH_4 = (byte) 0x85;

		private final byte[] messageAuthenticationCode;

		/** Crea datos <i>Mutual Authentication</i> para la APDU <i>General Authenticate</i>.
		 * @param mac C&oacute;digo de Autenticaci&oacute;n del Mensaje (MAC). */
		public DataMutualAuthentication(final byte[] mac) {
			messageAuthenticationCode = mac;
		}

		@Override
		public byte[] getBytes() {
			return new Tlv(
				TAG_DYNAMIC_AUTHENTICATION_DATA,
				new Tlv(TAG_GEN_AUTH_4, messageAuthenticationCode).getBytes()
			).getBytes();
		}
	}
}