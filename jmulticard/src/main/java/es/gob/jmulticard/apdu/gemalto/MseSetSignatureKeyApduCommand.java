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
package es.gob.jmulticard.apdu.gemalto;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad orientada a
 * establecer una clave privada para firma.
 * @author Carlos Gamuci Mill&aacute;n */
public final class MseSetSignatureKeyApduCommand extends CommandApdu {

    /** Byte de instrucci&oacute;n de la APDU. */
    private static final byte INS_MANAGE_ENVIROMENT = (byte) 0x22;

    /** Establece la clave indicada para firma. */
    private static final byte SET_FOR_SIGN = (byte) 0x41;

    /** Plantilla de referencia de control para firma */
    private static final byte SIGN_TEMPLATE = (byte) 0xb6;

    /** Etiqueta para hacer referencia a un fichero dedicado. */
    private static final byte PRIVATE_KEY_REFERENCE = (byte) 0x84;

    /** Etiqueta para hacer referencia a un fichero dedicado. */
    private static final byte CRYPTOGRAPHIC_MECHANISM = (byte) 0x80;

    /** Mecanismo criptogr&aacute;fico a usar con la clave privada establecida. */
    public enum CryptographicMechanism {

    	/** RSASSA con PKCS#1 v2.1 y SHA1. */
    	RSASSA_PSS_SHA1((byte) 0x01),

    	/** RSASSA con PKCS#1 v1.5 y SHA1. */
    	RSASSA_PKCS1v1_5_SHA1((byte) 0x02),

    	/** RSASSA con PKCS#1 v1.5 y MD5. */
    	RSASSA_PKCS1v1_5_MD5((byte) 0x04);

    	private final byte value;

    	private CryptographicMechanism(final byte v) {
    		this.value = v;
    	}

    	/** Obtiene el valor del mecanismo.
    	 * @return Valor del mecanismo */
    	public byte getValue() {
    		return this.value;
    	}
    }

    /** Crea una APDU para el establecimiento de la clave privada de firma.
     * @param cla Clase (CLA) de la APDU
     * @param algo Mecanismo criptogr&aacute;fico a usar con la clave privada establecida
     * @param privateKeyReference Referencia a la clave a establecer */
    public MseSetSignatureKeyApduCommand(final byte cla,
    		                             final CryptographicMechanism algo,
    		                             final byte privateKeyReference) {
        super(
    		cla,                                      // CLA (00)
            INS_MANAGE_ENVIROMENT,                    // INS (22)
            SET_FOR_SIGN,							  // P1  (41)
            SIGN_TEMPLATE,                            // P2  (B6)
            buidData(algo, privateKeyReference),	  // Data
            null                                      // Le
        );
    }

    private static byte[] buidData(final CryptographicMechanism algo,
                                   final byte privateKeyReference) {
    	if (algo == null) {
    		throw new IllegalArgumentException("El mecanismo criptografico no puede ser nulo"); //$NON-NLS-1$
    	}
        return new byte[] {
    		CRYPTOGRAPHIC_MECHANISM,
    		(byte) 0x01, // Len
    		algo.getValue(),
    		PRIVATE_KEY_REFERENCE,
    		(byte) 0x01, // Len
    		privateKeyReference
        };
    }
}