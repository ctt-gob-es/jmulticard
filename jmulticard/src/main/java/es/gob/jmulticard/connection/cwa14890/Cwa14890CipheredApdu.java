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
package es.gob.jmulticard.connection.cwa14890;

import java.io.ByteArrayOutputStream;

import es.gob.jmulticard.apdu.CommandApdu;

/** APDU cifrada para su env&iacute;o a trav&eacute;s de un canal seguro.
 * @author Carlos Gamuci
 * @author Alberto Mart&iacute;nez
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Cwa14890CipheredApdu extends CommandApdu {

	private static final byte TAG_CRYPTOGRAPHIC_CHECKSUM = (byte) 0x8E;

	private final byte[] mac;
	private transient final byte[] data;

    byte[] getMac() {
        final byte[] out = new byte[mac.length];
        System.arraycopy(mac, 0, out, 0, mac.length);
        return out;
    }

    byte[] getCryptogramData() {
        final byte[] out = new byte[data.length];
        System.arraycopy(data, 0, out, 0, data.length);
        return out;
    }

    /** Crea una APDU cifrada seg&uacute;n CWA-14890.
     * @param cla Clase (CLA).
     * @param ins Instrucci&oacute;n (INS).
     * @param p1 Primer par&aacute;metro.
     * @param p2 Segundo par&aacute;metro.
     * @param apduData Datos del TLV criptograma.
     * @param apduMac C&oacute;digo de autenticaci&oacute;n del criptograma (MAC). */
    Cwa14890CipheredApdu(final byte cla,
    		     final byte ins,
    		     final byte p1,
    		     final byte p2,
    		     final byte[] apduData,
    		     final byte[] apduMac) {
        super(
    		cla,					      // CLA
    		ins,					      // INS
    		p1,						      // P1
    		p2,						      // P2
    		buildData(apduData, apduMac), // Data
    		null					      // Le
		);
        mac = new byte[apduMac.length];
        System.arraycopy(apduMac, 0, mac, 0, apduMac.length);
        data = new byte[apduData.length];
        System.arraycopy(apduData, 0, data, 0, apduData.length);
    }

    private static byte[] buildData(final byte[] data, final byte[] mac) {
       if (data == null || mac == null) {
        	throw new IllegalArgumentException("Ni los datos (TLV) ni el MAC pueden ser nulos"); //$NON-NLS-1$
       }
       if (mac.length != 4 && mac.length != 8) {
        	throw new IllegalArgumentException(
    			"El MAC debe medir cuatro u ocho octetos, y el recibido mide " + mac.length + " octetos" //$NON-NLS-1$ //$NON-NLS-2$
			);
       }
       final ByteArrayOutputStream baos = new ByteArrayOutputStream();
       try {
	       baos.write(data);
	       baos.write(TAG_CRYPTOGRAPHIC_CHECKSUM);
	       baos.write((byte)mac.length);
	       baos.write(mac);
       }
       catch(final Exception e) {
    	   throw new IllegalStateException(
			   "Error creando la APDU cifrada", e //$NON-NLS-1$
		   );
       }
       return baos.toByteArray();
    }

    @Override
    public void setLe(final int le) {
        throw new UnsupportedOperationException("No se puede establecer el Le en una APDU cifrada"); //$NON-NLS-1$
    }

}