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

/** Constantes del DNIe (versiones con IDESP posterior a "BMP100001", con nueva jerarqu&iacute;a de certificados) para
 * el establecimiento de canal seguro CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
class Dnie3r2UsrCwa14890Constants extends Dnie3UsrCwa14890Constants {

    /** Certificado de la CA intermedia de Terminal verificable por la tarjeta.
     * (<i>c-CV-CA-CS-AUT</i>). */
	private static final byte[] C_CV_CA_R2 = new byte[] {
		(byte) 0x7f, (byte) 0x21, (byte) 0x81, (byte) 0xce, (byte) 0x5f, (byte) 0x37, (byte) 0x81, (byte) 0x80, (byte) 0x7a, (byte) 0xa0, (byte) 0x6c, (byte) 0x96,
        (byte) 0x5e, (byte) 0x8f, (byte) 0xb2, (byte) 0x19, (byte) 0x61, (byte) 0xcf, (byte) 0xd4, (byte) 0x49, (byte) 0xd0, (byte) 0x9b, (byte) 0x9d, (byte) 0xaf,
        (byte) 0x03, (byte) 0x04, (byte) 0x73, (byte) 0x01, (byte) 0x15, (byte) 0x69, (byte) 0x70, (byte) 0xb7, (byte) 0x73, (byte) 0xf1, (byte) 0x9c, (byte) 0x40,
        (byte) 0xf1, (byte) 0x27, (byte) 0xd3, (byte) 0x38, (byte) 0xe3, (byte) 0xc1, (byte) 0x35, (byte) 0xeb, (byte) 0x21, (byte) 0x20, (byte) 0x56, (byte) 0x6d,
        (byte) 0xc6, (byte) 0xf9, (byte) 0xf7, (byte) 0x45, (byte) 0xff, (byte) 0xb8, (byte) 0xf8, (byte) 0xe2, (byte) 0xb6, (byte) 0x1e, (byte) 0xe8, (byte) 0x16,
        (byte) 0x6f, (byte) 0xfd, (byte) 0x06, (byte) 0xd2, (byte) 0x8c, (byte) 0xb4, (byte) 0x8c, (byte) 0x15, (byte) 0x2a, (byte) 0x1f, (byte) 0xa4, (byte) 0xf7,
        (byte) 0xe9, (byte) 0xf6, (byte) 0x09, (byte) 0xd7, (byte) 0x52, (byte) 0x76, (byte) 0x33, (byte) 0x1c, (byte) 0xb7, (byte) 0x00, (byte) 0xb8, (byte) 0x4e,
        (byte) 0x36, (byte) 0xac, (byte) 0x8a, (byte) 0x0a, (byte) 0x77, (byte) 0x74, (byte) 0x46, (byte) 0x8c, (byte) 0x3c, (byte) 0xf3, (byte) 0xd1, (byte) 0x47,
        (byte) 0xa4, (byte) 0x9c, (byte) 0x97, (byte) 0x6e, (byte) 0x17, (byte) 0xab, (byte) 0x02, (byte) 0xda, (byte) 0x03, (byte) 0xea, (byte) 0x4a, (byte) 0xc1,
        (byte) 0x51, (byte) 0x77, (byte) 0x7e, (byte) 0xdf, (byte) 0xbc, (byte) 0x35, (byte) 0xc2, (byte) 0x7d, (byte) 0x56, (byte) 0xfb, (byte) 0xa6, (byte) 0x85,
        (byte) 0x75, (byte) 0x6e, (byte) 0xd6, (byte) 0x52, (byte) 0x85, (byte) 0x1d, (byte) 0xfd, (byte) 0xe7, (byte) 0x01, (byte) 0xbf, (byte) 0x87, (byte) 0x49,
        (byte) 0x92, (byte) 0xdd, (byte) 0x4d, (byte) 0xe8, (byte) 0x5f, (byte) 0x38, (byte) 0x3d, (byte) 0x33, (byte) 0xe3, (byte) 0xd5, (byte) 0x2a, (byte) 0x4b,
        (byte) 0x09, (byte) 0x40, (byte) 0xe3, (byte) 0x90, (byte) 0xcd, (byte) 0x1a, (byte) 0x64, (byte) 0x1f, (byte) 0xea, (byte) 0x2e, (byte) 0x9c, (byte) 0xdd,
        (byte) 0x79, (byte) 0xd3, (byte) 0x87, (byte) 0x2d, (byte) 0xd6, (byte) 0xc5, (byte) 0x08, (byte) 0xd5, (byte) 0xef, (byte) 0x23, (byte) 0x9c, (byte) 0xb0,
        (byte) 0x7e, (byte) 0xb5, (byte) 0x55, (byte) 0x68, (byte) 0xce, (byte) 0x18, (byte) 0x8b, (byte) 0x65, (byte) 0x13, (byte) 0xac, (byte) 0xb8, (byte) 0x84,
        (byte) 0x14, (byte) 0xc9, (byte) 0xad, (byte) 0xf7, (byte) 0xa6, (byte) 0x4e, (byte) 0x2c, (byte) 0xc0, (byte) 0xb3, (byte) 0x14, (byte) 0xd1, (byte) 0x27,
        (byte) 0x54, (byte) 0xae, (byte) 0xee, (byte) 0x67, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x42, (byte) 0x08, (byte) 0x65, (byte) 0x73,
        (byte) 0x52, (byte) 0x44, (byte) 0x49, (byte) 0x62, (byte) 0x00, (byte) 0x18
    };

	@Override
	public byte[] getCCvCa() {
		return C_CV_CA_R2;
	}

}