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

import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

/** Gestiona las constantes para el establecimiento de canal seguro CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.  */
interface Cwa14890Constants {

    /** Obtiene la referencia al fichero en donde reside la clave p&uacute;blica de la autoridad certificadora
     * ra&iacute;z de la jerarqu&iacute;a de certificados verificables por la tarjeta.
     * @return Referencia al fichero en donde reside la clave p&uacute;blica de la autoridad certificadora
     * ra&iacute;z de la jerarqu&iacute;a de certificados verificables por la tarjeta.*/
    byte[] getRefCCvCaPublicKey();

    /** Obtiene el certificado de la CA intermedia de terminal verificable por la tarjeta.
     * @return Certificado de la CA intermedia de terminal verificable por la tarjeta.*/
    byte[] getCCvCa();

    /** Obtiene el identificador de la CA intermedia (CHR). El campo ocupa siempre 12 bytes y si el numero de serie es
     * de menor longitud se rellena con ceros a la izquierda. El n&uacute;mero de serie es de al menos 8 bytes.
     * Aqu&iacute; se obtienen los 8 bytes del n&uacute;mero de serie obviando el resto del campo (que no se
     * utiliza).
     * @return Identificador de la CA intermedia (CHR). */
    byte[] getChrCCvCa();

    /** Obtiene la referencia al fichero en donde reside la clave privada de componente.
     * @return Referencia al fichero en donde reside la clave privada de componente. */
    byte[] getRefIccPrivateKey();

    /** Obtiene el certificado de Terminal verificable por la tarjeta.
     * @return Certificado de Terminal verificable por la tarjeta. */
    byte[] getCCvIfd();

    /** Obtiene el identificador de la CA intermedia (CHR). El campo ocupa siempre 12 bytes y si el numero de serie es
     * de menor longitud se rellena con ceros a la izquierda. El n&uacute;mero de serie es de al menos 8 bytes.
     * Aqu&iacute; indicamos los 8 bytes del n&uacute;mero de serie obviando el resto del campo (que no se
     * utiliza).
     * @return Identificador de la CA intermedia (CHR). */
    byte[] getChrCCvIfd();

    /** Obtiene la clave privada del certificado de Terminal.
     * @return Clave privada del certificado de Terminal. */
    RSAPrivateKey getIfdPrivateKey();

    /** Obtiene la clave p&uacute;blica del certificado de componente de la tarjeta.
     * @return Clave p&uacute;blica del certificado de componente de la tarjeta. */
    PublicKey getCaComponentPublicKey();

}