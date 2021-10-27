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

import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;

/** Constantes del DNIe para el establecimiento de canal seguro CWA-14890. */
abstract class Dnie3Cwa14890Constants implements Cwa14890PublicConstants, Cwa14890PrivateConstants {

    /** Referencia al fichero en donde reside la clave p&uacute;blica de la autoridad certificadora
     * ra&iacute;z de la jerarqu&iacute;a de certificados verificables por la tarjeta.
     * (<i>pk-RCA-AUT-keyRef</i>).*/
	private static final byte[] REF_C_CV_CA_PUBLIC_KEY = {
        (byte) 0x02, (byte) 0x0f
    };

    /** Referencia al fichero en donde reside la clave privada de componente.
     * (<i>sk-ICC-AUT-keyRef</i>). */
	private static final byte[] REF_ICC_PRIVATE_KEY = {
        (byte) 0x02, (byte) 0x1f
    };

    /** Clave p&uacute;blica del certificado de componente de la tarjeta.
     * (<i>pk-RCAicc</i>). */
    private static final PublicKey CA_COMPONENT_PUBLIC_KEY = new PublicKey() {

        private static final long serialVersionUID = -143874096089393139L;

        private final byte[] encoded = {
            (byte) 0x30, (byte) 0x81, (byte) 0x9F, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48,
            (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x81,
            (byte) 0x8D, (byte) 0x00, (byte) 0x30, (byte) 0x81, (byte) 0x89, (byte) 0x02, (byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0xEA,
            (byte) 0xDE, (byte) 0xDA, (byte) 0x45, (byte) 0x53, (byte) 0x32, (byte) 0x94, (byte) 0x50, (byte) 0x39, (byte) 0xDA, (byte) 0xA4,
            (byte) 0x04, (byte) 0xC8, (byte) 0xEB, (byte) 0xC4, (byte) 0xD3, (byte) 0xB7, (byte) 0xF5, (byte) 0xDC, (byte) 0x86, (byte) 0x92,
            (byte) 0x83, (byte) 0xCD, (byte) 0xEA, (byte) 0x2F, (byte) 0x10, (byte) 0x1E, (byte) 0x2A, (byte) 0xB5, (byte) 0x4F, (byte) 0xB0,
            (byte) 0xD0, (byte) 0xB0, (byte) 0x3D, (byte) 0x8F, (byte) 0x03, (byte) 0x0D, (byte) 0xAF, (byte) 0x24, (byte) 0x58, (byte) 0x02,
            (byte) 0x82, (byte) 0x88, (byte) 0xF5, (byte) 0x4C, (byte) 0xE5, (byte) 0x52, (byte) 0xF8, (byte) 0xFA, (byte) 0x57, (byte) 0xAB,
            (byte) 0x2F, (byte) 0xB1, (byte) 0x03, (byte) 0xB1, (byte) 0x12, (byte) 0x42, (byte) 0x7E, (byte) 0x11, (byte) 0x13, (byte) 0x1D,
            (byte) 0x1D, (byte) 0x27, (byte) 0xE1, (byte) 0x0A, (byte) 0x5B, (byte) 0x50, (byte) 0x0E, (byte) 0xAA, (byte) 0xE5, (byte) 0xD9,
            (byte) 0x40, (byte) 0x30, (byte) 0x1E, (byte) 0x30, (byte) 0xEB, (byte) 0x26, (byte) 0xC3, (byte) 0xE9, (byte) 0x06, (byte) 0x6B,
            (byte) 0x25, (byte) 0x71, (byte) 0x56, (byte) 0xED, (byte) 0x63, (byte) 0x9D, (byte) 0x70, (byte) 0xCC, (byte) 0xC0, (byte) 0x90,
            (byte) 0xB8, (byte) 0x63, (byte) 0xAF, (byte) 0xBB, (byte) 0x3B, (byte) 0xFE, (byte) 0xD8, (byte) 0xC1, (byte) 0x7B, (byte) 0xE7,
            (byte) 0x67, (byte) 0x30, (byte) 0x34, (byte) 0xB9, (byte) 0x82, (byte) 0x3E, (byte) 0x97, (byte) 0x7E, (byte) 0xD6, (byte) 0x57,
            (byte) 0x25, (byte) 0x29, (byte) 0x27, (byte) 0xF9, (byte) 0x57, (byte) 0x5B, (byte) 0x9F, (byte) 0xFF, (byte) 0x66, (byte) 0x91,
            (byte) 0xDB, (byte) 0x64, (byte) 0xF8, (byte) 0x0B, (byte) 0x5E, (byte) 0x92, (byte) 0xCD, (byte) 0x02, (byte) 0x03, (byte) 0x01,
            (byte) 0x00, (byte) 0x01
        };

        /** {@inheritDoc} */
        @Override
        public String getFormat() {
            return "X.509"; //$NON-NLS-1$
        }

        /** {@inheritDoc} */
        @Override
        public byte[] getEncoded() {
            final byte[] out = new byte[this.encoded.length];
            System.arraycopy(this.encoded, 0, out, 0, this.encoded.length);
            return out;
        }

        /** {@inheritDoc} */
        @Override
        public String getAlgorithm() {
            return "RSA"; //$NON-NLS-1$
        }
    };

	@Override
	public byte[] getRefCCvCaPublicKey() {
		return REF_C_CV_CA_PUBLIC_KEY;
	}

	@Override
	public byte[] getRefIccPrivateKey() {
		return REF_ICC_PRIVATE_KEY;
	}

	@Override
	public PublicKey getCaComponentPublicKey() {
		return CA_COMPONENT_PUBLIC_KEY;
	}
}