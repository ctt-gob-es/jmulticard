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

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

/** Constantes del DNIe (versiones con IDESP posterior a "BMP100001", con nueva jerarqu&iacute;a de certificados) para
 * el establecimiento de canal seguro de PIN CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class Dnie3r2PinCwa14890Constants extends Dnie3r2Cwa14890Constants {

    /** Certificado de Terminal verificable por la tarjeta.
     * (<i>c-CV-IFD-AUT</i>). */
	private static final byte[] C_CV_IFD = new byte[] {
		(byte) 0x7f, (byte) 0x21, (byte) 0x81, (byte) 0xcd, (byte) 0x5f, (byte) 0x37, (byte) 0x81, (byte) 0x80, (byte) 0x0a, (byte) 0x3d, (byte) 0xb4, (byte) 0xd1,
        (byte) 0x57, (byte) 0x98, (byte) 0xf2, (byte) 0x34, (byte) 0xf6, (byte) 0x31, (byte) 0xfd, (byte) 0x94, (byte) 0xc9, (byte) 0x1d, (byte) 0x2a, (byte) 0x63,
        (byte) 0x63, (byte) 0xd0, (byte) 0xe1, (byte) 0x8e, (byte) 0x1b, (byte) 0x56, (byte) 0xda, (byte) 0xbd, (byte) 0xe6, (byte) 0x22, (byte) 0xbc, (byte) 0x20,
        (byte) 0x1f, (byte) 0xd7, (byte) 0xc7, (byte) 0xff, (byte) 0x59, (byte) 0xff, (byte) 0x66, (byte) 0xda, (byte) 0x6e, (byte) 0x43, (byte) 0x4f, (byte) 0xe2,
        (byte) 0xf7, (byte) 0xf4, (byte) 0x6e, (byte) 0x42, (byte) 0xe4, (byte) 0xa6, (byte) 0x06, (byte) 0xea, (byte) 0x82, (byte) 0x39, (byte) 0xac, (byte) 0x1a,
        (byte) 0xc3, (byte) 0x0c, (byte) 0x7d, (byte) 0xad, (byte) 0xe2, (byte) 0x29, (byte) 0x65, (byte) 0xdf, (byte) 0x60, (byte) 0x6d, (byte) 0x11, (byte) 0x5e,
        (byte) 0x04, (byte) 0xc8, (byte) 0xef, (byte) 0xfc, (byte) 0x77, (byte) 0x2b, (byte) 0x8f, (byte) 0x5d, (byte) 0x48, (byte) 0x77, (byte) 0x3e, (byte) 0x34,
        (byte) 0x95, (byte) 0x5f, (byte) 0x33, (byte) 0xf4, (byte) 0x64, (byte) 0xed, (byte) 0x85, (byte) 0xcc, (byte) 0x0e, (byte) 0xb1, (byte) 0xbc, (byte) 0x57,
        (byte) 0x2a, (byte) 0xfa, (byte) 0xba, (byte) 0x47, (byte) 0x25, (byte) 0xfb, (byte) 0xf5, (byte) 0xbd, (byte) 0xcf, (byte) 0x1d, (byte) 0x8c, (byte) 0x38,
        (byte) 0xc9, (byte) 0xfe, (byte) 0x9c, (byte) 0xd8, (byte) 0x53, (byte) 0x6f, (byte) 0x34, (byte) 0x0b, (byte) 0xce, (byte) 0x14, (byte) 0x1d, (byte) 0xf5,
        (byte) 0x18, (byte) 0x7f, (byte) 0xa2, (byte) 0xe2, (byte) 0x37, (byte) 0x2d, (byte) 0x73, (byte) 0xbc, (byte) 0x7f, (byte) 0x89, (byte) 0x48, (byte) 0x35,
        (byte) 0x0c, (byte) 0xba, (byte) 0xde, (byte) 0xf2, (byte) 0x5f, (byte) 0x38, (byte) 0x3c, (byte) 0x0d, (byte) 0xcc, (byte) 0x88, (byte) 0x8d, (byte) 0x47,
        (byte) 0x96, (byte) 0x54, (byte) 0x3f, (byte) 0x03, (byte) 0x25, (byte) 0x4f, (byte) 0x4e, (byte) 0x2c, (byte) 0xdf, (byte) 0x98, (byte) 0xb1, (byte) 0xe1,
        (byte) 0x26, (byte) 0x11, (byte) 0xe3, (byte) 0x98, (byte) 0x1f, (byte) 0x53, (byte) 0x33, (byte) 0xdf, (byte) 0x98, (byte) 0xc8, (byte) 0x86, (byte) 0x01,
        (byte) 0x93, (byte) 0x75, (byte) 0x84, (byte) 0x0f, (byte) 0xac, (byte) 0x61, (byte) 0xdb, (byte) 0x8f, (byte) 0x1b, (byte) 0xa3, (byte) 0xb5, (byte) 0x43,
        (byte) 0xdc, (byte) 0xea, (byte) 0x3d, (byte) 0x05, (byte) 0x9e, (byte) 0x6a, (byte) 0x41, (byte) 0x4f, (byte) 0x6d, (byte) 0xd2, (byte) 0x9f, (byte) 0xc7,
        (byte) 0xc9, (byte) 0x9d, (byte) 0x8b, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x42, (byte) 0x08, (byte) 0x65, (byte) 0x73, (byte) 0x53,
        (byte) 0x44, (byte) 0x49, (byte) 0x62, (byte) 0x00, (byte) 0x18
	};

    /** Identificador de la CA intermedia (CHR). El campo ocupa siempre 12 bytes y si el n&uacute;mero de serie es
     * de menor longitud se rellena con ceros a la izquierda. El n&uacute;mero de serie es de al menos 8 bytes.
     * Aqu&iacute; indicamos los 8 bytes del n&uacute;mero de serie obviando el resto del campo (que no se
     * utiliza).
     * (<i>sn-IFD</i>). */
	private static final byte[] CHR_C_CV_IFD = new byte[] {
        (byte) 0xd0, (byte) 0x02, (byte) 0xe0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04
    };

    /** Clave privada del certificado de Terminal.
     * (<i>sk-IFD-AUT</i>). */
	private static final RSAPrivateKey IFD_PRIVATE_KEY = new RSAPrivateKey() {

        private static final long serialVersionUID = 6991556885804507378L;

        /** (<i>n</i>). */
        private final BigInteger ifdModulus = new BigInteger(1, new byte[] {
            (byte) 0xdf, (byte) 0x03, (byte) 0x93, (byte) 0x0d, (byte) 0x4f, (byte) 0x1d, (byte) 0x97, (byte) 0x15, (byte) 0xeb, (byte) 0xb0, (byte) 0x0f, (byte) 0xbd,
            (byte) 0xae, (byte) 0x48, (byte) 0xaf, (byte) 0x9c, (byte) 0x9d, (byte) 0xbf, (byte) 0xd6, (byte) 0x99, (byte) 0xca, (byte) 0xb0, (byte) 0xbd, (byte) 0xbe,
            (byte) 0x5c, (byte) 0xdb, (byte) 0x01, (byte) 0x34, (byte) 0x00, (byte) 0x0e, (byte) 0x46, (byte) 0x2e, (byte) 0x71, (byte) 0x3a, (byte) 0xe9, (byte) 0x7a,
            (byte) 0x2f, (byte) 0x7e, (byte) 0x20, (byte) 0xaf, (byte) 0xbf, (byte) 0x84, (byte) 0xd3, (byte) 0xce, (byte) 0x73, (byte) 0x4f, (byte) 0xe2, (byte) 0x15,
            (byte) 0x75, (byte) 0x7a, (byte) 0xaf, (byte) 0xa1, (byte) 0xe8, (byte) 0x9e, (byte) 0x64, (byte) 0x57, (byte) 0xea, (byte) 0xe2, (byte) 0xe8, (byte) 0x08,
            (byte) 0x11, (byte) 0x03, (byte) 0x73, (byte) 0xe2, (byte) 0x56, (byte) 0x56, (byte) 0x34, (byte) 0x94, (byte) 0xfb, (byte) 0x5d, (byte) 0x10, (byte) 0x4f,
            (byte) 0x0d, (byte) 0xcc, (byte) 0x88, (byte) 0x8d, (byte) 0x47, (byte) 0x96, (byte) 0x54, (byte) 0x3f, (byte) 0x03, (byte) 0x25, (byte) 0x4f, (byte) 0x4e,
            (byte) 0x2c, (byte) 0xdf, (byte) 0x98, (byte) 0xb1, (byte) 0xe1, (byte) 0x26, (byte) 0x11, (byte) 0xe3, (byte) 0x98, (byte) 0x1f, (byte) 0x53, (byte) 0x33,
            (byte) 0xdf, (byte) 0x98, (byte) 0xc8, (byte) 0x86, (byte) 0x01, (byte) 0x93, (byte) 0x75, (byte) 0x84, (byte) 0x0f, (byte) 0xac, (byte) 0x61, (byte) 0xdb,
            (byte) 0x8f, (byte) 0x1b, (byte) 0xa3, (byte) 0xb5, (byte) 0x43, (byte) 0xdc, (byte) 0xea, (byte) 0x3d, (byte) 0x05, (byte) 0x9e, (byte) 0x6a, (byte) 0x41,
            (byte) 0x4f, (byte) 0x6d, (byte) 0xd2, (byte) 0x9f, (byte) 0xc7, (byte) 0xc9, (byte) 0x9d, (byte) 0x8b
        });

        /** (<i>d</i>). */
        private final BigInteger ifdPrivateExponent = new BigInteger(1, new byte[] {
            (byte) 0x86, (byte) 0x6f, (byte) 0x0f, (byte) 0x2c, (byte) 0x0c, (byte) 0xaf, (byte) 0x17, (byte) 0xae, (byte) 0x7d, (byte) 0x1e, (byte) 0xea, (byte) 0xbe,
            (byte) 0x3a, (byte) 0xdb, (byte) 0x52, (byte) 0x11, (byte) 0x24, (byte) 0xfe, (byte) 0xc9, (byte) 0x8c, (byte) 0x77, (byte) 0xa4, (byte) 0xc7, (byte) 0x1c,
            (byte) 0x83, (byte) 0xb8, (byte) 0xf9, (byte) 0x26, (byte) 0xb1, (byte) 0x89, (byte) 0xe9, (byte) 0x40, (byte) 0x81, (byte) 0xbd, (byte) 0x33, (byte) 0x95,
            (byte) 0x16, (byte) 0x1f, (byte) 0xff, (byte) 0xf0, (byte) 0x31, (byte) 0x91, (byte) 0x0e, (byte) 0x64, (byte) 0xfb, (byte) 0x1a, (byte) 0x02, (byte) 0x7d,
            (byte) 0x51, (byte) 0x0e, (byte) 0x1d, (byte) 0xe5, (byte) 0x89, (byte) 0xe6, (byte) 0x41, (byte) 0x32, (byte) 0xc6, (byte) 0x42, (byte) 0xf6, (byte) 0x00,
            (byte) 0x36, (byte) 0xd1, (byte) 0x4f, (byte) 0xfe, (byte) 0xd5, (byte) 0xd0, (byte) 0xce, (byte) 0x1f, (byte) 0x45, (byte) 0xe7, (byte) 0x11, (byte) 0x6f,
            (byte) 0x13, (byte) 0xc4, (byte) 0xe6, (byte) 0x38, (byte) 0x8e, (byte) 0x25, (byte) 0xdd, (byte) 0x43, (byte) 0x83, (byte) 0x57, (byte) 0x78, (byte) 0x05,
            (byte) 0x85, (byte) 0x73, (byte) 0xdc, (byte) 0x29, (byte) 0xad, (byte) 0x6a, (byte) 0x37, (byte) 0x32, (byte) 0x71, (byte) 0x6d, (byte) 0x08, (byte) 0x11,
            (byte) 0x24, (byte) 0xb7, (byte) 0x52, (byte) 0x51, (byte) 0x40, (byte) 0xb1, (byte) 0xdd, (byte) 0xab, (byte) 0xe2, (byte) 0x51, (byte) 0xa4, (byte) 0x98,
            (byte) 0x0c, (byte) 0xc5, (byte) 0xc0, (byte) 0x3a, (byte) 0x86, (byte) 0xa8, (byte) 0x2d, (byte) 0x17, (byte) 0x4f, (byte) 0xb7, (byte) 0xa8, (byte) 0x1d,
            (byte) 0x24, (byte) 0x8d, (byte) 0x7c, (byte) 0xaa, (byte) 0x2b, (byte) 0x3d, (byte) 0x61, (byte) 0xd1
        });

        /** {@inheritDoc} */
        @Override
        public BigInteger getModulus() {
            return this.ifdModulus;
        }

        /** {@inheritDoc} */
        @Override
        public String getFormat() {
            return "PKCS#8"; //$NON-NLS-1$
        }

        /** {@inheritDoc} */
        @Override
        public byte[] getEncoded() {
        	throw new UnsupportedOperationException();
        }

        /** {@inheritDoc} */
        @Override
        public String getAlgorithm() {
            return "RSA"; //$NON-NLS-1$
        }

        /** {@inheritDoc} */
        @Override
        public BigInteger getPrivateExponent() {
            return this.ifdPrivateExponent;
        }
    };

	@Override
	public byte[] getCCvIfd() {
		return C_CV_IFD;
	}

	@Override
	public byte[] getChrCCvIfd() {
		return CHR_C_CV_IFD;
	}

	@Override
	public RSAPrivateKey getIfdPrivateKey() {
		return IFD_PRIVATE_KEY;
	}

	@Override
	public int getIfdKeyLength() {
		return 128;
	}
}