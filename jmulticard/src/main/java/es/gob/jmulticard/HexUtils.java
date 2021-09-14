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
import java.util.logging.Logger;

/** Utilidades varias de tratamiento de datos binarios y hexadecimales.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Alberto Mart&iacute;nez
 * @author Carlos Gamuci. */
public final class HexUtils {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

    /** Equivalencias de hexadecimal a texto por la posici&oacute;n del vector. Para
     * ser usado en <code>hexify()</code>. */
    private static final char[] HEX_CHARS = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    /** Constructor privado. */
    private HexUtils() {
        // No se permite instanciacion en una clase de utilidades
    }

    /** Comprueba si dos <i>arrays</i> de octetos son iguales.
     * @param v Primer <i>array</i> de octetos.
     * @param w Segundo <i>array</i> de octetos.
     * @return <code>true</code> si los <i>arrays</i> son iguales, <code>false</code> en caso contrario. */
    public static boolean arrayEquals(final byte[] v, final byte[] w) {
        return HexUtils.arrayEquals(v, 0, v.length, w, 0, w.length);
    }

    /** Comprueba si dos <i>arrays</i> de octetos son iguales.
     * @param v Primer <i>array</i> de octetos.
     * @param vOffset Desplazamiento (<i>offset</i>) de inicio para el primer <i>array</i>.
     * @param vLen Longitud de los datos en el primer <i>array</i>.
     * @param w Segundo <i>array</i> de octetos.
     * @param wOffset Desplazamiento (<i>offset</i>) de inicio para el segundo <i>array</i>.
     * @param wLen Longitud de los datos en el segundo <i>array</i>.
     * @return <code>true</code> si los <i>arrays</i> son iguales en longitudes y valores comparados desde
     *         los respectivos desplazamientos, <code>false</code> en caso contrario. */
    public static boolean arrayEquals(final byte[] v, final int vOffset, final int vLen, final byte[] w, final int wOffset, final int wLen) {
        if (vLen != wLen || v.length < vOffset + vLen || w.length < wOffset + wLen) {
            return false;
        }

        for (int i = 0; i < vLen; i++) {
            if (v[i + vOffset] != w[i + wOffset]) {
                return false;
            }
        }
        return true;
    }

    /** Obtiene un <code>short</code> a partir de un <i>array</i> de octetos.
     * @param data <i>Array</i> de octetos.
     * @param offset Desplazamiento (<i>offset</i>) hasta el inicio de los datos a tratar.
     * @return Valor <code>short</code>. */
    public static short getShort(final byte[] data, final int offset) {
        return (short) HexUtils.getUnsignedInt(data, offset);
    }

    /** Obtiene un entero sin signo (doble octeto) a partir de un <i>array</i> de octetos.
     * @param data <i>Array</i> de octetos.
     * @param offset Desplazamiento (<i>offset</i>) hasta el inicio de los datos a tratar.
     * @return Valor entero sin signo (<i>2-byte unsigned int</i>). */
    public static int getUnsignedInt(final byte[] data, final int offset) {
        return (data[offset] & 0xff) << 8 | data[offset + 1] & 0xff;
    }

    /** Convierte un vector de octetos en una cadena de caracteres que contiene su
     * representaci&oacute;n hexadecimal. Copiado directamente de <a href="http://www.openscdp.org/ocf/api/opencard/core/util/HexString.html">
     * <code>opencard.core.util.HexString</code></a>.
     * @param abyte <i>Array</i> de octetos que deseamos representar textualmente.
     * @param separator Indica si han de separarse o no los octetos con un gui&oacute;n y en
     *        l&iacute;neas de 16.
     * @return Representaci&oacute;n textual del vector de octetos de entrada. */
    public static String hexify(final byte abyte[], final boolean separator) {
        if (abyte == null) {
            return "null"; //$NON-NLS-1$
        }
        final StringBuffer stringbuffer = new StringBuffer(256);
        int i = 0;
        for (final byte element : abyte) {
            if (separator && i > 0) {
                stringbuffer.append('-');
            }
            stringbuffer.append(HexUtils.HEX_CHARS[element >> 4 & 0xf]);
            stringbuffer.append(HexUtils.HEX_CHARS[element & 0xf]);
            if (++i == 16) {
                if (separator) {
                    stringbuffer.append('\n');
                }
                i = 0;
            }
        }
        return stringbuffer.toString();
    }

    /** Devuelve una porci&oacute;n del <i>array</i> especificado.
     * @param src <i>Array</i> de octetos original.
     * @param srcPos Posici&oacute;n de origen de la porci&oacute;n del <i>array</i> de octetos a obtener.
     * @param length N&uacute;mero de octetos de la porci&oacute;n a obtener.
     * @return Una porci&oacute;n del <i>array</i> especificado. */
    public static byte[] subArray(final byte[] src, final int srcPos, final int length) {
        if (length == 0) {
            return null;
        }
        if (src.length < srcPos + length) {
            return null;
        }
        final byte[] temp = new byte[length];
        System.arraycopy(src, srcPos, temp, 0, length);
        return temp;
    }

    /** Realiza la operacion XOR entre dos <i>array</i> de octetos. El resultado se recortar&aacute; para
     * ser del tama&ntilde;o del primer <i>array</i> recibido tomando los octetos menos significativos
     * del resultado.
     * @param v Primer <i>array</i> de bytes.
     * @param w Segundo <i>array</i> de bytes.
     * @return Resultado del XOR de los <i>arrays</i> de entrada. */
    public static byte[] xor(final byte[] v, final byte[] w) {

        byte[] xored;
        byte[] trimmedXor;
        xored = new BigInteger(1, v).xor(new BigInteger(1, w)).toByteArray();
        trimmedXor = new byte[v.length];
        if (xored.length >= trimmedXor.length) {
            System.arraycopy(xored, xored.length - trimmedXor.length, trimmedXor, 0, trimmedXor.length);
        }
        else {
            System.arraycopy(xored, 0, trimmedXor, trimmedXor.length - xored.length, xored.length);
        }
        return trimmedXor;
    }

    /** Convierte un entero a un <i>array</i> de octetos de 4 posiciones, ordenado de
     * izquierda a derecha.
     * @param value Entero a convertir.
     * @return <i>Array</i> de octetos resultante. */
    public static byte[] intToByteArray(final int value) {
        final byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            final int offset = (b.length - 1 - i) * 8;
            b[3 - i] = (byte) (value >>> offset & 0xFF);
        }
        return b;
    }

	/** Concatena <i>arrays</i> de octetos.
	 * @param arrays <i>Arrays</i> de octetos a concatenar, en el orden de concatenaci&oacute;n.
	 * @return <i>Arrays</i> concatenados. */
	public static byte[] concatenateByteArrays(final byte[]... arrays) {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (final byte[] array : arrays) {
			try {
				baos.write(array);
			}
			catch (final IOException e) {
				throw new IllegalStateException(
					"Error construyendo el campo de datos: " + e, e //$NON-NLS-1$
				);
			}
		}
		return baos.toByteArray();
	}

    /** Convierte un <i>array</i> de caracteres en otro de octetos.
     * @param in El <i>array</i> de <code>char</code> de entrada.
     * @return <i>Array</i> de <code>byte</code> correspondiente al
     *         <i>array</i> de <code>char</code> de entrada. */
    public static byte[] charArrayToByteArray(final char[] in) {
    	if (in == null) {
    		LOGGER.warning(
				"Se ha pedido convertir un array de caracteres nulo, se devolvera otro vacio de octetos" //$NON-NLS-1$
			);
    		return new byte[0];
    	}
    	if (in.length < 1) {
    		LOGGER.warning(
				"El array de caracteres proporcionado esta vacio, se devolvera otro vacio de octetos" //$NON-NLS-1$
			);
    		return new byte[0];
    	}
    	final byte[] ret = new byte[in.length];
    	for (int i=0; i<in.length; i++) {
    		ret[i] = (byte) in[i];
    	}
    	return ret;
    }

}