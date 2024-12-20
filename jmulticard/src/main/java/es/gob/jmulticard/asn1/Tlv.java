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
package es.gob.jmulticard.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JmcLogger;

/** Representaci&oacute;n de un TLV (Tipo-Longitud-Valor) binario en forma ASN&#46;1 DER.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Tlv {

    /** Octeto de tipo (etiqueta). */
    private final byte tag;

    /** Longitud del valor. */
    private final int length;

    /** Estructura binaria completa del TLV. */
    private final byte[] bytes;

    private final int valueOffset;

    /** Construye un TLV simple con etiqueta y longitud de un solo octeto cada uno.
     * @param t Etiqueta (tipo) del TLV.
     * @param value Valor del TLV. */
    public Tlv(final byte t, final byte[] value) {
    	if (value == null) {
            throw new IllegalArgumentException("El valor del TLV no puede ser nulo"); //$NON-NLS-1$
        }
        valueOffset = 2;
        tag = t;
        length = value.length;


        final int iExtLen;
        if (length >= 256) {
        	iExtLen = 4;
        }
        else if (length >= 128) {
        	iExtLen = 3;
        }
        else {
        	iExtLen = 2;
        }

        bytes = new byte[value.length + iExtLen];
        bytes[0] = t;

        if (length >= 256) {
        	bytes[1] = (byte) 0x82;
        	bytes[2] = (byte) (value.length >> 8 & 0xFF);
        	bytes[3] = (byte) (value.length & 0xFF);
    	}
        else if (value.length >= 128) {
        	bytes[1] = (byte) 0x81;
        	bytes[2] = (byte)value.length;
    	}
        else {
            bytes[1] = (byte)value.length;
        }

        System.arraycopy(value, 0, bytes, iExtLen, value.length);
    }

    /** Construye un TLV simple a partir de su representaci&oacute;n binaria directa.
     * @param buffer Representaci&oacute;n binaria del TLV.
     * @throws TlvException En caso de error analizando el TLV. */
    public Tlv(final byte[] buffer) throws TlvException {
        if (buffer == null) {
            throw new IllegalArgumentException("El TLV no puede ser nulo"); //$NON-NLS-1$
        }
        if (buffer.length == 0) {
        	JmcLogger.warning("Se ha pedido crear un TLV vacio"); //$NON-NLS-1$
        	length = 0;
        	bytes = new byte[0];
        	tag = (byte) 0xff;
        	valueOffset = 0;
        	return;
        }
        if (buffer.length < 2) {
            throw new IllegalArgumentException(
        		"El TLV no puede medir menos de dos octetos: " + HexUtils.hexify(buffer, false)//$NON-NLS-1$
    		);
        }

        int offset = 0;

        // Copiamos el TLV completo
        final byte[] tempBytes = new byte[buffer.length];
        System.arraycopy(buffer, 0, tempBytes, 0, buffer.length);

        tag = tempBytes[offset++];

        // Copiamos la longitud
        int size = tempBytes[offset++] & 0xff;
        final boolean indefinite = size == 128;
        if (indefinite) {
            if ((tag & 0x20) == 0) {
                throw new TlvException("Longitud del TLV invalida"); //$NON-NLS-1$
            }
        }
        else if (size >= 128) {
            int sizeLen = size - 128;
            // NOTA: El tamano debe caber en tres octetos
            if (sizeLen > 3) {
                throw new TlvException("TLV demasiado largo"); //$NON-NLS-1$
            }
            size = 0;
            while (sizeLen > 0) {
                size = (size << 8) + (tempBytes[offset++] & 0xff);
                sizeLen--;
            }
        }

        length = size;
        valueOffset = offset;

        bytes = new byte[valueOffset + length];
        System.arraycopy(tempBytes, 0, bytes, 0, valueOffset + length);

    }

    /** Devuelve el TLV directamente en binario.
     * @return Valor binario completo del TLV. */
    public byte[] getBytes() {
        final byte[] out = new byte[bytes.length];
        System.arraycopy(bytes, 0, out, 0, bytes.length);
        return out;
    }

    /** Devuelve la longitud del valor del TLV.
     * @return Longitud del valor del TLV. */
    public int getLength() {
        return length;
    }

    /** Devuelve el tipo (etiqueta) del TLV.
     * @return Tipo (etiqueta) del TLV. */
    public byte getTag() {
        return tag;
    }

    /** Devuelve el valor del TLV.
     * @return Valor del del TLV. */
    public byte[] getValue() {
        final byte[] out = new byte[length];
        System.arraycopy(bytes, valueOffset, out, 0, length);
        return out;
    }

    /** Obtiene un TLV de un flujo de entrada, leyendo del mismo &uacute;nicamente los octetos
     * correspondientes al TLV en cuesti&oacute;n.
     * @param recordOfTlv Flujo de entrada.
     * @return TLV recuperado del flujo.
     * @throws IOException Si ocurre un error durante la lectura del TLV. */
    public static Tlv decode(final ByteArrayInputStream recordOfTlv) throws IOException {

        final byte tag = (byte) recordOfTlv.read();

        // Comprobamos que el Tipo sea valido (tipos multi-octeto)
        if ((tag & 0x1f) == 0x1f) {
            throw new IOException("El tipo del TLV es invalido"); //$NON-NLS-1$
        }

        // Copiamos la longitud
        int size = recordOfTlv.read() & 0xff;

        final boolean indefinite = size == 128;
        if (indefinite) {
            if ((tag & 0x20) == 0) {
                throw new IOException("Longitud del TLV invalida"); //$NON-NLS-1$
            }
        }
        else if (size >= 128) {
            int sizeLen = size - 128;
            // NOTA: El tamano debe caber en tres octetos
            if (sizeLen > 3) {
                throw new IOException("TLV demasiado largo"); //$NON-NLS-1$
            }
            size = 0;
            while (sizeLen > 0) {
                size = (size << 8) + (recordOfTlv.read() & 0xff);
                sizeLen--;
            }
        }

        final byte[] value = new byte[size];
        if (value.length != recordOfTlv.read(value)) {
            throw new IndexOutOfBoundsException(
        		"La longitud de los datos leidos no coincide con el parametro indicado" //$NON-NLS-1$
    		);
        }

        return new Tlv(tag, value);
    }

    @Override
	public String toString() {
    	return "TLV (Tag=" + HexUtils.hexify(new byte[] { getTag() }, false) + //$NON-NLS-1$
			", Length=" + getLength() + //$NON-NLS-1$
				", Value=" + (getValue().length == 0 ? "vacio" : HexUtils.hexify(getValue(), false)) + ")"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
    }
}