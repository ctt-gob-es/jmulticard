package es.gob.jmulticard.apdu.connection.cwa14890;

import es.gob.jmulticard.HexUtils;

/** Cifrador de APDU seg&uacute;n CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
abstract class ApduEncrypter {

    /** CLA que se suma a los CLA de las APDU que se protegen. */
    protected static final byte CLA_OF_PROTECTED_APDU = (byte) 0x0C; // Indicate "Secure messaging" (0x08) and "Header is protected" (0x04)

    /** Primer byte a agregar en los padding ISO-7816. */
    private static final byte ISO7816_PADDING_PREFIX = (byte) 0x80;

    /** Agrega un relleno (<i>padding</i>) a un array de bytes conforme las especificaciones ISO 7816.
     * Esto es, se agrega un byte <code>0x80</code> al array y se completa con bytes <code>0x00</code> hasta que el
     * array es m&uacute;ltiplo de 8.
     * @param data Datos a los que agregar el relleno.
     * @return Datos con relleno. */
    protected static byte[] addPadding7816(final byte[] data) {
        final byte[] paddedData = new byte[(data.length / 8 + 1) * 8];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        paddedData[data.length] = ISO7816_PADDING_PREFIX;
        // Machacamos los datos
        for (int i = data.length + 1; i < paddedData.length; i++) {
            paddedData[i] = '\0';
        }
        return paddedData;
    }

    /** Elimina el padding ISO 7816 de los datos.
     * @param paddedData Datos con padding.
     * @return Datos sin padding. */
    protected static byte[] removePadding7816(final byte[] paddedData) {
        for (int i = paddedData.length - 1; i >= 0; i--) {
            if (paddedData[i] == ISO7816_PADDING_PREFIX) {
                if (i == 0) {
                    return new byte[0];
                }
                return HexUtils.subArray(paddedData, 0, i);
            }
            else if (paddedData[i] != (byte) 0x00) {
                // Consideramos que no tenia padding
                return paddedData;
            }
        }
        // Esto solo ocurriria si todo fuesen 0x00
        return paddedData;
    }


}
