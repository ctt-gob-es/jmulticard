package es.gob.jmulticard.apdu.connection.cwa14890;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.asn1.Tlv;

/** Cifrador de APDU seg&uacute;n CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
abstract class ApduEncrypter {

    /** Tag del TLV de datos de una APDU protegida. */
    protected static final byte TAG_DATA_TLV = (byte) 0x87;

    /** Tag del TLV del Le de una APDU protegida. */
    private static final byte TAG_LE_TLV = (byte) 0x97;

    /** Byte prefijo de los datos para el c&aacute;lculo de la MAC. */
    private static final byte TLV_VALUE_PREFIX_TO_MAC = (byte) 0x01;

    /** CLA que se suma a los CLA de las APDU que se protegen. */
    private static final byte CLA_OF_PROTECTED_APDU = (byte) 0x0C; // Indicate "Secure messaging" (0x08) and "Header is protected" (0x04)

    /** Primer byte a agregar en los padding ISO-7816. */
    private static final byte ISO7816_PADDING_PREFIX = (byte) 0x80;

    /** En el relleno ISO-7816, longitud de la cual debe ser m&uacute;ltiplo el tama&ntilde;o de los datos de salida. */
    protected int paddingLength = 8;

    /** Encapsula una APDU para ser enviada por un canal seguro CWA-14890.
     * El contador SSC se autoincrementa durante la operaci&oacute;n.
     * @param unprotectedApdu APDU desprotegida (en claro)
     * @param keyCipher Clave sim&eacute;trica de cifrado
     * @param keyMac Clave sim&eacute;trica para el MAC
     * @param sendSequenceCounter Contador de secuencia actual
     * @param cryptoHelper Operador criptogr&aacute;fico
     * @return APDU protegida (cifrada y con MAC)
     * @throws IOException Si ocurren problemas durante los cifrados de la APDU */
    CipheredApdu protectAPDU(final CommandApdu unprotectedApdu,
                                    final byte[] keyCipher,
                                    final byte[] keyMac,
                                    final byte[] sendSequenceCounter,
                                    final CryptoHelper cryptoHelper) throws IOException {

        byte cla = unprotectedApdu.getCla();
        final byte ins = unprotectedApdu.getIns();
        final byte p1 = unprotectedApdu.getP1();
        final byte p2 = unprotectedApdu.getP2();
        final byte[] data = unprotectedApdu.getData();
        final Integer le = unprotectedApdu.getLe();

        final byte[] tlvDataBytes = getDataTlv(
    		data, keyCipher, sendSequenceCounter, cryptoHelper, this.paddingLength
		);
        final byte[] completeDataBytes = getCompleteDataBytes(le, tlvDataBytes);

        // Sumamos la CLA al valor indicativo de APDU cifrada
        cla = (byte) (cla | CLA_OF_PROTECTED_APDU);

        // Componemos los datos necesario para el calculo del MAC del mensaje
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(
    		addPadding7816(
				new byte[] {
					cla, ins, p1, p2
				},
				this.paddingLength
			)
		);
        baos.write(completeDataBytes);
        final byte[] encryptedDataPadded = addPadding7816(baos.toByteArray(), this.paddingLength);

        // Calculamos el valor MAC para la autenticacion de los datos
        final byte[] mac = generateMac(
    		encryptedDataPadded,
    		sendSequenceCounter,
    		keyMac,
    		cryptoHelper
		);

        return new CipheredApdu(cla, ins, p1, p2, completeDataBytes, mac);
    }

    protected abstract byte[] encryptData(final byte[] data,
    		                              final byte[] key,
    		                              final byte[] ssc,
    		                              final CryptoHelper cryptoHelper) throws IOException;

    /** Agrega un relleno (<i>padding</i>) a un array de bytes conforme las especificaciones ISO 7816.
     * Esto es, se agrega un byte <code>0x80</code> al array y se completa con bytes <code>0x00</code> hasta que el
     * array es m&uacute;ltiplo de 8.
     * @param data Datos a los que agregar el relleno.
     * @param size Longitud de la cual debe ser m&uacute;ltiplo el tama&ntilde;o de los datos de salida.
     * @return Datos con relleno. */
    protected static byte[] addPadding7816(final byte[] data, final int size) {
        final byte[] paddedData = new byte[(data.length / size + 1) * size];
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

    /** Aplica el algoritmo para la generaci&oacute;n de la MAC del mensaje.
     * @param dataPadded Datos sobre los que generar la MAC.
     * @param ssc Contador de secuencia de la operaci&oacute;n.
     * @param kMac Clave necesaria para la operaci&oacute;n (algoritmo dependiente de la implementaci&oacute;n).
     * @param cryptoHelper Manejador para la realizaci&oacute;n de las operaciones criptogr&aacute;ficas.
     * @return Clave de autenticaci&oacute;n de los datos.
     * @throws IOException Si hay errores de entrada / salida. */
    protected abstract byte[] generateMac(final byte[] dataPadded,
                                          final byte[] ssc,
                                          final byte[] kMac,
                                          final CryptoHelper cryptoHelper) throws IOException;

    abstract ResponseApdu decryptResponseApdu(final ResponseApdu responseApdu,
			final byte[] keyCipher,
			final byte[] ssc,
			final byte[] kMac,
			final CryptoHelper cryptoHelper) throws IOException;

    private static void wipeByteArray(final byte[] in) {
    	if (in != null) {
    		for (int i=0; i<in.length; i++) {
    			in[i] = '\0';
    		}
    	}
    }

    private static byte[] getCompleteDataBytes(final Integer le, final byte[] tlvDataBytes) {

        // Si hay campo Le calculamos el TLV con ellos
        byte[] tlvLeBytes = new byte[0];
        if (le != null) {
            tlvLeBytes = new Tlv(
        		TAG_LE_TLV,
        		new byte[] {
    				le.byteValue()
        		}
    		).getBytes();
        }

        // Concatenamos los TLV de datos y Le para obtener el cuerpo de la nueva APDU
        final byte[] completeDataBytes = new byte[tlvDataBytes.length + tlvLeBytes.length];
        System.arraycopy(tlvDataBytes, 0, completeDataBytes, 0, tlvDataBytes.length);
        System.arraycopy(tlvLeBytes, 0, completeDataBytes, tlvDataBytes.length, tlvLeBytes.length);

        return completeDataBytes;
    }

	private byte[] getDataTlv(final byte[] data,
			                  final byte[] keyCipher,
			                  final byte[] sendSequenceCounter,
			                  final CryptoHelper cryptoHelper,
			                  final int paddingSize) throws IOException {

		// Si hay datos calculamos el TLV con estos datos cifrados
		if (data != null && data.length > 0) {
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(TLV_VALUE_PREFIX_TO_MAC);
			final byte[] paddedData = addPadding7816(data, paddingSize);
			baos.write(encryptData(paddedData, keyCipher, sendSequenceCounter, cryptoHelper));

			// Sobrescribimos los datos de la APDU inmediatamente despues de cifrarla, para que este
			// el minimo tiempo en memoria. Como los arrays son mutables con escribir esta copia se
			// sobreescriben todas las referencias.
			wipeByteArray(paddedData);
			wipeByteArray(data);

			return new Tlv(TAG_DATA_TLV, baos.toByteArray()).getBytes();
		}
		return new byte[0];
	}

}
