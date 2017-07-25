package es.gob.jmulticard.card.dnie;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890Connection;
import es.gob.jmulticard.apdu.dnie.MseSetSignatureKeyApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Pkcs15Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta FNMT CERES con canal seguro.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CeresSc extends Dnie {

    /** Certificados de la tarjeta indexados por su alias. */
    private Map<String, X509Certificate> certs;

    /** Alias de los certificados de la tarjeta indexados por el identificador interno del certificado (pasado de <code>byte[]</code> a <code>String</code>). */
    private Map<String, String> aliasByCertAndKeyId;

    /** Referencias a las claves privadas de la tarjeta indexadas por el alias de su certificado asociado. */
    private Map<String, DniePrivateKeyReference> keyReferences;

	/** Construye una tarjeta FNMT CERES con canal seguro.
     * @param conn Conexi&oacute;n con la tarjeta.
     * @param pwc <i>PasswordCallback</i> para obtener el PIN de la TIF.
     * @param cryptoHelper Funcionalidades criptogr&aacute;ficas de utilidad que pueden
     *                     variar entre m&aacute;quinas virtuales.
     * @param ch Gestor de <i>callbacks</i> para la solicitud de datos al usuario.
     * @throws ApduConnectionException Si la conexi&oacute;n con la tarjeta se
     *                                 proporciona cerrada y no es posible abrirla.*/
	public CeresSc(final ApduConnection conn,
			final PasswordCallback pwc,
			final CryptoHelper cryptoHelper,
			final CallbackHandler ch) throws ApduConnectionException {
		super(conn, pwc, cryptoHelper, ch);
	}

	@Override
	protected byte[] signOperation(final byte[] data,
                                   final String algorithm,
                                   final PrivateKeyReference privateKeyReference) throws CryptoCardException,
                                                                                         PinException {
		openSecureChannelIfNotAlreadyOpened();

        ResponseApdu res;
        try {
            CommandApdu apdu = new MseSetSignatureKeyApduCommand(
        		(byte) 0x00, ((DniePrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath()
    		);

            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
            		"Error en el establecimiento de las clave de firma con respuesta: " + res.getStatusWord(), res.getStatusWord() //$NON-NLS-1$
        		);
            }

            // TODO: Modificar esta llamada y la clase DigestInfo para que reciba el algoritmo
            // de digest directamente

            final byte[] digestInfo;
            try {
                digestInfo = DigestInfo.encode(algorithm, data, this.cryptoHelper);
            }
            catch (final IOException e) {
                throw new DnieCardException("Error en el calculo del hash para firmar: " + e, e); //$NON-NLS-1$
            }

            apdu = new PsoSignHashApduCommand((byte) 0x00, digestInfo);
            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
                	"Error durante la operacion de firma con respuesta: " + res.getStatusWord(), res.getStatusWord() //$NON-NLS-1$
                );
            }
        }
        catch(final LostChannelException e) {
            try {
                getConnection().close();
                if (getConnection() instanceof Cwa14890Connection) {
                    setConnection(((Cwa14890Connection) getConnection()).getSubConnection());
                }
            }
            catch (final Exception ex) {
                throw new DnieCardException("No se pudo recuperar el canal seguro para firmar: " + ex, ex); //$NON-NLS-1$
            }
            return signOperation(data, algorithm, privateKeyReference);
        }
        catch (final ApduConnectionException e) {
            throw new DnieCardException("Error en la transmision de comandos a la tarjeta: " + e, e); //$NON-NLS-1$
        }
        return res.getData();
	}

	@Override
	protected Cwa14890PublicConstants getCwa14890PublicConstants() {
		return new CeresScCwa14890Constants();
	}

	@Override
	protected Cwa14890PrivateConstants getCwa14890PrivateConstants() {
		return new CeresScCwa14890Constants();
	}

    /** Carga el certificado de la CA intermedia y las localizaciones del resto de los certificados.
     * @throws ApduConnectionException Si hay problemas en la precarga. */
    @Override
	protected void preloadCertificates() throws ApduConnectionException {
		try {
			preload();
		}
		catch (final Exception e) {
			throw new ApduConnectionException("Error cargando las estructuras iniciales de la tarjeta: " + e, e); //$NON-NLS-1$
		}
    }

    /** Carga la informaci&oacute;n p&uacute;blica con la referencia a las claves de firma. */
    @Override
	protected void loadKeyReferences() {
    	// Vacio, lo hacemos todo en la precarga de certificados
    }

    /** {@inheritDoc} */
    @Override
    public String[] getAliases() {
    	return this.certs.keySet().toArray(new String[0]);
    }

    /** {@inheritDoc} */
    @Override
    public PrivateKeyReference getPrivateKey(final String alias) {
    	return this.keyReferences.get(alias);
    }

	private void preload() throws ApduConnectionException,
	                              Iso7816FourCardException,
	                              IOException,
	                              CertificateException,
	                              Asn1Exception,
	                              TlvException {

		// Nos vamos al raiz antes de nada
		selectMasterFile();

		// Leemos el CDF
		final byte[] cdfBytes = selectFileByLocationAndRead(CDF_LOCATION);

		// Cargamos el CDF
		final Pkcs15Cdf cdf = new Cdf();
		cdf.setDerValue(cdfBytes);

		this.certs = new LinkedHashMap<>(cdf.getCertificateCount());
		this.aliasByCertAndKeyId = new LinkedHashMap<>(cdf.getCertificateCount());

		for (int i = 0; i < cdf.getCertificateCount(); i++) {
			final Location l = new Location(
				cdf.getCertificatePath(i).replace("\\", "").trim() //$NON-NLS-1$ //$NON-NLS-2$
			);
			final X509Certificate cert = (X509Certificate) CERT_FACTORY.generateCertificate(
				new ByteArrayInputStream(deflate(selectFileByLocationAndRead(l)))
			);
			final String alias = i + " " + cert.getSerialNumber(); //$NON-NLS-1$
			this.aliasByCertAndKeyId.put(HexUtils.hexify(cdf.getCertificateId(i), false), alias);
			this.certs.put(alias, cert);
		}

		// Leemos el PrKDF
		final byte[] prkdfValue = selectFileByLocationAndRead(PRKDF_LOCATION);

		// Establecemos el valor del PrKDF
		final PrKdf prkdf = new PrKdf();
		prkdf.setDerValue(prkdfValue);

		this.keyReferences = new LinkedHashMap<>();
		for (int i = 0; i < prkdf.getKeyCount(); i++) {
			final String alias = this.aliasByCertAndKeyId.get(HexUtils.hexify(prkdf.getKeyId(i), false));
			if (alias != null) {
				this.keyReferences.put(
					alias,
					new DniePrivateKeyReference(
						this,
						prkdf.getKeyIdentifier(i),
	            		new Location(prkdf.getKeyPath(i)),
	            		prkdf.getKeyName(i),
	            		prkdf.getKeyReference(i),
	            		((RSAPublicKey)this.certs.get(alias).getPublicKey()).getModulus().bitLength()
					)
				);
			}
		}

		// Sincronizamos claves y certificados
		hideCertsWithoutKey();
	}

	/** Oculta los certificados que no tienen una clave privada asociada. */
	private void hideCertsWithoutKey() {
		final String[] aliases = getAliases();
		for (final String alias : aliases) {
			if (this.keyReferences.get(alias) == null) {
				this.certs.remove(alias);
			}
		}
	}

}
