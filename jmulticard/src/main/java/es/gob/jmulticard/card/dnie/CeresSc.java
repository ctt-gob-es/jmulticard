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
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV2Connection;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetComputationApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Pkcs15Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.CardMessages;
import es.gob.jmulticard.card.CompressionUtils;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PinException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants;
import es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Tarjeta FNMT CERES con canal seguro.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CeresSc extends Dnie {

	private static final byte[] ATR_MASK_TC = new byte[] {
		(byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};
	private static final Atr ATR_TC = new Atr(new byte[] {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x46, (byte) 0x4E, (byte) 0x4d,
        (byte) 0x54, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x90, (byte) 0x00
    }, ATR_MASK_TC);

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
     *                                 proporciona cerrada y no es posible abrirla.
	 * @throws InvalidCardException Si la tarjeta no es una CERES 4.30 o superior. */
	public CeresSc(final ApduConnection conn,
			final PasswordCallback pwc,
			final CryptoHelper cryptoHelper,
			final CallbackHandler ch) throws ApduConnectionException, InvalidCardException {
		super(conn, pwc, cryptoHelper, ch);
		checkAtr(conn.reset());
	}

	@Override
	public X509Certificate getCertificate(final String alias) {
		return this.certs.get(alias);
	}

	@Override
	protected byte[] signOperation(final byte[] data,
                                   final String algorithm,
                                   final PrivateKeyReference privateKeyReference) throws CryptoCardException,
                                                                                         PinException {
		openSecureChannelIfNotAlreadyOpened();

        ResponseApdu res;
        try {
            CommandApdu apdu = new MseSetComputationApduCommand(
        		(byte) 0x00, ((DniePrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath(),
        		null
    		);

            res = getConnection().transmit(apdu);
            if (!res.isOk()) {
                throw new DnieCardException(
            		"Error en el establecimiento de las clave de firma con respuesta: " + res.getStatusWord(), res.getStatusWord() //$NON-NLS-1$
        		);
            }

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
				new ByteArrayInputStream(
					CompressionUtils.deflate(
						selectFileByLocationAndRead(l)
					)
				)
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

    /** Establece y abre el canal seguro CWA-14890 si no lo estaba ya hecho.
     * @throws CryptoCardException Si hay problemas en el proceso.
     * @throws PinException Si el PIN usado para la apertura de canal no es v&aacute;lido o no se ha proporcionado
     * 						un PIN para validar.  */
    @Override
	protected void openSecureChannelIfNotAlreadyOpened() throws CryptoCardException, PinException {
        // Abrimos el canal seguro si no lo esta ya
        if (!isSecurityChannelOpen()) {
        	// Aunque el canal seguro estuviese cerrado, podria si estar enganchado
            if (!(getConnection() instanceof Cwa14890Connection)) {
            	final ApduConnection secureConnection;
        		secureConnection = new Cwa14890OneV2Connection(
            		this,
            		getConnection(),
            		this.cryptoHelper,
            		getCwa14890PublicConstants(),
            		getCwa14890PrivateConstants()
        		);
                try {
                    setConnection(secureConnection);
                }
                catch (final ApduConnectionException e) {
                    throw new CryptoCardException("Error en el establecimiento del canal seguro: " + e, e); //$NON-NLS-1$
                }
            }
            try {
                verifyPin(getInternalPasswordCallback());
            }
            catch (final ApduConnectionException e) {
                throw new CryptoCardException("Error en la apertura del canal seguro: " + e, e); //$NON-NLS-1$
            }
        }
    }

    @Override
	protected boolean needAuthorizationToSign() {
    	return false;
    }

    @Override
    protected String getPinMessage(final int retriesLeft) {
    	return CardMessages.getString("Gen.0", Integer.toString(retriesLeft)); //$NON-NLS-1$
    }

    private static void checkAtr(final byte[] atrBytes) throws InvalidCardException {
    	final Atr tmpAtr = new Atr(atrBytes, ATR_MASK_TC);
    	if (ATR_TC.equals(tmpAtr)) {
    		if (atrBytes[15] >= (byte) 0x04 && atrBytes[16] >= (byte) 0x30) {
    			LOGGER.info(
					"Encontrada TC CERES en version " + //$NON-NLS-1$
						HexUtils.hexify(new byte[] { atrBytes[15] }, false) + "." + HexUtils.hexify(new byte[] { atrBytes[16] }, false) //$NON-NLS-1$
				);
    			return;
    		}
    	}
    	throw new InvalidCardException("CERES", ATR_TC, atrBytes); //$NON-NLS-1$
    }
}
