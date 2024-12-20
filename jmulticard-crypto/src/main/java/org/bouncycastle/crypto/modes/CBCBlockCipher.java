package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DefaultMultiBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
 */
public class CBCBlockCipher
    extends DefaultMultiBlockCipher
    implements CBCModeCipher
{
    private final byte[]          IV;
    private byte[]          cbcV;
    private byte[]          cbcNextV;

    private final int             blockSize;
    private BlockCipher     cipher = null;
    private boolean         encrypting;

    /**
     * Return a new CBC mode cipher based on the passed in base cipher
     *
     * @param cipher the base cipher for the CBC mode.
     * @return a new CBC mode.
     */
    public static CBCModeCipher newInstance(final BlockCipher cipher)
    {
        return new CBCBlockCipher(cipher);
    }

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of chaining.
     * @deprecated use the CBCBlockCipher.newInstance() static method.
     */
    @Deprecated
	public CBCBlockCipher(
        final BlockCipher cipher)
    {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();

        this.IV = new byte[this.blockSize];
        this.cbcV = new byte[this.blockSize];
        this.cbcNextV = new byte[this.blockSize];
    }

    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    @Override
	public BlockCipher getUnderlyingCipher()
    {
        return this.cipher;
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     *
     * @param encrypting if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    @Override
	public void init(
        final boolean             encrypting,
        CipherParameters    params)
        throws IllegalArgumentException
    {
        final boolean oldEncrypting = this.encrypting;

        this.encrypting = encrypting;

        if (params instanceof ParametersWithIV)
        {
            final ParametersWithIV ivParam = (ParametersWithIV)params;
            final byte[] iv = ivParam.getIV();

            if (iv.length != this.blockSize)
            {
                throw new IllegalArgumentException("initialisation vector must be the same length as block size");
            }

            System.arraycopy(iv, 0, this.IV, 0, iv.length);

            params = ivParam.getParameters();
        }
        else
        {
            Arrays.fill(this.IV, (byte)0);
        }

        reset();

        // if null it's an IV changed only (key is to be reused).
        if (params != null)
        {
            this.cipher.init(encrypting, params);
        }
        else if (oldEncrypting != encrypting)
        {
            throw new IllegalArgumentException("cannot change encrypting state without providing key.");
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/CBC".
     */
    @Override
	public String getAlgorithmName()
    {
        return this.cipher.getAlgorithmName() + "/CBC";
    }

    /**
     * return the block size of the underlying cipher.
     *
     * @return the block size of the underlying cipher.
     */
    @Override
	public int getBlockSize()
    {
        return this.cipher.getBlockSize();
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param in the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    @Override
	public int processBlock(
        final byte[]      in,
        final int         inOff,
        final byte[]      out,
        final int         outOff)
        throws DataLengthException, IllegalStateException
    {
        return this.encrypting ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    @Override
	public void reset()
    {
        System.arraycopy(this.IV, 0, this.cbcV, 0, this.IV.length);
        Arrays.fill(this.cbcNextV, (byte)0);

        this.cipher.reset();
    }

    /**
     * Do the appropriate chaining step for CBC mode encryption.
     *
     * @param in the array containing the data to be encrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private int encryptBlock(
        final byte[]      in,
        final int         inOff,
        final byte[]      out,
        final int         outOff)
        throws DataLengthException, IllegalStateException
    {
        if (inOff + this.blockSize > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        /*
         * XOR the cbcV and the input,
         * then encrypt the cbcV
         */
        for (int i = 0; i < this.blockSize; i++)
        {
            this.cbcV[i] ^= in[inOff + i];
        }

        final int length = this.cipher.processBlock(this.cbcV, 0, out, outOff);

        /*
         * copy ciphertext to cbcV
         */
        System.arraycopy(out, outOff, this.cbcV, 0, this.cbcV.length);

        return length;
    }

    /**
     * Do the appropriate chaining step for CBC mode decryption.
     *
     * @param in the array containing the data to be decrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the decrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private int decryptBlock(
        final byte[]      in,
        final int         inOff,
        final byte[]      out,
        final int         outOff)
        throws DataLengthException, IllegalStateException
    {
        if (inOff + this.blockSize > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        System.arraycopy(in, inOff, this.cbcNextV, 0, this.blockSize);

        final int length = this.cipher.processBlock(in, inOff, out, outOff);

        /*
         * XOR the cbcV and the output
         */
        for (int i = 0; i < this.blockSize; i++)
        {
            out[outOff + i] ^= this.cbcV[i];
        }

        /*
         * swap the back up buffer into next position
         */
        byte[]  tmp;

        tmp = this.cbcV;
        this.cbcV = this.cbcNextV;
        this.cbcNextV = tmp;

        return length;
    }
}
