package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.encoders.Hex;

public class SecT131R2Curve extends AbstractF2m
{
    private static final int SECT131R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;
    private static final ECFieldElement[] SECT131R2_AFFINE_ZS = new ECFieldElement[] { new SecT131FieldElement(ECConstants.ONE) }; 

    protected SecT131R2Point infinity;

    public SecT131R2Curve()
    {
        super(131, 2, 3, 8);

        this.infinity = new SecT131R2Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("03E5A88919D7CAFCBF415F07C2176573B2")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("04B8266A46C55657AC734CE38F018F2192")));
        this.order = new BigInteger(1, Hex.decodeStrict("0400000000000000016954A233049BA98F"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SECT131R2_DEFAULT_COORDS;
    }

    @Override
	protected ECCurve cloneCurve()
    {
        return new SecT131R2Curve();
    }

    @Override
	public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_LAMBDA_PROJECTIVE:
            return true;
        default:
            return false;
        }
    }

    @Override
	public int getFieldSize()
    {
        return 131;
    }

    @Override
	public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT131FieldElement(x);
    }

    @Override
	protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecT131R2Point(this, x, y);
    }

    @Override
	protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecT131R2Point(this, x, y, zs);
    }

    @Override
	public ECPoint getInfinity()
    {
        return infinity;
    }

    @Override
	public boolean isKoblitz()
    {
        return false;
    }

    public int getM()
    {
        return 131;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 3;
    }

    public int getK3()
    {
        return 8;
    }

    @Override
	public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 3;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat192.copy64(((SecT131FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat192.copy64(((SecT131FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
            }
        }

        return new AbstractECLookupTable()
        {
            @Override
			public int getSize()
            {
                return len;
            }

            @Override
			public ECPoint lookup(int index)
            {
                long[] x = Nat192.create64(), y = Nat192.create64();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    long MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return createPoint(x, y);
            }

            @Override
			public ECPoint lookupVar(int index)
            {
                long[] x = Nat192.create64(), y = Nat192.create64();
                int pos = index * FE_LONGS * 2;

                for (int j = 0; j < FE_LONGS; ++j)
                {
                    x[j] = table[pos + j];
                    y[j] = table[pos + FE_LONGS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(long[] x, long[] y)
            {
                return createRawPoint(new SecT131FieldElement(x), new SecT131FieldElement(y), SECT131R2_AFFINE_ZS);
            }
        };
    }
}
