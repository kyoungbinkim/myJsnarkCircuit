package examples.generators;

import java.math.BigInteger;
import java.util.Random;

import util.Util;
import circuit.auxiliary.LongElement;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.LongIntegerModGadget;


/*
*                       256bits n       512bits n       1024 bits n
*    constrain       :  ~50 million     ~200 million    x
*    proving time    :  11  sec         50  sec         x
*    total time      :  55  sec         240 sec         x
*

public class rsaEnc extends CircuitGenerator {

    private Random rand = new Random(0);
    private static BigInteger p;        //             모르는 값
    private static BigInteger q;        //             모르는 값
    private static BigInteger n;        // p * q
    private static BigInteger order;    // (p-1)*(q-1) 모르는 값 
    public static BigInteger pk;        // e
    private static BigInteger sk;       // d           모르는 값
    private static BigInteger cipherText;   // m^e
    public static BigInteger message = new BigInteger("960325");

    private int nLength;                // n bit length
 
    private LongElement nLongElement;
    private LongElement pkLongElement;
    private LongElement mLongElement;
    private LongElement cLongElement;

    // size : p,q bit len
    public rsaEnc(String circuitName, int pqBitSize) {
        super(circuitName);
        this.nLength = pqBitSize * 2;
        rsaSetup(pqBitSize);
	}

	@Override
	protected void buildCircuit() {
        nLongElement = createLongElementInput(nLength, "n");
        pkLongElement = createLongElementInput(nLength, "pk");
        mLongElement = createLongElementInput(nLength, "message");
        cLongElement = createLongElementInput(nLength, "c");

        
        LongElement calculated_cLongElement = pow(mLongElement, pkLongElement, nLongElement);
        // cLongElement.makeOutput("c");
        // calculated_cLongElement.makeOutput("calc c");
        cLongElement.assertEquality(calculated_cLongElement);
    }


    /*
        Long Element로 구현하면 비트 길이의 제약이 없
        a^b mod n
    */
    LongElement pow(LongElement a, LongElement b, LongElement n){
        Wire[] bBitWireArray = b.getBits(nLength).asArray();
        LongElement square = a;
        LongElement result = new LongElement(oneWire.getBitWires(nLength));
        LongIntegerModGadget longintegetmodgadget;

        for(int i=0; i<nLength; i++){

            LongElement tmp = new LongElement(bBitWireArray[i].isEqualTo(zeroWire).getBitWires(1));
            LongElement tmp2 = new LongElement(bBitWireArray[i].getBitWires(1)).mul(square);

            longintegetmodgadget = new LongIntegerModGadget(result.mul(tmp2.add(tmp)), n, true);
            result = longintegetmodgadget.getRemainder();

            LongElement tmp3 = square.mul(square);
            longintegetmodgadget = new LongIntegerModGadget(tmp3, n, false);
            square = longintegetmodgadget.getRemainder();
        }
        return result;
    }



	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		
        circuitEvaluator.setWireValue(nLongElement, n, LongElement.CHUNK_BITWIDTH);
        circuitEvaluator.setWireValue(pkLongElement, pk, LongElement.CHUNK_BITWIDTH);
        circuitEvaluator.setWireValue(mLongElement, message, LongElement.CHUNK_BITWIDTH);
        circuitEvaluator.setWireValue(cLongElement, cipherText, LongElement.CHUNK_BITWIDTH);

	}


    private void rsaSetup(int bitSize){
        p = BigInteger.probablePrime(bitSize, rand);
        q = BigInteger.probablePrime(bitSize, rand);
        while(p.multiply(q).bitLength() > bitSize*2){
            System.out.println("pick p q");
            p = BigInteger.probablePrime(bitSize, rand);
            q = BigInteger.probablePrime(bitSize, rand);
        }
        n = p.multiply(q);
        order = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        System.out.println("p bit len : " + Integer.toString(p.bitLength()));
        System.out.println("q bit len : " + Integer.toString(q.bitLength()));
        System.out.println("n bit len : " + Integer.toString(n.bitLength()));

        pk = new BigInteger(bitSize*2, rand).mod(order);
        while(order.gcd(pk).compareTo(BigInteger.ONE) != 0){
            pk = new BigInteger(bitSize*2, rand).mod(order);
        }
        sk = pk.modInverse(order);   

        
    }


    private static BigInteger rsaEncryption(BigInteger M){
        BigInteger c = M.modPow(pk, n);
        System.out.println("enc : " + c.toString());
        return c;
    }
    
	public static void main(String[] args) throws Exception {
        
		rsaEnc generator = new rsaEnc("RSA enc", 256);

        cipherText = rsaEncryption(message);
        
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}
