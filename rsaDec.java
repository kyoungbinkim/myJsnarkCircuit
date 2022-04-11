package examples.generators;

import java.math.BigInteger;
import java.util.Random;
import java.nio.charset.StandardCharsets;

import util.Util;
import circuit.auxiliary.LongElement;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.ModGadget;

/*
    256bits p,q     512bits n
    constrain       :   약 200만개   512bit 지수승
    proving time    :   50sec  
*/

public class rsaDec extends CircuitGenerator {

    private Random rand = new Random(0);
    private static BigInteger p;        
    private static BigInteger q;        
    private static BigInteger n;        // p * q
    private static BigInteger order;    // (p-1) * (q-1)
    public static BigInteger pk;        // e
    private static BigInteger sk;       // d
    private static BigInteger cipherText = new BigInteger("3814131678415201177304543701723813930960506828092320199734903490445051846672373530664772742052689180801312612221921878767990815583459655782999214922500027");
    public static BigInteger message;

    private int nLength;

    private Wire nWire;
    private Wire pkWire;
    private Wire skWire;
    private Wire mWire;
    private Wire cWire;

    private LongElement nLongElement;
    private LongElement pkLongElement;
    private LongElement skLongElement;
    private LongElement mLongElement;
    private LongElement cLongElement;

    // enc : 3814131678415201177304543701723813930960506828092320199734903490445051846672373530664772742052689180801312612221921878767990815583459655782999214922500027
    
    public rsaDec(String circuitName, int size) {
        super(circuitName);
        this.nLength = 2*size;
        rsaSetup(size);
	}

	@Override
	protected void buildCircuit() {
        nLongElement = createLongElementInput(nLength, "n");
        pkLongElement = createLongElementInput(nLength, "pk");
        mLongElement = createLongElementInput(nLength, "message");
        cLongElement = createLongElementInput(nLength, "c");

        skLongElement = createLongElementProverWitness(nLength, "sk");

        LongElement calculated_mLongElement = pow(cLongElement, skLongElement, nLongElement);
        calculated_mLongElement.assertEquality(mLongElement);
    }

    // square and multiply
    
    Wire pow(Wire a, Wire b, Wire n){
        //a^b mod n
        Wire[] bBitArray = b.getBitWires(Config.LOG2_FIELD_PRIME).asArray();
        Wire tmp = oneWire.mul(a);
        Wire result = oneWire;
        ModGadget modgadget;

        for (int i=0; i < bBitArray.length ; i++){
            // if bBit == 1 :  check = tmp
            // if bBit == 0 :  check = 1
            Wire check = bBitArray[i].mul(tmp).add(bBitArray[i].isEqualTo(zeroWire));
            modgadget = new ModGadget(result.mul(check), n, 126);
            result = modgadget.getOutputWires()[0];


            modgadget = new ModGadget(tmp.mul(tmp), n, 126);
            tmp = modgadget.getOutputWires()[0]; /// a^1 a^2 a^4 ....
        }

        return result;
    }

    LongElement pow(LongElement a, LongElement b, LongElement n){
        Wire[] bBitWireArray = b.getBits(nLength).asArray();
        LongElement square = a;
        LongElement result = new LongElement(oneWire.getBitWires(nLength));
        LongIntegerModGadget longintegetmodgadget;

        for(int i=0; i<nLength; i++){

            LongElement tmp = new LongElement(bBitWireArray[i].isEqualTo(zeroWire).getBitWires(1));
            LongElement tmp2 = new LongElement(bBitWireArray[i].getBitWires(1)).mul(square);

            longintegetmodgadget = new LongIntegerModGadget(result.mul(tmp2.add(tmp)), n, false);
            result = longintegetmodgadget.getRemainder();

            LongElement tmp3 = square.mul(square);
            longintegetmodgadget = new LongIntegerModGadget(tmp3, n, true);
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
        circuitEvaluator.setWireValue(skLongElement, sk, LongElement.CHUNK_BITWIDTH);
	}


    private void rsaSetup(int size){
        p = BigInteger.probablePrime(size, rand);
        q = BigInteger.probablePrime(size, rand);
        while(p.multiply(q).bitLength() > size*2){
            System.out.println("pick p q");
            p = BigInteger.probablePrime(size, rand);
            q = BigInteger.probablePrime(size, rand);
        }
        n = p.multiply(q);
        order = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        System.out.println("p bit len : " + Integer.toString(p.bitLength()));
        System.out.println("q bit len : " + Integer.toString(q.bitLength()));
        System.out.println("n bit len : " + Integer.toString(n.bitLength()));

        pk = new BigInteger(size*2, rand).mod(order);
        while(order.gcd(pk).compareTo(BigInteger.ONE) != 0){
            pk = new BigInteger(size*2, rand).mod(order);
        }
        sk = pk.modInverse(order);   

        
    }


    private static BigInteger rsaDecryption(BigInteger C){
        BigInteger m = C.modPow(sk, n);
        System.out.println("Dec m : " + m.toString());
        return m;
    }
    
	public static void main(String[] args) throws Exception {
        
		rsaDec generator = new rsaDec("RSA dec", 256);

        message = rsaDecryption(cipherText);
        
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}
