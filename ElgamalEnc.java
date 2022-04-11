package examples.generators;

import java.math.BigInteger;
import java.util.Random;
import java.nio.charset.StandardCharsets;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;

public class ElgamalEnc extends CircuitGenerator {
    
    private static Random rand;
    
    private static BigInteger p = Config.FIELD_PRIME;       // set fieldPeime
    private static BigInteger g = new BigInteger("5");      // set generator
    private static BigInteger r;        // declare rand;
    private static BigInteger sk;       // 원래 없어야함
    public static BigInteger pk;        // 원래는 input으로 받아야한다.

    private static String s = "hello";
    private static BigInteger Message = new BigInteger(s.getBytes(StandardCharsets.US_ASCII));
    private static BigInteger[] CipherText = new BigInteger [2];

	private Wire[] c;
    private Wire pkWire;
    private Wire gWire;
    private Wire rWire;
    private Wire mWire;

    public ElgamalEnc(String circuitName, int seed) {
        super(circuitName);
        rand = new Random(seed);
        ElgamalSetup();
	}

	@Override
	protected void buildCircuit() {
        gWire = createInputWire("generator Wire");
        c = createInputWireArray(2, "cipher text");
		pkWire = createInputWire("pk wire");

        rWire = createProverWitnessWire("r Wire");
        mWire = createProverWitnessWire("Message wire");
    

        Wire c1_ = pow(gWire, rWire);   // c1 = g^r
        addEqualityAssertion(c1_, c[0], "c1 error");

        Wire c2_ = pow(pkWire, rWire).mul(mWire);   // c2 = pk^r * M
        addEqualityAssertion(c2_, c[1], "c2 error");
	}

    // square and multiply
    Wire pow(Wire a, Wire b){

        Wire[] bBitArray = b.getBitWires(Config.LOG2_FIELD_PRIME).asArray();
        Wire tmp = oneWire.mul(a);
        Wire result = oneWire;

        for (int i=0; i < bBitArray.length ; i++){
            // if bBit == 1 :  check = tmp
            // if bBit == 0 :  check = 1
            Wire check = bBitArray[i].mul(tmp).add(bBitArray[i].isEqualTo(zeroWire));
            result = result.mul(check);

            tmp = tmp.mul(tmp);
        }


        return result;
    }

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(pkWire, pk);
        circuitEvaluator.setWireValue(gWire, g);
        circuitEvaluator.setWireValue(rWire, r);
        circuitEvaluator.setWireValue(mWire, Message);
        circuitEvaluator.setWireValue(c[0], CipherText[0]);
        circuitEvaluator.setWireValue(c[1], CipherText[1]);
	}

    private void ElgamalSetup(){
        sk = new BigInteger(254, rand).mod(p);
        pk = g.modPow(sk, p);

        System.out.println("sk : " + pk.toString());
        System.out.println("pk : " + sk.toString());
    }
    
    private static BigInteger[] ElgamalEncryption(BigInteger M){
        BigInteger[] c = new BigInteger[2];

        r =  new BigInteger(254, rand).mod(p);
		
        c[0] = g.modPow(r, p);                      // c1 = g^r mod p
        c[1] = pk.modPow(r, p).multiply(M).mod(p);  // c2  = pk^r * M mod p

        System.out.println("Message : "+ M.toString());
        System.out.println("r : " + r.toString());
        System.out.println("c[0] : " + c[0].toString());
        System.out.println("c[1] : " + c[1].toString());

        return c;
    }

    private static void Enc(){
        CipherText = ElgamalEncryption(Message);
        return;
    }

	public static void main(String[] args) throws Exception {
        
		ElgamalEnc generator = new ElgamalEnc("elgamal enc", 12);

        Enc();

		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}