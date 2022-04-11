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

public class ElgamalDec extends CircuitGenerator {
    
    private static Random rand;
    
    private static BigInteger p = Config.FIELD_PRIME;       // set fieldPeime
    private static BigInteger g = new BigInteger("5");      // set generator
    private static BigInteger sk;
    public static BigInteger pk;

    private static String s = "hello";
    private static BigInteger Message = new BigInteger(s.getBytes(StandardCharsets.US_ASCII));
    private static BigInteger[] CipherText = new BigInteger [2];

	private Wire c1InverseWire;
    private Wire c2Wire;
    private Wire pkWire;
    private Wire skWire;
    private Wire gWire;
    private Wire mWire;

    // c[0] : 19864469837388005762443942614633110854005420942056894762929762692534361048008
    // c[1] : 545120494707816529337916764788516187372376127658799426325033959296773692740

    public ElgamalDec(String circuitName, int seed) {
        super(circuitName);
        rand = new Random(seed);
        ElgamalSetup();

        this.CipherText[0] = new BigInteger("19864469837388005762443942614633110854005420942056894762929762692534361048008");
        this.CipherText[1] = new BigInteger("545120494707816529337916764788516187372376127658799426325033959296773692740");
	}

	@Override
	protected void buildCircuit() {
        gWire = createInputWire("generator Wire");
        c1InverseWire = createInputWire("c1 inverse Wire");
        c2Wire = createInputWire("c2 Wire");
		pkWire = createInputWire("pk wire");
        mWire = createInputWire("Message wire");

        skWire = createProverWitnessWire("sk Wire");

        Wire pk_ = pow(gWire, skWire);  // check  pk == g^sk
        addEqualityAssertion(pk_, pkWire, "pk error");

        Wire m_ = pow(c1InverseWire, skWire).mul(c2Wire);   // check c2 / c1^sk
        addEqualityAssertion(m_, mWire, "M error");
	}

    // square and multiply
    Wire pow(Wire a, Wire b){
        //a^b 
        Wire[] bBitArray = b.getBitWires(Config.LOG2_FIELD_PRIME).asArray();
        Wire tmp = oneWire.mul(a);
        Wire result = oneWire;

        for (int i=0; i < bBitArray.length ; i++){
            // if bBit == 1 :  check = tmp
            // if bBit == 0 :  check = 1
            Wire check = bBitArray[i].mul(tmp).add(bBitArray[i].isEqualTo(zeroWire));
            result = result.mul(check);

            tmp = tmp.mul(tmp); /// a^1 a^2 a^4 ....
        }

        return result;
    }

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(pkWire, pk);
        circuitEvaluator.setWireValue(gWire, g);
        circuitEvaluator.setWireValue(mWire, Message);
        circuitEvaluator.setWireValue(c1InverseWire, CipherText[0].modInverse(p));
        circuitEvaluator.setWireValue(c2Wire, CipherText[1]);
        circuitEvaluator.setWireValue(skWire, sk);
	}

    private void ElgamalSetup(){
        sk = new BigInteger(254, rand).mod(p);
        pk = g.modPow(sk, p);

        System.out.println("sk : " + pk.toString());
        System.out.println("pk : " + sk.toString());
    }   

    // 확인용으로 구현
    private static void ElgamalDecryption(BigInteger[] c){
        BigInteger m = c[1].multiply(c[0].modInverse(p).modPow(sk, p)).mod(p);
        System.out.println("dec Message : " + m.toString());
    }
    
	public static void main(String[] args) throws Exception {
        
		ElgamalDec generator = new ElgamalDec("elgamal dec", 12);
        ElgamalDecryption(CipherText);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}