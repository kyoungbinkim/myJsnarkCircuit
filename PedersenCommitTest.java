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


// to test 64 비트의 256비트 승.

public class PedersenCommitTest extends CircuitGenerator {

    private Random rand = new Random(0);

    private BigInteger p = new BigInteger(Config.FIELD_PRIME.toString());
    private BigInteger g = new BigInteger(253, rand);
    private BigInteger h = new BigInteger(253, rand);
    private BigInteger c;
    private BigInteger m;
    private BigInteger r;
    
    public Wire gWire;
    public Wire hWire;
    public Wire cWire;
    private Wire rWire;
    private Wire mWire;

    // size : p,q bit len
    public PedersenCommitTest(String circuitName) {
        super(circuitName);   
        pedersenCommit();
	}

	@Override
	protected void buildCircuit() {
        
        gWire = createInputWire("g");
        hWire = createInputWire("h");
        cWire = createInputWire("c");

        rWire = createProverWitnessWire("r");
        mWire = createProverWitnessWire("m");

        Wire computed_c= pow(gWire,mWire, 64).mul(pow(hWire,rWire, Config.LOG2_FIELD_PRIME));
        makeOutput(computed_c, "computed commit");
        makeOutput(cWire, "commit");

        addEqualityAssertion(computed_c, c, "invalid commit");
    }


    // curve field prime 똑같이 사용한다.
    Wire pow(Wire a, Wire b, int b_len) {
        Wire[] bBitWires = b.getBitWires(b_len).asArray();
        Wire sq = oneWire.mul(a);
        Wire ret = oneWire;

        for(int i=0; i<b_len; i++){
            // 0 --> 1
            // 1 --> sq

            Wire tmp  =  bBitWires[i].isEqualTo(zeroWire).add(bBitWires[i].mul(sq));

            ret = ret.mul(tmp);
            sq = sq.mul(sq); 
        }
        return ret;
    }
    
    BigInteger pedersenCommit(){
        m = new BigInteger(63, rand);
        r = new BigInteger(253, rand);

        // c = g^m * h^r
        c = g.modPow(m, p).multiply(h.modPow(r, p)).mod(p);

        System.out.println("p : \t" + p.toString());
        System.out.println("m : \t" + m.toString());
        System.out.println("commit : " + c.toString());
        System.out.println("p len : "+ Config.LOG2_FIELD_PRIME);

        return c;
    }

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		circuitEvaluator.setWireValue(gWire, g);
        circuitEvaluator.setWireValue(hWire, h);
        circuitEvaluator.setWireValue(cWire, c);
        circuitEvaluator.setWireValue(rWire, r);
        circuitEvaluator.setWireValue(mWire, m);
	}

	public static void main(String[] args) throws Exception {
		PedersenCommitTest generator = new PedersenCommitTest("PedersenCommitTest");

		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
    }
}
