package examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;

public class ageProofSha2HashUseWitness extends CircuitGenerator {
    
	private Wire myAge;
	private Wire[] myAgeHash;

    private SHA256Gadget sha2Gadget;

    public ageProofSha2HashUseWitness(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		// age(Hash preimage) set as witness
		myAge = createProverWitnessWire("my Age");		
		
		// age set as public input
		// myAge = createInputWire();

		Wire[] myAgeBitArray = myAge.getBitWires(128).asArray();

		// Hash value
		myAgeHash = createInputWireArray(8, "my age Hash");

		// to check Age and Hash 
		Wire result = zeroWire;

		result = myAge.isGreaterThanOrEqual(20, 32);
		addEqualityAssertion(result, new BigInteger("1"), "you're not Adult");

		sha2Gadget = new SHA256Gadget(myAgeBitArray, 1, 16, false, true);
		Wire[] HashOutput = sha2Gadget.getOutputWires();
		

		for (int i=0; i<8; i++){
			result = result.add(HashOutput[i].isEqualTo(myAgeHash[i]));
		}
		addEqualityAssertion(result, new BigInteger("9"), "Hash Input is not correct");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		String _myAge = "27";
		circuitEvaluator.setWireValue(myAge, new BigInteger(_myAge));
		
		circuitEvaluator.setWireValue(myAgeHash[0], new BigInteger("1404699653"));
        circuitEvaluator.setWireValue(myAgeHash[1], new BigInteger("1957037327"));
        circuitEvaluator.setWireValue(myAgeHash[2], new BigInteger("4083699947"));
        circuitEvaluator.setWireValue(myAgeHash[3], new BigInteger("4102700171"));
        circuitEvaluator.setWireValue(myAgeHash[4], new BigInteger("3734196689"));
        circuitEvaluator.setWireValue(myAgeHash[5], new BigInteger("2345150495"));
        circuitEvaluator.setWireValue(myAgeHash[6], new BigInteger("1250137028"));
        circuitEvaluator.setWireValue(myAgeHash[7], new BigInteger("1392173851"));

		//random Input 
        // for (int i=0; i<8; i++){
        //     circuitEvaluator.setWireValue(myAgeHash[i], Util.nextRandomBigInteger(new BigInteger("4294967296"))); // 2^32
        // }
	}

	public static void main(String[] args) throws Exception {

		ageProofSha2HashUseWitness generator = new ageProofSha2HashUseWitness("age Proof Sha2 use witness");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}