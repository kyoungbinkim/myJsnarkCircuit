package examples.generators;

import util.Util;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;

public class hashTimeTest extends CircuitGenerator{
	
    private int inputBits;
    private int inputWireNum;

    private int wireSize = 256;

    private Wire[] inputWire;

    public hashTimeTest(String circuitName, int _inputBits) {
		super(circuitName);
		this.inputBits= _inputBits;
        if (_inputBits % wireSize == 0)
            this.inputWireNum = (int) _inputBits/wireSize;
        else
            this.inputWireNum = (int) _inputBits/wireSize +1;
        System.out.println("input BIts : "+ Integer.toString(_inputBits));
        System.out.println("inputWireNum  :  " + Integer.toString(inputWireNum));
	}

    @Override
    protected void buildCircuit() {
        inputWire = createInputWireArray(inputWireNum, "input Wires");

        // Wire[] inputBitsWires = new Wire[wireSize * inputWireNum];

        // for (int i=0; i<inputWireNum; i++){
        //     Wire[] tmp = inputWire[i].getBitWires(wireSize).asArray();
        //     for (int j=0; j<wireSize; j++){
        //         inputBitsWires[i*wireSize + j] = tmp[j];
        //     }
        // }

        SHA256Gadget sha2gadget;

        sha2gadget = new SHA256Gadget(inputWire, wireSize, (int) wireSize*inputWireNum/8, false, true);
        makeOutputArray(sha2gadget.getOutputWires(), "sha output");

    }


    @Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        for (int i = 0; i < inputWireNum; i++) {
			circuitEvaluator.setWireValue(inputWire[i], Util.nextRandomBigInteger(Config.FIELD_PRIME));
		}
	}
    public static void main(String[] args) throws Exception {
		
		hashTimeTest generator = new hashTimeTest("hash Test time", 256);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}
}
