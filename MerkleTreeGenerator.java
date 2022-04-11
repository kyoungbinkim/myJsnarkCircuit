package examples.generators;

import util.Util;

import java.math.BigInteger;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;

public class MerkleTreeGenerator extends CircuitGenerator{
	private Wire[] leafWires;
	private int treeHeight;
	private int hashDigestDimension = 8;

    private int leafBitWidth;
    private int leafNum;
    private int totalWireNum; 


    public MerkleTreeGenerator(String circuitName, int _treeHeight, int _leafBitWidth) {
		super(circuitName);
		this.treeHeight = _treeHeight;
        this.leafNum = (int) Math.pow(2,treeHeight); // 2^n
        this.totalWireNum = this.leafNum * 2 - 1; // 등비수열 합  a(r^n - 1) / (r-1)   (1 + 2^1 + 2^2 + .... + 2^n)
        this.leafBitWidth = _leafBitWidth;
	}

    @Override
    protected void buildCircuit() {

        leafWires = createInputWireArray(leafNum);
        makeOutputArray(leafWires, "input Wires");
        
        Wire[] outputWires = new Wire[totalWireNum * hashDigestDimension];

        SHA256Gadget sha2gadget;

        // leaf Hash 
        for(int i=0; i< leafNum; i++){
            Wire[] temp = leafWires[i].getBitWires(leafBitWidth).asArray();
            sha2gadget = new SHA256Gadget(temp, 1, leafBitWidth/8, false, true);
            Wire[] hashOutput = sha2gadget.getOutputWires();
            for (int j=0; j<hashDigestDimension; j++){
                outputWires[(totalWireNum - leafNum + i)*8 + j] = hashOutput[j];
            }
        }


        for(int i = totalWireNum - leafNum - 1; i>=0; i--){
            Wire[] temp2 = new Wire[hashDigestDimension*2]; // 16
            for (int j=0; j<hashDigestDimension*2;j++){
                temp2[j] =  outputWires[8 * (i*2 + 1) + j]; // array tree : child node = parent * 2 + 1
            }

            Wire[] temp3 = new WireArray(temp2).getBits(32).asArray();
            sha2gadget = new SHA256Gadget(temp3, 1, 64, false, true); // total Byte : 32 * 16 / 8
            Wire[] hashOutput = sha2gadget.getOutputWires();
            for(int j=0; j<hashDigestDimension; j++){
                outputWires[i*8 +j] = hashOutput[j];
            }
        }
        makeOutputArray(outputWires, "outputWires");
    }


    @Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        for(int i=0; i < leafNum; i++){
            // 20 - 53 - 86 - 119
            circuitEvaluator.setWireValue(leafWires[i], new BigInteger(Integer.toString(20 + i*33)));
        }
	}
    public static void main(String[] args) throws Exception {
		
		MerkleTreeGenerator generator = new MerkleTreeGenerator("MerkleTreeGen_2", 2, 32);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}
}
