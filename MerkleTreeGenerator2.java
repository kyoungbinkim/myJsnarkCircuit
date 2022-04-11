package examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;

public class MerkleTreeGenerator2 extends CircuitGenerator{
	private Wire[] leafWires;
    private int inputDimension;
	private int treeHeight;
	private int hashDigestDimension = 8;

    private int leafBitWidth;
    private int leafNum;
    private int totalWireNum; 


    public MerkleTreeGenerator2(String circuitName, int _treeHeight, int _leafBitWidth, int _inputDimension) {
		super(circuitName);
		this.treeHeight = _treeHeight;
        this.leafNum = (int) Math.pow(2,treeHeight); // 2^n
        this.totalWireNum = this.leafNum * 2 - 1; // 등비수열 합  a(r^n - 1) / (r-1)  <= (1 + 2^1 + 2^2 + .... + 2^n)
        this.leafBitWidth = _leafBitWidth;
        this.inputDimension = _inputDimension;
	}

    @Override
    protected void buildCircuit() {

        leafWires = createInputWireArray(leafNum * inputDimension);
        makeOutputArray(leafWires, "input Wires");

        Wire[][] InputWires = new Wire[leafNum][inputDimension];

        for (int i=0; i<leafNum; i++){
            for (int j=0; j<inputDimension; j++){
                InputWires[i][j] = leafWires[i*8 + j];
            }
        }
        
        Wire[][] outputWires = new Wire[totalWireNum][hashDigestDimension]; // MerkleTreeOutput

        SHA256Gadget sha2gadget;

        // leaf Hash 
        for(int i=0; i< leafNum; i++){
            Wire[] temp = new WireArray(InputWires[i]).getBits(leafBitWidth).asArray();
            sha2gadget = new SHA256Gadget(temp, 1,  inputDimension * leafBitWidth/8, false, true);
            Wire[] hashOutput = sha2gadget.getOutputWires();
            for (int j=0; j<hashDigestDimension; j++){
                outputWires[totalWireNum - leafNum + i][j] = hashOutput[j];
            }
        }


        for(int i = totalWireNum - leafNum - 1; i>=0; i--){
            Wire[] temp2 = new Wire[hashDigestDimension*2]; // 16

            for (int j=0; j<hashDigestDimension;j++){
                temp2[j] =  outputWires[(i*2 + 1)][j]; // 왼쪽 child noded = parent * 2 + 1
            }
            for (int j=0; j<hashDigestDimension; j++){ // 오른쪽 child noded = parent * 2 + 2
                temp2[j + hashDigestDimension] = outputWires[i*2+2][j];
            }

            Wire[] temp3 = new WireArray(temp2).getBits(32).asArray(); // temp2 => bitWires
            sha2gadget = new SHA256Gadget(temp3, 1, 64, false, true); // total Byte : 32 * 16 / 8
            Wire[] hashOutput = sha2gadget.getOutputWires();
            for(int j=0; j<hashDigestDimension; j++){
                outputWires[i][j] = hashOutput[j];
            }
        }

        for (int i=0; i<totalWireNum; i++){
            makeOutputArray(outputWires[i], "outputWires"+Integer.toString(i));
        }
    }


    @Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        for (int i=0; i<inputDimension; i++){
            circuitEvaluator.setWireValue(leafWires[i], new BigInteger("0"));
        }
        for (int i=0; i<inputDimension; i++){
            circuitEvaluator.setWireValue(leafWires[8+i], new BigInteger("1"));
        }
        // cm_old hash value
        circuitEvaluator.setWireValue(leafWires[16], new BigInteger("3105824687"));
        circuitEvaluator.setWireValue(leafWires[17], new BigInteger("3862418437"));
        circuitEvaluator.setWireValue(leafWires[18], new BigInteger("1212064685"));
        circuitEvaluator.setWireValue(leafWires[19], new BigInteger("4072953071"));
        circuitEvaluator.setWireValue(leafWires[20], new BigInteger("1622751769"));
        circuitEvaluator.setWireValue(leafWires[21], new BigInteger("856301769"));
        circuitEvaluator.setWireValue(leafWires[22], new BigInteger("2898601113"));
        circuitEvaluator.setWireValue(leafWires[23], new BigInteger("759242631"));

        for (int i=0; i<inputDimension; i++){
            circuitEvaluator.setWireValue(leafWires[24+i], new BigInteger("3"));
        }
	}

    /*
        [output] Value of Wire # 374646 (cm_old[0]) :: 3105824687
        [output] Value of Wire # 374647 (cm_old[1]) :: 3862418437
        [output] Value of Wire # 374648 (cm_old[2]) :: 1212064685
        [output] Value of Wire # 374649 (cm_old[3]) :: 4072953071
        [output] Value of Wire # 374650 (cm_old[4]) :: 1622751769
        [output] Value of Wire # 374651 (cm_old[5]) :: 856301769
        [output] Value of Wire # 374652 (cm_old[6]) :: 2898601113
        [output] Value of Wire # 374653 (cm_old[7]) :: 759242631
    */

    public static void main(String[] args) throws Exception {
		
		MerkleTreeGenerator2 generator = new MerkleTreeGenerator2("MerkleTreeGen_2", 2, 32, 8);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}
}
