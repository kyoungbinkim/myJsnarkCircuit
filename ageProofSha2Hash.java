package examples.generators;

import java.math.BigInteger;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.config.Config;
import examples.gadgets.hash.SHA256Gadget;

public class ageProofSha2Hash extends CircuitGenerator {

    private Wire[] inputSha2Hash;

    private SHA256Gadget sha2Gadget;


    public ageProofSha2Hash(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {

        inputSha2Hash = createInputWireArray(8);
        // makeOutputArray(inputSha2Hash, "inputSha2Hash");

        Wire result = zeroWire;
        Wire tmp;
        Wire[] tmpBitArray;
        Wire[] HashOutput;

        for (int i=20; i<=100; i++){
            tmp = oneWire.mul(i);
            tmpBitArray = tmp.getBitWires(128).asArray(); // wire[128]
            
            sha2Gadget = new SHA256Gadget(tmpBitArray, 1, 16, false, true);
            HashOutput = sha2Gadget.getOutputWires(); // 8 * 32bit arsssray
            makeOutputArray(HashOutput, Integer.toString(i)+ " SHA-2"); 

            for (int j=0; j<HashOutput.length ; j++){
                
                result = result.add( HashOutput[j].isEqualTo(inputSha2Hash[j]) );

            }
            
            // cannot use equals method !!!
            // equals value and constrain Num 
            // if(HashOutput[0].equals(inputSha2Hash[0]) && 
            //    HashOutput[1].equals(inputSha2Hash[1]) &&
            //    HashOutput[2].equals(inputSha2Hash[2])){
            //        result = oneWire;
            //        break;
            //    }

        }

        // addEqualityAssertion(result, new BigInteger("8"), "you're not Adult ! ");  //  if result != 8s then assert
        
        result = result.isEqualTo(new BigInteger("8"));
        makeOutput(result, "myAgeHash result (if result == 1 then you're Adult !)");
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

        // 27 input
        circuitEvaluator.setWireValue(inputSha2Hash[0], new BigInteger("1404699653"));
        circuitEvaluator.setWireValue(inputSha2Hash[1], new BigInteger("1957037327"));
        circuitEvaluator.setWireValue(inputSha2Hash[2], new BigInteger("4083699947"));
        circuitEvaluator.setWireValue(inputSha2Hash[3], new BigInteger("4102700171"));
        circuitEvaluator.setWireValue(inputSha2Hash[4], new BigInteger("3734196689"));
        circuitEvaluator.setWireValue(inputSha2Hash[5], new BigInteger("2345150495"));
        circuitEvaluator.setWireValue(inputSha2Hash[6], new BigInteger("1250137028"));
        circuitEvaluator.setWireValue(inputSha2Hash[7], new BigInteger("1392173851"));
        
        //random Input 
        // for (int i=0; i<8; i++){
        //     circuitEvaluator.setWireValue(inputSha2Hash[i], Util.nextRandomBigInteger(new BigInteger("4294967296"))); // 2^32
        // }
    }

    // [output] Value of Wire # 14852 (27 SHA-2[0]) :: 1404699653
    // [output] Value of Wire # 14853 (27 SHA-2[1]) :: 1957037327
    // [output] Value of Wire # 14854 (27 SHA-2[2]) :: 4083699947
    // [output] Value of Wire # 14855 (27 SHA-2[3]) :: 4102700171
    // [output] Value of Wire # 14856 (27 SHA-2[4]) :: 3734196689
    // [output] Value of Wire # 14857 (27 SHA-2[5]) :: 2345150495
    // [output] Value of Wire # 14858 (27 SHA-2[6]) :: 1250137028
    // [output] Value of Wire # 14859 (27 SHA-2[7]) :: 1392173851


    public static void main(String[] args) throws Exception {

        ageProofSha2Hash generator = new ageProofSha2Hash("age Proof SHA2");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }

}
