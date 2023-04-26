import java.util.*;


public class Solve {
    public static void main(String[] args) {
        if (args[0].equals("4")) {
            level4();
        } 

    }

    public static void level4() {
        // There are always 15 cmp instructions so we grep for them in the pwntools 
        // script and read them from stdin here
        int[] nums = new int[15];
        Scanner scnr = new Scanner(System.in);
        int x = 0;
        while (scnr.hasNext()) {
            nums[x++] = scnr.nextInt(16);
        }

        // We allocate an array of 16 ints for the 16 char password
        int[] result = new int[16];

        // We set the first character the be the first possible ASCII char
        // which happens to be 'A'
        result[0] = 48;

        while (true) {

            // Loop through all the numbers recieved from stdin
            for (int i = 0; i < nums.length; i++) {
                // Perform the subtraction to get the next index of our password
                int curr = nums[i] - result[i];

                // Check if the character is alpanumeric
                if (!Character.isAlphabetic((char) curr) && !Character.isDigit((char) curr)) {
                    break;
                } else {
                    // Place the character if its valid in our result
                    result[i + 1] = curr;
                }

                // Check if this is the last index and if so print out the result and exit.
                if (i == nums.length - 1) {
                    for (int j = 0; j < result.length; j++) {
                        System.out.print((char) result[j]);
                    }
                    System.out.println();
                    System.exit(0);
                }
            }

            // If we broke out of the for loop we end up here where we increment the first
            // char in the result (our next guess) and make sure that character is still valid.
            result[0]++;
            if (result[0] == 58) {
                result[0] = 65;
            } else if (result[0] == 91) {
                result[0] = 97;
            } else if (result[0] > 122) {
                // If we reach the last valid character then we couldn't find a solution
                // so we break out of the while loop and exit.
                System.out.println("No solution found!");
                break;
            }


        }
    }
}
