import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


public class CommandUtil {
    public static String exec(String command) throws IOException, InterruptedException {
        Runtime run = Runtime.getRuntime();
        Process p = run.exec(command);
        BufferedInputStream in = new BufferedInputStream(p.getInputStream());
        BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String lineStr;
        while ((lineStr = inBr.readLine()) != null) {
            sb.append(lineStr);
            sb.append("\n");
        }
        if (p.waitFor() != 0) {
            if (p.exitValue() == 1) {

            }

        }
        inBr.close();
        in.close();

        return sb.toString();

    }
}
