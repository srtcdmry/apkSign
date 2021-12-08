import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


public class CommandUtil {
    public static String exec(String command) throws IOException, InterruptedException {
        Runtime run = Runtime.getRuntime();
        Process p = run.exec(command);// 启动另一个进程来执行命令
        BufferedInputStream in = new BufferedInputStream(p.getInputStream());
        BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String lineStr;
        while ((lineStr = inBr.readLine()) != null) {
            //获得命令执行后在控制台的输出信息
            sb.append(lineStr);
            sb.append("\n");
        }
        if (p.waitFor() != 0) {
            if (p.exitValue() == 1) {
                //p.exitValue()==0表示正常结束，1：非正常结束
//                System.err.println("命令执行失败!");
            }

        }
        inBr.close();
        in.close();

        return sb.toString();

    }
}
