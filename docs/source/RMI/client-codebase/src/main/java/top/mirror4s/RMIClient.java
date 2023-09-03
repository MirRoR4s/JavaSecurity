package top.mirror4s;
import java.rmi.Naming;
import java.util.ArrayList;
import java.io.Serializable;
import java.util.List;

public class RMIClient implements Serializable {
    public class Payload extends ArrayList<Integer>{}

    public void lookup() throws Exception{
        ICalc r = (ICalc) Naming.lookup("rmi://192.168.43.117:1099/refObj");

        List<Integer> li = new Payload();
        li.add(3);
        li.add(4);
        System.out.println(r.sum(li));
    }

    public static void main(String[] args) throws Exception {
        new RMIClient().lookup();
    }

}
