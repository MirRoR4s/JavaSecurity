package example;
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;
public class RemoteServer {
    private void start() throws Exception{
        if (System.getSecurityManager() == null){
            System.out.println("setup SecurityManager");
            System.setSecurityManager(new SecurityManager());
        }
        Calc h = new Calc();
        LocateRegistry.createRegistry(1099);
        Naming.bind("refObj",h);
    }

    public static void main(String[] args) throws Exception {
        new RemoteServer().start();
    }
}

