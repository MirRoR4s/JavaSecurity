package maskhe;


import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class Helloimpl extends UnicastRemoteObject implements Hello {
    public Helloimpl() throws RemoteException {
    }

    @Override
    public String welcome(String name) throws RemoteException {
        return "Hello, "+name;
    }
}