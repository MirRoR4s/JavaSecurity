package top.mirror4s;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Main {
    public static void main(String[] args) throws RemoteException, AlreadyBoundException {
        RemoteObj remoteObj = new RemoteObjImpl();
        Registry registry = LocateRegistry.createRegistry(1099);
        registry.bind("remoteObj", remoteObj);


    }
}