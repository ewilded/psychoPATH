package burp;


import uk.co.pentest.psychoPATH.PsychoPATH;
import uk.co.pentest.psychoPATH.PsychoTab;
import uk.co.pentest.psychoPATH.PayloadFactory;

/**
 * The main entry class that Burp calls to load/unload the extension.
 */
public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        PsychoPATH.callbacks = callbacks;
        callbacks.setExtensionName("psychoPATH Extension");
        PsychoPATH.PsychoTab = new PsychoTab();
        callbacks.addSuiteTab(PsychoPATH.PsychoTab);
        
        callbacks.registerExtensionStateListener(this);
        
        // now we register two intruder extension factories; one for the traversed filename, one for the payload marker
        callbacks.registerIntruderPayloadGeneratorFactory(new PayloadFactory(PsychoPATH.PsychoTab, "byte"));
        callbacks.registerIntruderPayloadGeneratorFactory(new PayloadFactory(PsychoPATH.PsychoTab, "check"));
        callbacks.registerIntruderPayloadGeneratorFactory(new PayloadFactory(PsychoPATH.PsychoTab, "path"));
        callbacks.registerIntruderPayloadGeneratorFactory(new PayloadFactory(PsychoPATH.PsychoTab, "mark"));
        callbacks.registerContextMenuFactory(new Menu(callbacks));
    }

    @Override
    public void extensionUnloaded() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    public static IBurpExtenderCallbacks getBurpCallbacks() {
        return PsychoPATH.callbacks;
    }
    

}
