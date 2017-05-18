package burp;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import uk.co.pentest.psychoPATH.PsychoPATH;

public class Menu implements IContextMenuFactory {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private String host;
    private String proto;
    private String path;
    
    public Menu(IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) 
    {
        // save selected items host and proto
	List<JMenuItem> menu = new ArrayList<>();		
	JMenuItem item = new JMenuItem("Propagate to psychoPATH"); 
	item.addMouseListener(new MouseListener() {            
            @Override
            public void mouseReleased(MouseEvent e) {
                IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
                for (IHttpRequestResponse selectedItem : selectedItems) {
                    host = selectedItem.getHost();
                    proto = selectedItem.getProtocol();
                    path = selectedItem.getUrl().getPath();
                }
                PsychoPATH.PsychoTab.psychoPanel.updateScope(proto,host);
                //PsychoPATH.PsychoTab.psychoPanel.logOutput("method called 1"+"\n");                               
            }
            @Override
            public void mouseClicked(MouseEvent e) {
                //PsychoPATH.PsychoTab.psychoPanel.logOutput("method called 2"+"\n"); 
            }
            @Override
            public void mousePressed(MouseEvent e) {
                //PsychoPATH.PsychoTab.psychoPanel.logOutput("method called 3"+"\n");
            }
            @Override
            public void mouseEntered(MouseEvent e) {
                //PsychoPATH.PsychoTab.psychoPanel.logOutput("method called 4"+"\n");
            }

            @Override
            public void mouseExited(MouseEvent e) {
                //PsychoPATH.PsychoTab.psychoPanel.logOutput("method called 5"+"\n");
            }
        });		
        menu.add(item);		
        return menu;
    }   
}
