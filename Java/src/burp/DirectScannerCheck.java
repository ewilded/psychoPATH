/*
 
 The simple scanner check class for psychoPATH "LFI" mode.
 Sends payloads, greps responses.

 /etc/passwd and win.ini are default filenames.
 The target OS setting needs to exist in the psychoTab, as it is not the same thing as slashes to use, while there is no point in bashing windows 
 if we know nix is the remote sys.
 
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ListModel;
import uk.co.pentest.psychoPATH.IntruderPayloadGenerator;
import uk.co.pentest.psychoPATH.PsychoTab;


public class DirectScannerCheck extends PsychoPATHScannerCheck {

        private PsychoTab tab;
	private IBurpCollaboratorClientContext collabClient;	
       
        private List<IScanIssue> issues;
        private IHttpRequestResponse base;
        private IHttpRequestResponse attackReq;
        
           
        
	public DirectScannerCheck(IBurpExtenderCallbacks cb, PsychoTab tab) 
        {           
            super(cb,tab);
            this.tab = tab;
            checkHttpService = null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		return -1;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) 
        {            
                this.issues = null;                             
                if(this.tab.psychoPanel.scannerChecksCheckbox.isSelected()==false) return this.issues; // the "Enable Scanner checks" checkbox                
        	IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
		URL url = reqInfo.getUrl();
                int port = url.getPort();
		boolean https=false;
                String host = url.getHost();
                if(url.getProtocol()=="https") https=true;
		String urlStr = url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+url.getPath();
		if(!createCheckHttpService(host,port,https))  
                {
                    callbacks.printError("HTTP connection failed");
                    callbacks.issueAlert("HTTP connection failed");
                    return issues;
                }
                generator = new IntruderPayloadGenerator("path",tab,true);                  

                while(generator.hasMorePayloads())
                {
                    byte[] payload = generator.getNextPayload(insertionPoint.getBaseValue().getBytes());               
                    
                    if(payload.length==1) 
                    { //payload generation failed, move onto next command
			callbacks.printError("Payload generation failed!");
			callbacks.issueAlert("Payload generation failed!");
                        return this.issues;
                    }
                    // To avoid Burp's default behaviour with automatic encoding of insertion points in Scanner
                    // we replaced "byte [] req = insertionPoint.buildRequest(payload);"
                    // with new BuildUnencodedRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload))
                    // as adviced by Paj: https://support.portswigger.net/customer/portal/questions/17301079-design-new-extension-problem-with-buildrequest-and-url-encode
                    // with his code snippet: https://gist.github.com/pajswigger/c1fff3ce6e5637126ff92bf57fba54e1
                    
                    byte [] req=null;
                    try {
                        req = new BuildUnencodedRequest(helpers).buildUnencodedRequest(insertionPoint, payload);
                    } catch (Exception ex) {
                        Logger.getLogger(DirectScannerCheck.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                    //callbacks.printError((new String(req))+"\n\n");                  
                    attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
                    byte[] resp = attackReq.getResponse();
                    
                    // check the bytes for (depending (or not depending) on the filename in use:
                    // checking for the presence of the root:x: / win.ini in the response
                    // ; for 16-bit app support
                    //[fonts]
                    //[extensions]
                    //[mci extensions]
                    //[files]
                    //[Mail]
                    //MAPI=1
                    String response =  this.helpers.bytesToString(resp);      
                    
                    ListModel scanChecksModel = tab.psychoPanel.scannerMatchRules.getModel();
        
                    // make sure the string is not already on the list
                    for(int i=0;i<scanChecksModel.getSize();i++)
                    {                        
                        if(response.contains(scanChecksModel.getElementAt(i).toString()))
                        {
                                // avoid duplicates
                                // we also might check for some interesting error messages or even use backslash's comparison mechanism to detect changes in the response
                                // anyway, let's raise an issue, abort further checks                        
                                //callbacks.printError(new String(exploitRR.getResponse()));					
                                this.issues = new ArrayList<IScanIssue>(1);			
                                BinaryPayloadIssue issue;
                                issue = new BinaryPayloadIssue(callbacks,attackReq,"");
                                this.issues.add((IScanIssue) issue);
                                return this.issues;                                   
                        }
                    }                                                              
                }               
                return this.issues;
        }	                
    }
