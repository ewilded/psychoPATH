
package burp;


public class BinaryPayloadIssue extends PsychoPATHScannerIssue {
	private String issueDetail;
	
	private static final String DETAIL_TEMPLATE = "The target is vulnerable to Arbitrary file read (also improperly called LFI)";
	
	public BinaryPayloadIssue(IBurpExtenderCallbacks cb,IHttpRequestResponse exploitRR, String details) {
		super(cb,exploitRR,details);
		issueDetail = DETAIL_TEMPLATE;
	}
        public void appendIssueDetail(String text)
        {
                this.issueDetail = this.issueDetail+text;
        }        
	@Override
	public String getIssueDetail() {
		return issueDetail;
	}

    @Override
    public String getHost() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getPort() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getProtocol() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
