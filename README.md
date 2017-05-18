Original work by: Julian H. https://github.com/ewilded/psychoPATH

# psychoPATH - a blind webroot file upload detection tool

## What is psychoPATH?
This tool is a customizable payload generator designed for blindly detecting web file upload implementations allowing to write files into the webroot (aka document root). The "blind" aspect is the key here and is inherent to dynamic testing usually conducted with no access to the source code or the filesystem. 

This tool helps to discover several vulnerable and not easily-detectable scenarios:
- the upload function is vulnerable to path traversal and the upload directory is inside of the document root
- the upload function is vulnerable to path traversal and the upload directory is outside the document root
- the upload function is not vulnerable to path traversal, but the upload directory is inside of the document root, with no direct links to the uploaded file exposed by the application

The purpose of creating this tool was to automate the detection of these non-trivial web root file uploads.

Neither this tool or this write up focus on the possible ways of circumventing any mechanisms preventing one from controlling the uploaded file contents/extension; which simply is the natural next step once we know we can upload legitimate files to the webroot. One thing at a time, for now we just want to detect if we can upload a file anywhere in the webroot.

## Inisght into scenarios
### path traversal + upload dir outside the webroot

Let's consider the following vulnerable Java servlet:

        private static final String SAVE_DIR = "/tmp";
    	protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        String appPath = request.getServletContext().getRealPath("");
        String savePath =  SAVE_DIR;
        File fileSaveDir = new File(savePath);
        if (!fileSaveDir.exists()) {
            fileSaveDir.mkdir(); 
        }
        String full_name=SAVE_DIR;
        for (Part part : request.getParts()) {
            String fileName = extractFileName(part);
            part.write(savePath + File.separator + fileName);
	    full_name=savePath + File.separator + fileName;
        }


The servlet is using user-supplied values as file names (e.g. `a.jpg`). It stores uploaded files in an upload directory `/tmp` located outside the document root (let's assume the document root here is `/var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot`). 

In order to get our file saved in the document root instead of the default upload directory, the user-supplied value, instead of benign `a.jpg`, would have to look more like `./../../../../../../../../../../var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot/a.jpg`.

Assuming we cannot see any detailed error messages from the application and we have no access to the file system - all we know is that it is running on Apache Tomcat and that the URL is `http://example.org/uploadbare_traversal_outside_webroot`. In order to come up with this particular payload, we would have to try several possible document root variants, like:

/opt/tomcat8/example
/opt/tomcat5/webapps/example.org
/var/lib/tomcat6/webapps/uploadbare_traversal_outside_webroot
/var/lib/tomcat7/webapps/uploadbare_traversal_outside_webroot
/var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot
/opt/tomcat7/webapps/example
/opt/tomcat8/webapps/example.org
/opt/tomcat6/webapps/uploadbare_traversal_outside_webroot
/opt/tomcat7/webapps/example
/opt/tomcat8/webapps/example.org
/opt/tomcat5/webapps/uploadbare_traversal_outside_webroot
[...]
 and so on. The remote webroot can depend on the platform, version, OS type, OS version as well as on internal standards within an organisation.

Based on well-known server-specific webroot paths + target hostname + user-specified variables, psychoPATH attempts to generate a comprehensive list of all potentially valid paths to use while blindly searching for vulnerable file upload. This approach was directly inspired by the technique used in `--os-shell` mode in `sqlmap`.


### path traversal + upload dir inside of the webroot

Let's go to our next scenario then, which will be a slightly modified versio of the previous example.
The code remains the same, traversal-vulnerable. The only different is the configured upload directory. Instead of absolute `/tmp/`, we use relative `nowaytofindme/tmp`, which in our case effectively revolves to `/var/lib/tomcat8/webapps/uploadbase_traversal_inside_webroot/nowaytofindme/tmp`.

The `nowaytofindme/tmp` directory is not explicitly linked by the application and there is no way to guess it with a dictionary-based enumeration approach.

Luckily for us, the application is still vulnerable to path traversal.
We do not even need to guess the webroot. The payload to do the trick is simply `../../a.jpg`.

### No path traversal + upload dir inside the webroot

The third example is not vulnerable to path traversal. The upload directory is located in the webroot (`logs/tmp` -> `/var/lib/tomcat8/webapps/uploadbase_traversal_inside_webroot/logs/tmp`). We already know it exists, but we would not normally suspect this could be the actual upload directory (no listing, uploaded file is not explicitly linked by the application).

So, the payload is simply `a.jpg`. The file (or its copy) is put under `logs/tmp/a.jpg` - but no sane person would search for the file they just uploaded in a directory/subdirectory called `logs/`. psychoPATH is not a sane person ;)

### Other possible issues with traversal-vulnerable cases
There might be another vulnerable, hard to discover variant of a file upload function prone to path traversal. 
Both traversal cases described above would not get detected if there was no +w permission on the webroot (`/var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot` and `/var/lib/tomcat8/webapps/uploadbare_traversal_inside_webroot`, respectively). The only spark of hope here is that any of the subdirectories, like `images/`, has such permission enabled. This is why all the directories inside the webroot are also worth shooting at explicitly, leading to payloads like `./../../../../../../../../var/lib/tomcat8/uploadbare_traversal_inside_webroot/images/a.jpg` or `./../images/a.jpg`.

### Are any of these scenarios even likely?
Not very (although all met in the wild, they are just quite rare), this is why it appeared sensible to automate the entire check.

Speaking of path traversal, *most* of today's frameworks and languages are path traversal-proof. Still, sometimes they are not used properly. When it comes to languages, they usually (e.g. PHP) strip any path sequences from the standard variable holding the POST-ed file (`Content-Disposition: form-data; name="file"; filename="test.jpg"`), still it is quite frequent the application is using another user-supplied variable to rename the file after upload (and this is our likely-succsful injection point).

When it comes to uploading files to hidden/not explicitly linked directories in the document root (those explicitly linked like `Your file is here: <a href='uploads/a.jpg'>uploads/a.jpg</a>` are trivial to find, no tools needed), it is usually a result of weird development practices and/or some forgotten 'temporary' code put together for testing - and never removed. Still, it happens and it is being missed, as no sane person would think of e.g. searching for the file they just uploaded in a webroot subdirectory called 'logs/tmp'.


## The algorithm

The following is a general algorithm we employ to perform blind detection of any of the cases mentioned above:
- upload a legitimate file that is accepted by the application (a benign filename, extension, format and size) - we want to avoid false negatives due to any additional validation checks performed by the application
- estimate the possible potentially valid webroots, including their variants with webroot-located subdirectories and path traversal payloads (both relative, like `../../a.jpg` and absolute, like `./../../../var/lib/tomcat6/webapps/servletname/a.jpg`, `./../../../var/lib/tomcat6/webapps/servletname/img/a.jpg` and so on)
- attempt to upload the file using all the payloads from the step above, placing a unique string in each file we attempt to upload
- we search for the uploaded file by attempting GETs to all known directories in the webroot, e.g. http://example.org/a.jpg, http://example.org/img/a.jpg and so on
- if we find the file in any of the locations, we look into its contents to identify the unique string (payload mark), so we can track down the successful payload

## psychoPATH usage

The extension interface consists of several lists of elements used to build permutations of all potentially valid payloads:
![Demo Screenshot](screenshots/first_run.png?raw=true "Usage example")
The {TARGET} holder is automatically replaced with elements from the Targets list, by default containing the Host header of the target. If the hostname is a subdomain, e.g. foo.bar.example.org, it will automatically be propagated into several possible target values, like `foo`, `bar`, `example` and `foo.bar.example.org`.

All the lists can be manually adjusted by using relevant Paste, Load, Remove and Add buttons.

The Traversals and Doc roots lists offer several sub-groups:
![Demo Screenshot](screenshots/traversal_groups.png?raw=true "Usage example")
![Demo Screenshot](screenshots/docroot_groups.png?raw=true "Usage example")

By default, all sub-groups are included as basic payload-building units.

First, we perform a legitimate upload request to the target application.
Then we right-click on the relevant request and click `Propagate to psychoPATH` context menu button:
![Demo Screenshot](screenshots/propagate.png?raw=true "Usage example")

This is required to let the plugin know about the target host and protocol, so it can adjust the payloads with the relevant information from the site map (like the host or the directories from the site map) - please note the changed list of Suffixes and Targets after propagation:
![Demo Screenshot](screenshots/after_propagation.png?raw=true "Usage example")

Now we send the request to Intruder. 
We set the attack type to Pitchfork.
Then we need to select two payload holders. One is the file name value we are about to inject into. The other is just a section in the uploaded file content - this is where the unique payload mark will be put:
![Demo Screenshot](screenshots/intruder_attack_setup.png?raw=true "Usage example")

Then we move to the Payloads tab. 
For the first payload, we change the type from "Simple list" to "Extension generated". We choose the "Path traversal" extension generator.
We UNCHECK the the default "URL-encode these characters" box:
![Demo Screenshot](screenshots/payload_one_setting.png?raw=true "Usage example")

Then we proceed to the second payload set (the payload mark).
For the first payload, we change the type from "Simple list" to "Extension generated". We choose the "Payload marker" extension generator:
![Demo Screenshot](screenshots/payload_two_setting.png?raw=true "Usage example")

We hit "Start attack" button and watch the results.
![Demo Screenshot](screenshots/results_0.png?raw=true "Usage example")

It might be handy to sort the responses by the status code/any other property of the server's response:
![Demo Screenshot](screenshots/results_1.png?raw=true "Usage example")

According to the sorted output, the application responded differently to several payloads which either refered to `var/lib/tomcat8/webapps` directory (which was the valid base document root in this case) or did not use any traversal combinations at all. Still, sometimes the response we receive might not give us any hints (entirely blind scanario).

We keep the Intruder attack window open and proceed to the verification phase (searching the entire site map for the file we uploaded).

In order to do this, we simply take a valid, preferably authenticated GET request to the application and send it to Intruder.
We select the URI section as the only payload holder:
![Demo Screenshot](screenshots/verification_step1.png?raw=true "Usage example")

In the Payloads section, again we change from "Simple" to "Extension generated". This time we choose "Directory checker" as the payload generator.
We UNCHECK the the default "URL-encode these characters" box: 
![Demo Screenshot](screenshots/verification_step2.png?raw=true "Usage example")

We hit the "Start attack" button and watch the results (now we are explicitly interested in getting "200 OK" response):
![Demo Screenshot](screenshots/verification_step3.png?raw=true "Usage example")

As we can see, the file has been created under `uploadbare_traversal_outside_webroot/a.jpg`. By looking at the payload marker spot, we can identify 585 as the number of the golden payload. 
We look back to the Intruder attack and search for the request with Payload 2 equal 585:
![Demo Screenshot](screenshots/verification_step3.png?raw=true "Usage example")

Now we know the golden payload to reach the document root was `./../../../../../../..//var/lib/tomcat8/webapps//uploadbare_traversal_outside_webroot/a.jpg`.

For other two examples, the results for payloads that have worked, would look as follows, respectively:
/uploadbare_traversal_inside_webroot:
![Demo Screenshot](screenshots/verification_case_2_step_1.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_2_step_2.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_2_step_3.png?raw=true "Usage example")

/uploadbare_no_traversal_inside_webroot:
![Demo Screenshot](screenshots/verification_case_3_step_1.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_3_step_2.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_3_step_3.png?raw=true "Usage example")

### TODO
- separate apache-like suffixes from the main list, they are there by default and do not go away once other than all/apache webroot set is picked
- more configuration options (switches for evasive techniques etc.)
- add padding to the payload markers in order to avoid any potential validation problems while uploading binary formats
- implement windows support
- implement directory-suffix traversals (traversals relative to the unknown document root + directories from the site map)
- add support for default 'work' directories on tomcat, like /var/lib/tomcat8/work/Catalina/localhost/uploadbare_traversal_inside_webroot/nowaytofindme/tmp/a.jpg
- nice to have - in  case of a positive result, automatically track back the payload that did the trick
- do optimisations (get rid of reduntant payloads, e.g. docroots prepended with traversal sequences of different lengths - just use long one instead)
