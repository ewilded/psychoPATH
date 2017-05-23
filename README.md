Original work by: Julian H. https://github.com/ewilded/psychoPATH

# psychoPATH - a blind webroot file upload & LFI detection tool
![Logo](logo_by_Sponge_Nutter.png?raw=true "Logo by Sponge Nutter")
## What is psychoPATH?
This tool is a customizable payload generator, initially designed to automate blind detection of web file upload implementations allowing to write files into the webroot (aka document root). The "blind" aspect is the key here and is inherent to dynamic testing usually conducted with no access to the source code or the filesystem. 

Shortly after implementation it turned out the tool can also be very handy in hunting Local File Inclusion aka arbitrary file reading issues involving path traversal.

This tool helps to discover several kinds of vulnerabilities not detected by most scanners/payload sets:
- file upload vulnerable to path traversal with the upload directory located inside the document root
- file upload vulnerable to path traversal with the upload directory outside the document root
- file upload not vulnerable to path traversal, but having the upload directory is inside of the document root, with no direct links to the uploaded file exposed by the application
- local file inclusion/arbitrary file read vulnerable to path traversal with non-recurrent filters involved


## Inisght into the file upload scenarios
At this point, controlling the uploaded file contents/extension is not the focus. One thing at a time, first we just want to detect if we can upload a *legitimate* file anywhere in the webroot.
### 1) Path traversal + upload dir outside the webroot

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

- /opt/tomcat8/example
- /opt/tomcat5/webapps/example.org 
- /var/lib/tomcat6/webapps/uploadbare_traversal_outside_webroot
- /var/lib/tomcat7/webapps/uploadbare_traversal_outside_webroot
- /var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot
- /opt/tomcat7/webapps/example
- /opt/tomcat8/webapps/example.org
- /opt/tomcat6/webapps/uploadbare_traversal_outside_webroot
- /opt/tomcat7/webapps/example
- /opt/tomcat8/webapps/example.org
- /opt/tomcat5/webapps/uploadbare_traversal_outside_webroot
[...]

and so on. The remote webroot can depend on the platform, version, OS type, OS version as well as on internal standards within an organisation.

Based on well-known server-specific webroot paths + target hostname + user-specified variables, psychoPATH attempts to generate a comprehensive list of all potentially valid paths to use while blindly searching for vulnerable file upload. This approach was directly inspired by the technique used in `--os-shell` mode in `sqlmap`.


### 2) Path traversal + upload dir inside of the webroot

Let's go to our next scenario then, which will be a slightly modified version of the previous example.
The code remains the same, traversal-vulnerable. The only difference is the configured upload directory. Instead of `/tmp/`, we use `/var/lib/tomcat8/webapps/uploadbase_traversal_inside_webroot/nowaytofindme/tmp`.

The `nowaytofindme/tmp` directory is not explicitly linked by the application and there is no way to guess it with a dictionary-based enumeration approach.

Luckily for us, the application is still vulnerable to path traversal.
We do not even need to guess the webroot. The payload to do the trick (put the file to `/var/lib/tomcat8/webapps/uploadbase_traversal_inside_webroot`, so it can be accessed by requesting `http://example.org/uploadbase_traversal_inside_webroot/a.jpg` is simply `../../a.jpg`.

### 3) No path traversal + upload dir inside the webroot

The third example is not vulnerable to path traversal. The upload directory is located in the webroot (`logs/tmp` -> `/var/lib/tomcat8/webapps/uploadbase_traversal_inside_webroot/logs/tmp`). We already know it exists, supposedly among multiple other directories, like `javascript/`, `css/` or `images/` - but we would not normally suspect any of these could be the actual upload directory (no directory listing + the uploaded file is not explicitly linked by the application).

So, the payload is simply `a.jpg`. The file (or its copy) is put under `logs/tmp/a.jpg` - but no sane person would search for the file they just uploaded in a directory/subdirectory called `logs/tmp`. psychoPATH is not a sane person.

### Other possible issues with traversal-vulnerable cases
There might be another vulnerable, hard to discover variant of a file upload function prone to path traversal. 
Both traversal cases described above would not get detected if there was no +w permission on the webroot (`/var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot` and `/var/lib/tomcat8/webapps/uploadbare_traversal_inside_webroot`, respectively). The only spark of hope here is that any of the subdirectories, like `images/`, has such permission enabled. This is why all the directories inside the webroot are also worth shooting at explicitly, leading to payloads like `./../../../../../../../../var/lib/tomcat8/uploadbare_traversal_inside_webroot/images/a.jpg` or `./../images/a.jpg`.

### Are any of these upload scenarios even likely?
Not very (although all met in the wild, they are just quite rare), this is why it appeared sensible to automate the entire check.

Speaking of path traversal, *most* of today's frameworks and languages are path traversal-proof. Still, sometimes they are not used properly. When it comes to languages, they usually (e.g. PHP) strip any path sequences from the standard variable holding the POST-ed file (`Content-Disposition: form-data; name="file"; filename="test.jpg"`), still it is quite frequent the application is using another user-supplied variable to rename the file after upload (and this is our likely-successful injection point).

When it comes to uploading files to hidden/not explicitly linked directories in the document root (those explicitly linked like `Your file is here: <a href='uploads/a.jpg'>uploads/a.jpg</a>` are trivial to find, no tools needed), it is usually a result of weird development practices and/or some forgotten 'temporary' code put together for testing - and never removed. Still, it happens and it is being missed, as, again, no sane person would think of e.g. searching for the file they just uploaded in a webroot subdirectory called `logs/tmp`.


## The algorithm

The following is a general algorithm we employ to perform blind detection of any of the cases mentioned above:
- upload a legitimate file that is accepted by the application (a benign filename, extension, format and size) - we want to avoid false negatives due to any additional validation checks performed by the application
- estimate the possible potentially valid webroots, including their variants with webroot-located subdirectories and path traversal payloads (both relative, like `../../a.jpg` and absolute, like `./../../../var/lib/tomcat6/webapps/servletname/a.jpg`, `./../../../var/lib/tomcat6/webapps/servletname/img/a.jpg` and so on) - this step is automated and customizable
- attempt to upload the file using all the payloads from the step above, placing a unique string in each file we attempt to upload (this step is automated and customizable as well)
- search for the uploaded file by attempting GETs to all known directories in the webroot, e.g. http://example.org/a.jpg, http://example.org/img/a.jpg and so on (this step is automated as well)
- if we find the file in any of the locations, we look into its contents to identify the unique string (payload mark), so we can track down the successful payload 

## The evasive payloads
The basic traversal payload is `../`, or more generally `<DOT><DOT><SLASH>` (a holder-based approach will become handy once Windows support + encodings are involved). 

The following are the potential bypassable filter scenarios:
1) removing only `../`
2) removing only `./`
3) removing `../` and then `./`
4) removing `./` and then `../`

This applies both to file uploading and file reading (LFI), please see the psychoPATH usage - LFI hunting section for more details.
A filter removing all occurrences of `..` or `/` does not seem to be bypassable (please let me know if I am wrong).

1)
`....//....//....//....//....//....//....//....//` -> rm `../`-> `../../../../../../../../` OK

2)
`...//...//...//...//...//...//...//...//...//` -> rm `./` -> `../../../../../../../../../` OK


3) 
`.....///.....///.....///.....///.....///.....///.....///` -> rm `../` -> `...//...//...//...//...//...//...//` -> rm `./` -> `../../../../../../../`  OK

4) 
`.....///.....///.....///.....///.....///.....///.....///` -> rm `./` -> `....//....//....//....//....//....//....//` -> rm `../` -> `../../../../../../../` OK

So, we only need three evasive payloads:

- `....//`
- `...//`
- `.....///`


## Webroot-guessing - optimization
To reduce the eventual number of payloads, by default the tool does not prepend the same document root with traversal strings which differ only in the number of the traversal sequences they consist of (e.g. `../` vs `../../` vs `../../../`) - as these are redundant when used with absolute paths. Instead, only the longest variant is used, e.g. `.....///.....///.....///.....///.....///.....///.....///var/lib/tomcat8/webapps/upload`. This significantly reduces the number of payloads sent. It might, however, be an issue - if the variable we are injecting into is somehow limited on its length, e.g. application rejects any values longer than 45 characters and the upload directory is `/tmp` - in that case `.....///var/lib/tomcat8/webapps/upload` would do the trick instead. If you are worried about the payload length and you care less about the number of payloads, turn optimization off. 

## psychoPATH usage - hunting uploads in the dark

The extension interface consists of several lists of elements used to build permutations of all potentially valid payloads:
![Demo Screenshot](screenshots/first_run.png?raw=true "Usage example")
The {TARGET} holder is automatically replaced with elements from the Targets list, by default containing the Host header of the target. If the hostname is a subdomain, e.g. foo.bar.example.org, it will automatically be propagated into several possible target values, like `foo`, `bar`, `example` and `foo.bar.example.org`.

All the lists can be manually adjusted by using relevant Paste, Load, Remove and Add buttons.

The Doc roots lists offer several sub-groups:
![Demo Screenshot](screenshots/docroot_groups.png?raw=true "Usage example")

By default, all sub-groups are included as basic payload-building units.

First, we perform a legitimate upload request to the target application.
Then we right-click on the relevant request and click `Propagate to psychoPATH` context menu button:
![Demo Screenshot](screenshots/propagate.png?raw=true "Usage example")

This is required to let the plugin know about the target host and protocol, so it can adjust the payloads with the relevant information from the site map (like the host or the directories from the site map) - please note the changed list of Suffixes and Targets after propagation:
![Demo Screenshot](screenshots/after_propagation.png?raw=true "Usage example")

Now we send the request to Intruder. 
We set the attack type to Pitchfork.
Then we need to select two payload holders. One is the file name value we are about to inject into. The other is just a section in the uploaded file content - this is where the unique payload mark will be put. Currently payload marks have fixed length of 7 characters. When injecting into image formats, the safest way is to mark exactly seven characters of a string - e.g. a piece of exif data. This way we won't encounter false negatives if the application is checking the validity of the image file before putting it into the upload directory of our interest:
![Demo Screenshot](screenshots/intruder_attack_setup.png?raw=true "Usage example")

Then we move to the Payloads tab. 
For the first payload, we change the type from "Simple list" to "Extension generated". We choose the "Path traversal" extension generator.
We UNCHECK the the default "URL-encode these characters" box:
![Demo Screenshot](screenshots/payload_one_setting.png?raw=true "Usage example")

Then we proceed to the second payload set (the payload mark).
For the first payload, we change the type from "Simple list" to "Extension generated". We choose the "Payload marker" extension generator:
![Demo Screenshot](screenshots/payload_two_setting.png?raw=true "Usage example")

We hit the "Start attack" button and watch the results.
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

We hit the "Start attack" button and watch the results (now we are explicitly interested in getting "200 OK" response).  Normally there would be a bit more, like ten or few dozens of site map-derived directories queried, in the example below it's just one (`uploadbare_traversal_outside_webroot`):
![Demo Screenshot](screenshots/verification_step3.png?raw=true "Usage example")

As we can see, the file has been created under `uploadbare_traversal_outside_webroot/a.jpg`. By looking at the payload marker spot, we can identify 585 as the number of the golden payload. 
We look back to the Intruder attack and search for the request with Payload 2 equal to 585:
![Demo Screenshot](screenshots/verification_step4.png?raw=true "Usage example")

Now we know the golden payload to reach the document root was `./../../../../../../..//var/lib/tomcat8/webapps//uploadbare_traversal_outside_webroot/a.jpg`.

For other two examples, the results for the payloads that have worked, would look as follows, respectively:
/uploadbare_traversal_inside_webroot:
![Demo Screenshot](screenshots/verification_case_2_step_1.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_2_step_2.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_2_step_3.png?raw=true "Usage example")

/uploadbare_no_traversal_inside_webroot:
![Demo Screenshot](screenshots/verification_case_3_step_1.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_3_step_2.png?raw=true "Usage example")
![Demo Screenshot](screenshots/verification_case_3_step_3.png?raw=true "Usage example")

## psychoPATH usage - hunting LFI
The Path traversal generator can be easily used for hunting Local File Inclusion/arbitrary file reading issues as well - and it's much simpler than hunting uploads.
The test_cases/LFI directory contains three vulnerable PHP scripts, reflecting the non-recurrent filter cases broken down in the "evasive payloads" section.

Below is a short presentation on how all three can be quickly detected with the payloads provided by psychoPATH.
First screenshot shows us the response of the script when a benign string `foo` is provided under the `file` variable. No content is returned:
![Demo Screenshot](screenshots/lfi_hunting_one_1.png?raw=true "Usage example")

We send the request to Intruder and mark the injection point:
![Demo Screenshot](screenshots/lfi_hunting_one_2.png?raw=true "Usage example")
We choose `Extension generated` `Path traversal` payload type.
Please not unchecking the `URL-encode these characters` - as a matter of fact the most reliable approach is to test each input like this twice - with and without URL-encoding:
![Demo Screenshot](screenshots/lfi_hunting_one_3.png?raw=true "Usage example")

Then we move to the psychoPATH configuration panel. We choose the file name, for instance `/etc/passwd`. We clear the web roots, targets and suffixes list, as we are nog going to need them to perform this attack:
![Demo Screenshot](screenshots/lfi_hunting_one_4.png?raw=true "Usage example")
We simply run "Start attack" and watch how each of the evasive techniques works on its corresponding vulnerable case:
![Demo Screenshot](screenshots/lfi_hunting_one_5.png?raw=true "Usage example")
![Demo Screenshot](screenshots/lfi_hunting_two.png?raw=true "Usage example")
![Demo Screenshot](screenshots/lfi_hunting_three.png?raw=true "Usage example")


## The perl script 
Initially this tool was developed as a perl script - which is still available, although no longer maintained at the moment.

### TODO
- add more configuration options:
  - LFI mode
  - use absolute paths with webroots (no traversal payload involved at all, just like it used to be in the original perl script)
  - windows backslash \ support
  - windows drive letters support for absolute webroots
  - windows evasive techniques
  - auto append/prepend the evasive payload with arbitrary characters (e.g. space)?? before, between dots, after dots, after slash? (four checkboxes) + list of characters to append, preferably set in ascii-dec/ascii-hex
  - any evasive techniques being a mix of \ and /? e.g. ....\/ -> rm ..\ -> ../
  - auto append the filename with arbitrary characters (preferably set in ascii-dec/ascii-hex, useful for LFI mode, but could as well be used to bypass extension controls, cause why not)
- Nice-to-haves:
- test on different resolution, make sure the project is easily runnable/importable
- separate apache-like suffixes from the main list, they are there by default and do not go away once other than all/apache webroot set is picked
- more examples of test cases
- add a "Copy to clipboard" button for generated payloads, so the output payloads can be used with other tools
- add support for ZIP traversals
- extend the tool with extension control mode (defeating the filters in order to upload an executable - different tricks depending on the platform)??
- in case of a positive result, automatically track back the payload that did the trick (instead of the dir check mode?)
