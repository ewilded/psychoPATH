Original work by: Julian H. https://github.com/ewilded/psychoPATH

# psychoPATH - a blind webroot file upload & LFI detection tool
![Logo](logo_by_Sponge_Nutter.png?raw=true "Logo by Sponge Nutter")
## psychoPATH - hunting file uploads & LFI in the dark
This tool is a highly configurable payload generator detecting LFI & web root file uploads. Involves advanced path traversal evasive techniques, dynamic web root list generation, output encoding, site map-searching payload generator, LFI mode, nix & windows support. 

![Demo Screenshot](screenshots/first_run.png?raw=true "User interface")

This tool helps to discover several kinds of vulnerabilities not detected by most known scanners and payload sets:
- local file inclusion/arbitrary file read vulnerable to path traversal with weak filters involved (e.g. non-recurrent)
- file upload vulnerable to path traversal with the upload directory located inside the document root
- file upload vulnerable to path traversal with the upload directory outside the document root
- file upload not vulnerable to path traversal, but having the upload directory is inside of the document root, with no direct links to the uploaded file exposed by the application

Also, the `Directory checker` payload generator can be used for other purposes, e.g. selective invasive content discovery or checking allowed HTTP methods per directory. 

At the moment, this plugin extends Burp Intruder with three payload generators:
![Demo Screenshot](screenshots/payload_generators.png?raw=true "Payload generators")

## To see detailed usage examples for all payload generators and scenarios (e.g. LFI hunting), please go to  [usage_examples.pdf](https://www.github.com/ewilded/psychoPATH/blob/master/usage_examples.pdf?raw=true)

## Insight into the file upload scenarios
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
- /opt/tomcat5/webapps/uploadbare_traversal_outside_webroot
- [...]

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

### Other possible issues with traversal-vulnerable uploads
There might be another vulnerable, hard to discover variant of a file upload function prone to path traversal. 
Both traversal cases described above would not get detected if there was no +w permission on the webroot (`/var/lib/tomcat8/webapps/uploadbare_traversal_outside_webroot` and `/var/lib/tomcat8/webapps/uploadbare_traversal_inside_webroot`, respectively). The only spark of hope here is that any of the subdirectories, like `images/`, has such permission enabled. This is why all the directories inside the webroot are also worth shooting at explicitly, leading to payloads like `./../../../../../../../../var/lib/tomcat8/uploadbare_traversal_inside_webroot/images/a.jpg` or `./../images/a.jpg`.

### Are any of these upload scenarios even likely?
Not very (although all met in the wild, they are just quite rare), this is why it appeared sensible to automate the entire check.

Speaking of path traversal, *most* of today's frameworks and languages are path traversal-proof. Still, sometimes they are not used properly. When it comes to languages, they usually (e.g. PHP) strip any path sequences from the standard variable holding the POST-ed file (`Content-Disposition: form-data; name="file"; filename="test.jpg"`), still it is quite frequent the application is using another user-supplied variable to rename the file after upload (and this is our likely-successful injection point).

When it comes to uploading files to hidden/not explicitly linked directories in the document root (those explicitly linked like `Your file is here: <a href='uploads/a.jpg'>uploads/a.jpg</a>` are trivial to find, no tools needed), it is usually a result of weird development practices and/or some forgotten 'temporary' code put together for testing - and never removed. Still, it happens and it is being missed, as, again, no sane person would think of e.g. searching for the file they just uploaded in a webroot subdirectory called `logs/tmp`.


### Hunting uploads in the dark - the algorithm

The following is a general algorithm we employ to perform blind detection of any of the cases mentioned above:
- upload a legitimate file that is accepted by the application (a benign filename, extension, format and size) - we want to avoid false negatives due to any additional validation checks performed by the application
- estimate the possible potentially valid webroots, including their variants with webroot-located subdirectories and path traversal payloads (both relative, like `../../a.jpg` and absolute, like `./../../../var/lib/tomcat6/webapps/servletname/a.jpg`, `./../../../var/lib/tomcat6/webapps/servletname/img/a.jpg` and so on) - this step is automated and customizable
- attempt to upload the file using all the payloads from the step above, placing a unique string in each file we attempt to upload (this step is automated and customizable as well)
- search for the uploaded file by attempting GETs to all known directories in the webroot, e.g. http://example.org/a.jpg, http://example.org/img/a.jpg and so on (this step is automated as well)
- if we find the file in any of the locations, we look into its contents to identify the unique string (payload mark), so we can track down the successful payload 


## The evasive techniques
The evasive techniques apply both to file uploading and file reading (LFI).

The basic traversal payload is `../`, or more generally `<DOT><DOT><SLASH>` (`<SLASH>` can be both the normal `/` and the Windows `\`).



### Non-recursive filters
1) removing only `../`
2) removing only `./`
3) removing `../` and then `./`
4) removing `./` and then `../`



First, let's have a look at the basic non-recursive filter scenarios:

1)
`....//....//....//....//....//....//....//....//` -> rm `../`-> `../../../../../../../../` OK

2)
`...//...//...//...//...//...//...//...//...//` -> rm `./` -> `../../../../../../../../../` OK


3) 
`.....///.....///.....///.....///.....///.....///.....///` -> rm `../` -> `...//...//...//...//...//...//...//` -> rm `./` -> `../../../../../../../`  OK

4) 
`.....///.....///.....///.....///.....///.....///.....///` -> rm `./` -> `....//....//....//....//....//....//....//` -> rm `../` -> `../../../../../../../` OK

So, we only need three non-recurrent evasive payloads:

- `....//`
- `...//`
- `.....///`

### Breakup-filters
By this we mean filters removing `..`, `../` or `./` BEFORE removing some other character/string - e.g. a whitespace - let's call it a breakup sequence.
To simplify the examples, we use white space as a breakup sequence:

1) `.. /` -> rm `../` -> `.. /` -> rm ` ` -> `../` OK 

2) `. ./` -> rm `../` -> `. ./` -> rm ` ` -> `../` OK 

3) `. ./` -> rm `..` -> `. ./` -> rm ` ` -> `../` OK

4) `. . /` -> rm `./` -> `.. /` -> rm ` ` -> `../` OK7

5) `.. .//` -> rm `../` -> `.. .//` -> rm `./` -> `.. /` rm ` ` -> `../` OK

6) `.. .//` -> rm `./` -> `.. /` -> rm `../` -> `.. /` -> rm ` ` -> `../` OK

7) `. . /` -> rm `..` -> `. . /` -> rm `./` -> `. . /` -> rm ` ` -> `../` OK

And finally it turns out the last breakup sequence `. . /` can defeat all the above filters at the same time.

So, we should only need one breakup sequence evasive payload:

- `. . /`

Or, more generally, `.{BREAKUP}.{BREAKUP}/`.

The breakup sequence is fully configurable, just as the list of the traversal payloads with the `{BREAKUP}` holder.

The breakup sequence might be a white space (or some other white character, as these are frequently removed from the user input). It might, as well, be some 'bad' word, like 'select' or 'script', if the application is stupid enough to try to prevent input validation problems by cutting out 'dangerous' strings from the user input - and keep processing it further - which creates cross-filter interferences leading to this kind of bypasses.


### Output encoding
At the moments, all the output payloads can be encoded with use of all/any of the following encodings:
- none (default)
- URL-encoded
- double URL-encoded

### Future improvements
Please see the [TODO](https://www.github.com/ewilded/psychoPATH/blob/master/TODO?raw=true)

### Contribution
Please feel free to report any evasive techniques/optimizations/features you would like to see included into this project.
