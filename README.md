Blindly exploiting insecure file upload implementations

The general assumptions are as follows:
- we have a file upload function in the application and we have some sample, valid file that is accepted (e.g. a JPEG image)
- our goal is to upload an executable (a webshell), but we do not know what the remote document root is, nor what the upload directory is
- we also do not know what are the file upload restrictions in place, but that's beside the point as long as we cannot reach the document root

First of all, we will attempt to find a way to reach the document root. After we achieve this, we can focus on uploading malicious files instead of legitimate ones. It is better to start with a legitimate file in order to decrease the likehood of a failure due to forbidden content/extension and focus on reaching the document root first. And this phase is the only purpose of this tool (it only  generates a set of payloads to use with Burp Intruder).

Reaching the document root

It might be reasonable to employ a basic evasive technique at this point already (for non-recursive removals of '../' and './').
There are two scenarios we may face when blindly attacking the upload dir:

a) the upload dir is located in the document root, in such case we should do fine without knowing its path at all, as it should be sufficient to attack with path traversal payloads reflecting several layers of nesting in order to hit the document root itself. 

./../test.jpg
./../../test.jpg
./../../../test.jpg
./../../../../test.jpg
./../../../../../test.jpg
./../../../../../../test.jpg
./../../../../../../../test.jpg
./../../../../../../../../test.jpg


./....//test.jpg
./....//....//test.jpg
./....//....//....//test.jpg
./....//....//....//....//test.jpg
./....//....//....//....//....//test.jpg
./....//....//....//....//....//....//test.jpg
./....//....//....//....//....//....//....//test.jpg
./....//....//....//....//....//....//....//....//test.jpg


..//...//test.jpg
..//...//...//test.jpg
..//...//...//...//test.jpg
..//...//...//...//...//test.jpg
..//...//...//...//...//...//test.jpg
..//...//...//...//...//...//...//test.jpg
..//...//...//...//...//...//...//...//test.jpg
..//...//...//...//...//...//...//...//...//test.jpg


b) the upload directory is located outside the document root, that is why we need to employ both directory traversal and full document root path guessing. 


So, we try both scenarios in one go. 
After the series of file upload attempts, we check the document root for existance of the file we tried to create:
http://example.org/test.jpg

The default configuration of get_docroots.pl provides us with a full list of possible payloads covering both above scenarios.
Its list of known document root paths is generated the same way as with --os-shell feature in sqlmap. 
Please see the sample_results.txt file to see the results produced with the default configuration.

If the file is there, we have reached the document root and now we can use the relevant traversal payload in order to try to bypass any file upload restrictions (extension, content, mime type, size, etc).

In order to identify the golden payload (the one that actually resulted in a successful file creation in the document root), we can use unique markers (e.g. number counter) placed in the contents of the file. The easiest way to do it is by using Burp Intruder with the first holder in the filename (our traversal payloads list) and the second one embedded in the file content (if dealing with images, exif tags are a safe place). We choose Pitchfork as the attack type and assign numbers to the second set of payloads. 
If the file upload is successfull, by its contents we will be able to easily identify the exact request that created it.
